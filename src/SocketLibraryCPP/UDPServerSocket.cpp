#include "pch.h"
#include "SocketLibrary/UDPServerSocket.h"

namespace SocketLibrary {
  UDPServerSocket::UDPServerSocket() : m_target() {
    {
      std::unique_lock lock(m_onReadMutex);
      m_onRead = nullptr;
    }
    m_target = {};
  }

  UDPServerSocket::~UDPServerSocket() noexcept {
    Close();
    {
      std::unique_lock lock(m_onReadMutex);
      m_onRead = nullptr;
    }
  }

  UDPServerSocket::UDPServerSocket(UDPServerSocket&& other) noexcept : UDPServerSocket() {
    *this = std::move(other);
  }

  UDPServerSocket& UDPServerSocket::operator=(UDPServerSocket&& other) noexcept {
    if(this == &other) {
      return *this;
    }
    const bool restart = other.IsActive();
    this->Close();
    Socket::operator=(std::move(other));
    {
      std::scoped_lock lock(m_targetMutex, other.m_targetMutex);
      m_target = std::move(other.m_target);
    }
    {
      std::scoped_lock lock(m_onReadMutex, other.m_onReadMutex);
      m_onRead = std::move(other.m_onRead);
      other.m_onRead = nullptr;
    }
    other.Close();
    if(restart) {
      Open();
    }
    return *this;
  }

  void UDPServerSocket::SetOnRead(std::function<void(unsigned char* message, size_t byteCount, sockaddr_in sender)> onRead) {
    {
      std::unique_lock lock(m_onReadMutex);
      m_onRead = std::move(onRead);
    }
  }

  bool UDPServerSocket::Open() {
    return Socket::Open();
  }

  bool UDPServerSocket::Close() {
    return Socket::Close();
  }

  bool UDPServerSocket::Startup() {
    //1) Create UDP socket
    if(!Initialize(Protocol::UDP)) {
      ErrorInterpreter("Error initializing socket", false);
      return false;
    }
    SOCKET thisSocket = GetSocket();
    if(thisSocket == INVALID_SOCKET) {
      ErrorInterpreter("Socket no longer initialized", false);
      return false;
    }
    //2) Apply socket options
    const int option = 1;
    if(setsockopt(
      thisSocket,
      SOL_SOCKET,
      SO_BROADCAST,
      reinterpret_cast<const char*>(&option),
      sizeof(option)
    ) == SOCKET_ERROR) {
      ErrorInterpreter("Error enabling broadcasting: ", true);
      return false;
    }
    DWORD bytesReturned = 0;
    BOOL disableICMPReset = FALSE;
    ::WSAIoctl(
      thisSocket,
      _WSAIOW(IOC_VENDOR, 12),
      &disableICMPReset,
      sizeof(disableICMPReset),
      nullptr,
      0,
      &bytesReturned,
      nullptr,
      nullptr
    );
    //3) Build bind address and bind the socket
    UpdateInterpreter("Binding socket");
    sockaddr_in bindAddress{};
    int bindLength = sizeof(bindAddress);
    if(!GetServiceAddress(Protocol::UDP, bindAddress)) {
      ErrorInterpreter("Invalid server IP/Port", false);
      return false;
    }
    if(::bind(thisSocket, reinterpret_cast<const sockaddr*>(&bindAddress), bindLength) == SOCKET_ERROR) {
      ErrorInterpreter("Socket binding error: ", true);
      return false;
    }
    UpdateInterpreter("Binding successful!");
    //4) Initialize default target
    {
      std::unique_lock lock(m_targetMutex);
      if(m_target.sin_family == AF_UNSPEC) {
        m_target = bindAddress;
      }
    }
    //5) Listen on bound socket
    SetConfigured(true);
    UpdateInterpreter("Preparing to listen for messages");
    if(!StartWorker(&UDPServerSocket::StaticMessageHandler, this)) {
      ErrorInterpreter("Thread creation error: ", true);
      return false;
    }
    UpdateInterpreter("Ready to send messages");
    return true;
  }

  bool UDPServerSocket::Cleanup() {
    return true;
  }

  unsigned __stdcall UDPServerSocket::StaticMessageHandler(void* arg) noexcept {
    auto* serverSocket = static_cast<UDPServerSocket*>(arg);
    if(serverSocket) {
      serverSocket->MessageHandler();
    }
    return 0;
  }

  void UDPServerSocket::MessageHandler() {
    if(!SetState(State::Active)) {
      Close();
      return;
    }
    std::vector<unsigned char> buffer;
    SOCKET thisSocket = INVALID_SOCKET;
    while(IsActive() && !StopRequested()) {
      thisSocket = GetSocket();
      if(thisSocket == INVALID_SOCKET) {
        ErrorInterpreter("Socket no longer initialized", false);
        break;
      }
      size_t messageLength = WaitForMessage(thisSocket);
      if(messageLength == 0) {
        continue;
      }
      if(buffer.size() < messageLength) {
        buffer.resize(messageLength);
      }
      sockaddr_in clientAddress{};
      int addrLen = sizeof(clientAddress);
      int byteCount = ::recvfrom(
        thisSocket,
        reinterpret_cast<char*>(buffer.data()),
        static_cast<int>(messageLength),
        0,
        (sockaddr*)&clientAddress,
        &addrLen
      );
      if(!IsActive()) {
        break;
      }
      if(byteCount >= 0) {
		TrafficUpdate("Received " + std::to_string(byteCount) + " bytes from " + GetSocketAddress(clientAddress));
        OnRead(buffer.data(), static_cast<size_t>(byteCount), clientAddress);
        continue;
      }
      const int error = ::WSAGetLastError();
      if(error == WSAEINTR || error == WSAEWOULDBLOCK || error == WSAETIMEDOUT) {
        continue;
      }
      if(error == WSAEMSGSIZE) {
        ErrorInterpreter("Message too large - discarding", false);
        continue;
      }
      ErrorInterpreter("Socket error: ", true);
      break;
    }
  }

  size_t UDPServerSocket::WaitForMessage(SOCKET socket) const noexcept {
    fd_set fileDescriptor;
    FD_ZERO(&fileDescriptor);
    FD_SET(socket, &fileDescriptor);
    const int result = ::select(0, &fileDescriptor, nullptr, nullptr, nullptr);
    if(result <= 0 || !FD_ISSET(socket, &fileDescriptor)) {
      return 0;
    }
    u_long available = 0;
    if(::ioctlsocket(socket, FIONREAD, &available) == 0 && available > 0) {
      constexpr size_t maxPayload = 65507;
      return static_cast<size_t>(available > maxPayload ? maxPayload : available);
    }
    return 0;
  }

  int UDPServerSocket::Broadcast(const void* bytes, size_t byteCount) {
    const int port = GetServerPort();
    if(port <= 0) {
      ErrorInterpreter("Broadcast error: Unable to resolve a valid port", false);
      return 0;
    }
    return Broadcast(bytes, byteCount, port);
  }

  int UDPServerSocket::Broadcast(const void* bytes, size_t byteCount, int port) {
    if(!bytes || byteCount == 0) {
      ErrorInterpreter("Send error: invalid buffer/length", false);
      return 0;
    }
    if(byteCount > static_cast<size_t>(std::numeric_limits<int>::max())) {
      ErrorInterpreter("Send error: payload too large for WinSock", false);
      return 0;
    }
    SOCKET thisSocket = GetSocket();
    if(!(GetConfigured() && GetRegistered() && thisSocket != INVALID_SOCKET)) {
      ErrorInterpreter("Send error: socket is not initialized/bound", false);
      return 0;
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(static_cast<uint16_t>(port));
    address.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    TrafficUpdate("Broadcasting message to: " + GetSocketAddress(address) + " - " + std::to_string(byteCount) + " bytes");
    const int totalBytes = static_cast<int>(byteCount);
    const int sentBytes = SendAll(address, static_cast<const char*>(bytes), totalBytes);
    if(sentBytes != totalBytes) {
      ErrorInterpreter("Error broadcasting message to " + GetSocketAddress(address) + ": ", true);
    } else {
      TrafficUpdate("Successfully broadcasted message");
    }
    return sentBytes;
  }

  int UDPServerSocket::Send(const void* bytes, size_t byteCount, const std::string& targetIP, const std::string& targetPort) {
    return Send(bytes, byteCount, ConstructAddress(targetIP, targetPort));
  }

  int UDPServerSocket::Send(const void* bytes, size_t byteCount, const std::string& targetIP, int targetPort) {
    return Send(bytes, byteCount, ConstructAddress(targetIP, targetPort));
  }

  int UDPServerSocket::Send(const void* bytes, size_t byteCount, const std::string& targetAddress) {
    if(targetAddress.empty()) {
      ErrorInterpreter("Send error: invalid target address", false);
      return 0;
    }
    sockaddr_in target{};
    if(!ParseSocketAddress(targetAddress, Protocol::UDP, target)) {
      ErrorInterpreter("Send error: invalid target address format", false);
      return 0;
    }
    return Send(bytes, byteCount, target);
  }

  int UDPServerSocket::Send(const void* bytes, size_t byteCount, const sockaddr_in& target) {
    if(!IsValidEndpointIPv4(target)) {
      ErrorInterpreter("Send error: invalid target address", false);
      return 0;
    }
    {
      std::unique_lock lock(m_targetMutex);
      m_target = target;
    }
    return Send(bytes, byteCount);
  }

  int UDPServerSocket::Send(const void* bytes, size_t byteCount) {
    if(!bytes || byteCount == 0) {
      ErrorInterpreter("Send error: invalid buffer/length", false);
      return 0;
    }
    if(byteCount > static_cast<size_t>(std::numeric_limits<int>::max())) {
      ErrorInterpreter("Send error: payload too large for WinSock", false);
      return 0;
    }
    SOCKET thisSocket = GetSocket();
    if(!(GetConfigured() && GetRegistered() && thisSocket != INVALID_SOCKET)) {
      ErrorInterpreter("Send error: socket is not initialized/connected", false);
      return 0;
    }
    sockaddr_in target{};
    {
      std::shared_lock lock(m_targetMutex);
      target = m_target;
    }
    if(!IsValidEndpointIPv4(target)) {
      ErrorInterpreter("Send error: invalid target address", false);
      return 0;
    }
    TrafficUpdate("Sending message to: " + GetSocketAddress(target) + " - " + std::to_string(byteCount) + " bytes");
    const int totalBytes = static_cast<int>(byteCount);
    const int sentBytes = SendAll(target, static_cast<const char*>(bytes), totalBytes);
    if(sentBytes != totalBytes) {
      ErrorInterpreter("Error sending message to " + GetSocketAddress(target) + ": ", true);
    } else {
      TrafficUpdate("Successfully sent message");
    }
    return sentBytes;
  }

  int UDPServerSocket::SendAll(sockaddr_in socket, const char* buffer, int bufferSize) {
    int totalSent = 0;
    SOCKET thisSocket = INVALID_SOCKET;
    while(totalSent < bufferSize) {
      thisSocket = GetSocket();
      const int sentBytes = ::sendto(
        thisSocket,
        buffer + totalSent,
        bufferSize - totalSent,
        0,
        reinterpret_cast<SOCKADDR*>(&socket),
        sizeof(socket)
      );
      if(sentBytes == SOCKET_ERROR) {
        const int error = ::WSAGetLastError();
        if(error == WSAEINTR || error == WSAEWOULDBLOCK || error == WSAETIMEDOUT) {
          if(StopRequested()) {
            break;
          }
          continue;
        }
        return totalSent; //Short write on fatal error
      }
      if(sentBytes == 0) {
        //Not sure what this indicates on UDP?
        return totalSent;
      }
      totalSent += sentBytes;
    }
    return totalSent;
  }

  void UDPServerSocket::OnRead(unsigned char* message, size_t byteCount, sockaddr_in sender) {
    std::function<void(unsigned char* message, size_t byteCount, sockaddr_in sender)> callback;
    {
      std::shared_lock lock(m_onReadMutex);
      callback = m_onRead;
    }
    if(!callback) {
      std::string update = "Received message";
      update += " from " + GetSocketAddress(sender);
      UpdateInterpreter(update);
      return;
    }
    try {
      callback(message, byteCount, sender);
    } catch(const std::exception& e) {
      ErrorInterpreter(std::string("OnRead callback exception: ") + e.what(), false);
    } catch(...) {
      ErrorInterpreter("OnRead callback exception: unknown", false);
    }
  }
} //namespace SocketLibrary
