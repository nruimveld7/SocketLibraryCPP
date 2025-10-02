#include "pch.h"
#include "SocketLibrary/TCPClientSocket.h"

namespace SocketLibrary {
  TCPClientSocket::TCPClientSocket() {
    {
      std::unique_lock lock(m_onDisconnectMutex);
      m_onDisconnect = nullptr;
    }
    {
      std::unique_lock lock(m_onReadMutex);
      m_onRead = nullptr;
    }
    m_connected.store(false, std::memory_order_relaxed);
    m_connectionDelay.store(5, std::memory_order_relaxed);
    m_cancelConnect.store(false, std::memory_order_relaxed);
    m_connecting.store(false, std::memory_order_relaxed);
  }

  TCPClientSocket::~TCPClientSocket() noexcept {
    Close();
    {
      std::unique_lock lock(m_onDisconnectMutex);
      m_onDisconnect = nullptr;
    }
    {
      std::unique_lock lock(m_onReadMutex);
      m_onRead = nullptr;
    }
  }

  void TCPClientSocket::SetOnDisconnect(std::function<void()> onDisconnect) {
    std::unique_lock lock(m_onDisconnectMutex);
    m_onDisconnect = std::move(onDisconnect);
  }

  void TCPClientSocket::SetOnRead(std::function<void(unsigned char* message, int byteCount)> onRead) {
    std::unique_lock lock(m_onReadMutex);
    m_onRead = std::move(onRead);
  }

  int TCPClientSocket::GetConnectionDelay() const noexcept {
    return m_connectionDelay.load(std::memory_order_acquire);
  }

  bool TCPClientSocket::SetConnectionDelay(int connectionDelay) {
    if(connectionDelay >= 1) {
      m_connectionDelay = connectionDelay;
      UpdateInterpreter("Successfully set connection delay: " + std::to_string(connectionDelay));
      return true;
    } else {
      ErrorInterpreter("Error: connection delay attempt '" + std::to_string(connectionDelay) + "' is not valid (must be a number > 0)", false);
      return false;
    }
  }

  bool TCPClientSocket::SetConnectionDelay(const std::string& connectionDelay) {
    int connDelayAttempt = 0;
    if(StringToInt(connectionDelay, connDelayAttempt)) {
      return SetConnectionDelay(connDelayAttempt);
    } else {
      ErrorInterpreter("Error parsing connection delay value from '" + connectionDelay + "'", false);
      return false;
    }
  }

  bool TCPClientSocket::IsConnected() const noexcept {
    return m_connected.load(std::memory_order_acquire);
  }

  bool TCPClientSocket::IsCancelling() const noexcept {
    return m_cancelConnect.load(std::memory_order_acquire);
  }

  bool TCPClientSocket::IsConnecting() const noexcept {
    return m_connecting.load(std::memory_order_acquire);
  }

  bool TCPClientSocket::Open() {
    //1) Create the TCP socket
    SetCancelling(false);
    if(!Initialize(Protocol::TCP)) {
      ErrorInterpreter("Error initializing socket", false);
      Close();
      return false;
    }
    SOCKET thisSocket = GetSocket();
    if(thisSocket == INVALID_SOCKET) {
      ErrorInterpreter("Socket no longer initialized", false);
      Close();
      return false;
    }
    //2) Attempt to connect to server socket
    SetConfigured(true);
    SetClosing(false);
    UpdateInterpreter("Ready to connect");
    if(!StartWorker(&TCPClientSocket::StaticConnectionHandler, this)) {
      ErrorInterpreter("Thread creation error: ", true);
      Close();
      return false;
    }
    return true;
  }

  bool TCPClientSocket::Close() {
    return Socket::Close();
  }

  bool TCPClientSocket::ReadyToConnect() const noexcept {
    const bool configured = IsConfigured();
    const bool registered = IsRegistered();
    const bool connected = IsConnected();
    const bool closing = IsClosing();
    SOCKET thisSocket = GetSocket();
    return !connected && configured && registered && !closing && thisSocket != INVALID_SOCKET;
  }

  unsigned __stdcall TCPClientSocket::StaticConnectionHandler(void* arg) noexcept {
    auto* clientSocket = static_cast<TCPClientSocket*>(arg);
    if(clientSocket) {
      clientSocket->ConnectionHandler();
    }
    return 0;
  }

  void TCPClientSocket::ConnectionHandler() {
    const std::chrono::milliseconds minBackoff{100};
    const std::chrono::milliseconds maxBackoff{5000};
    std::chrono::milliseconds backoff = minBackoff;
    while(true) {
      if(StopRequested() || IsCancelling()) {
        break;
      }
      if(IsConnected()) {
        backoff = minBackoff;
      } else if(!ReadyToConnect()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        continue;
      } else if(!ConnectAttempt()) {
        if(StopRequested() || IsCancelling()) {
          break;
        }
        std::this_thread::sleep_for(backoff);
        backoff = (backoff * 2 < maxBackoff) ? backoff * 2 : maxBackoff;
        continue;
      } else {
        backoff = minBackoff;
      }
      if(StopRequested() || IsCancelling()) {
        break;
      }
      MessageHandler();
      if(StopRequested() || IsCancelling()) {
        break;
      }
      if(!ReinitializeSocket(Protocol::TCP, false)) {
        ErrorInterpreter("Reconnect: reinitialization failed", false);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
      }
    }
  }

  bool TCPClientSocket::ConnectAttempt() {
    SetConnecting(true);
    UpdateInterpreter("Attempting socket connection");
    int delay = m_connectionDelay.load(std::memory_order_relaxed);
    delay = delay > 1 ? delay : 1;
    while(!IsCancelling() && !StopRequested() && ReadyToConnect()) {
      //1) Load the current handle each iteration
      SOCKET thisSocket = GetSocket();
      if(thisSocket == INVALID_SOCKET) {
        ErrorInterpreter("Socket no longer initialized", false);
        break;
      }
      if(IsConnected()) {
        SetConnecting(false);
        return true;
      }
      //2) Resolve target each time (handle runtime changes)
      sockaddr_in address{};
      int addressSize = sizeof(address);
      if(!GetServiceAddress(Protocol::TCP, address)) {
        ErrorInterpreter("Invalid server IP/Port", false);
        break;
      }
      //3) Attempt connect using the freshly loaded handle
      if(::connect(thisSocket, reinterpret_cast<SOCKADDR*>(&address), addressSize) != SOCKET_ERROR) {
        SetConnected(true);
        SetActive(true);
        SetConnecting(false);
        UpdateInterpreter("Client connected!");
        return true;
      }
      //4) Handle common race conditions
      const int error = WSAGetLastError();
      if(error == WSAEISCONN) {
        //Already connected
        SetConnected(true);
        SetActive(true);
        SetConnecting(false);
        return true;
      }
      //5) Retry after a delay
      ErrorInterpreter("Error connecting to socket: ", true);
      delay = m_connectionDelay.load(std::memory_order_relaxed);
      if(delay <= 0) {
        delay = 1;
      }
      for(int i = 0; i < delay; ++i) {
        if(IsCancelling() || StopRequested()) {
          SetConnecting(false);
          return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      }
    }
    SetConnecting(false);
    return false;
  }

  void TCPClientSocket::MessageHandler() {
    int lastMessageLength = -1;
    std::vector<unsigned char> buffer;
    while(IsConnected() && !StopRequested()) {
      int messageLength = GetMessageLength();
      if(messageLength <= 0) {
        ErrorInterpreter("Invalid message length: " + std::to_string(messageLength), false);
        OnDisconnect();
        break;
      }
      if(messageLength != lastMessageLength) {
        buffer.resize(messageLength);
        lastMessageLength = messageLength;
      }
      SOCKET thisSocket = GetSocket();
      const int byteCount = ::recv(thisSocket, reinterpret_cast<char*>(buffer.data()), messageLength, 0);
      if(byteCount > 0) {
        TrafficUpdate("Received " + std::to_string(byteCount) + " bytes from " + GetPeerAddress(thisSocket));
        OnRead(buffer.data(), byteCount);
        continue;
      }
      if(byteCount == 0) {
        UpdateInterpreter("Connection closed by server");
        break;
      }
      const int error = ::WSAGetLastError();
      if(error == WSAEINTR || error == WSAEWOULDBLOCK || error == WSAETIMEDOUT) {
        if(!IsConnected() || StopRequested()) {
          break;
        }
        continue;
      }
      ErrorInterpreter("Socket Error: ", true);
      break;
    }
    OnDisconnect();
  }

  int TCPClientSocket::Send(const void* bytes, size_t byteCount) {
    if(!bytes || byteCount == 0) {
      ErrorInterpreter("Send(bytes): invalid buffer/length", false);
      return 0;
    }
    if(byteCount > static_cast<size_t>(std::numeric_limits<int>::max())) {
      ErrorInterpreter("Send(bytes): payload too large for WinSock", false);
      return 0;
    }
    SOCKET thisSocket = GetSocket();
    if(!(IsConfigured() && IsRegistered() && IsConnected() && thisSocket != INVALID_SOCKET)) {
      ErrorInterpreter("Socket is not initialized/connected", false);
      return 0;
    }
    TrafficUpdate("Sending message - " + std::to_string(byteCount) + " Bytes");
    const int totalBytes = static_cast<int>(byteCount);
    const int sentBytes = SendAll(static_cast<const char*>(bytes), totalBytes);
    if(sentBytes != totalBytes) {
      ErrorInterpreter("Error sending message: ", true);
    } else {
      TrafficUpdate("Successfully sent message");
    }
    return sentBytes;
  }

  int TCPClientSocket::SendAll(const char* buffer, int bufferSize) {
    int totalSent = 0;
    SOCKET thisSocket = INVALID_SOCKET;
    while(totalSent < bufferSize) {
      thisSocket = GetSocket();
      if(thisSocket == INVALID_SOCKET) {
        return totalSent;
      }
      const int sentBytes = ::send(thisSocket, buffer + totalSent, bufferSize - totalSent, 0);
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
        //Peer closed
        return totalSent;
      }
      totalSent += sentBytes;
    }
    return totalSent;
  }

  void TCPClientSocket::SetConnected(bool connected) noexcept {
    m_connected.store(connected, std::memory_order_release);
  }

  void TCPClientSocket::SetCancelling(bool cancelling) noexcept {
    m_cancelConnect.store(cancelling, std::memory_order_release);
  }

  void TCPClientSocket::SetConnecting(bool connecting) noexcept {
    m_connecting.store(connecting, std::memory_order_release);
  }

  bool TCPClientSocket::Cleanup() {
    SetCancelling(true);
    SetConnecting(false);
    OnDisconnect();
    return true;
  }

  void TCPClientSocket::OnDisconnect() {
    const bool wasConnected = m_connected.exchange(false, std::memory_order_acq_rel);
    if(!wasConnected) {
      return;
    }
    std::function<void()> callback;
    {
      std::shared_lock lock(m_onDisconnectMutex);
      callback = m_onDisconnect;
    }
    if(!callback) {
      UpdateInterpreter("Disconnected");
      return;
    }
    try {
      callback();
    } catch(const std::exception& e) {
      ErrorInterpreter(std::string("OnDisconnect callback exception: ") + e.what(), false);
    } catch(...) {
      ErrorInterpreter("OnDisconnect callback exception: unknown", false);
    }
  }

  void TCPClientSocket::OnRead(unsigned char* message, int byteCount) {
    std::function<void(unsigned char* message, int byteCount)> callback;
    {
      std::shared_lock lock(m_onReadMutex);
      callback = m_onRead;
    }
    if(!callback) {
      UpdateInterpreter("Received message");
      return;
    }
    try {
      callback(message, byteCount);
    } catch(const std::exception& e) {
      ErrorInterpreter(std::string("OnRead callback exception: ") + e.what(), false);
    } catch(...) {
      ErrorInterpreter("OnRead callback exception: unknown", false);
    }
  }
} //namespace SocketLibrary
