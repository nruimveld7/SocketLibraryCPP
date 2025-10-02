#include "pch.h"
#include "SocketLibrary/Socket.h"

namespace SocketLibrary {
  int Socket::s_wsaRefCount{0};
  std::mutex Socket::s_wsaMutex;
  WSADATA Socket::s_wsaData = {};

  Socket::~Socket() noexcept {
    m_workers.StopWorkers();
    m_workers.WaitForWorkers();
    {
      std::unique_lock lock(m_errorHandlerMutex);
      m_errorHandler = nullptr;
    }
    {
      std::unique_lock lock(m_updateHandlerMutex);
      m_updateHandler = nullptr;
    }
    UnregisterWSA();
  }

  Socket::Socket(Socket&& other) noexcept
    : m_thisSocket(other.m_thisSocket.exchange(INVALID_SOCKET, std::memory_order_acq_rel)),
    m_name(std::move(other.m_name)),
    m_serverIP(std::move(other.m_serverIP)),
    m_serverPort(other.m_serverPort),
    m_messageLength(other.m_messageLength.load(std::memory_order_relaxed)),
    m_wsaRegistered(other.m_wsaRegistered.load(std::memory_order_relaxed)),
    m_active(other.m_active.load(std::memory_order_relaxed)),
    m_configured(other.m_configured.load(std::memory_order_relaxed)),
    m_closeAttempt(other.m_closeAttempt.load(std::memory_order_relaxed)),
    m_trafficUpdates(other.m_trafficUpdates.load(std::memory_order_relaxed)) {
    //Move callbacks under exclusive locks (deadlock-safe pair lock).
      {
        std::scoped_lock lock(m_errorHandlerMutex, other.m_errorHandlerMutex);
        m_errorHandler = std::move(other.m_errorHandler);
      }
      {
        std::scoped_lock lock(m_updateHandlerMutex, other.m_updateHandlerMutex);
        m_updateHandler = std::move(other.m_updateHandler);
      }
      // Invalidate source.
      other.m_wsaRegistered = false;
      other.m_active = false;
      other.m_configured = false;
      other.m_closeAttempt = false;
      other.m_serverPort = INVALID_PORT;
      other.m_name.clear();
      other.m_serverIP.clear();
  }

  Socket& Socket::operator=(Socket&& other) noexcept {
    if(this != &other) {
      // Release current resource (safe even if INVALID_SOCKET).
      CloseSocketSafe(m_thisSocket, true);
      //Move callbacks first (deadlock-safe pair lock).
      {
        std::scoped_lock lock(m_errorHandlerMutex, other.m_errorHandlerMutex);
        m_errorHandler = std::move(other.m_errorHandler);
      }
      {
        std::scoped_lock lock(m_updateHandlerMutex, other.m_updateHandlerMutex);
        m_updateHandler = std::move(other.m_updateHandler);
      }
      //Steal scalar state.
      m_name = std::move(other.m_name);
      m_serverIP = std::move(other.m_serverIP);
      m_serverPort = other.m_serverPort;
      m_messageLength = other.m_messageLength.load(std::memory_order_relaxed);
      m_wsaRegistered = other.m_wsaRegistered.load(std::memory_order_relaxed);
      m_active = other.m_active.load(std::memory_order_relaxed);
      m_configured = other.m_configured.load(std::memory_order_relaxed);
      m_closeAttempt = other.m_closeAttempt.load(std::memory_order_relaxed);
      m_trafficUpdates = other.m_trafficUpdates.load(std::memory_order_relaxed);
      //Steal the handle last.
      m_thisSocket.store(other.m_thisSocket.exchange(INVALID_SOCKET, std::memory_order_acq_rel), std::memory_order_release);
      //Invalidate source.
      other.m_wsaRegistered = false;
      other.m_active = false;
      other.m_configured = false;
      other.m_closeAttempt = false;
      other.m_serverPort = INVALID_PORT;
      other.m_name.clear();
      other.m_serverIP.clear();
    }
    return *this;
  }

  void Socket::SetErrorHandler(std::function<void(const std::string& errorMessage)> errorHandler) {
    std::unique_lock lock(m_errorHandlerMutex);
    m_errorHandler = std::move(errorHandler);
    m_errorHandlerFaulted.store(false, std::memory_order_release);
  }

  void Socket::SetUpdateHandler(std::function<void(const std::string& updateMessage)> updateHandler) {
    std::unique_lock lock(m_updateHandlerMutex);
    m_updateHandler = std::move(updateHandler);
  }

  std::string Socket::GetName() const noexcept {
    std::shared_lock lock(m_configMutex);
    return m_name;
  }

  bool Socket::SetName(const std::string& name) {
    std::unique_lock<std::shared_mutex> lock(m_configMutex);
    m_name = name;
    return true;
  }

  std::string Socket::GetServerIP() const noexcept {
    std::shared_lock lock(m_configMutex);
    return m_serverIP;
  }

  bool Socket::SetServerIP(const std::string& ip) {
    IN_ADDR address{};
    if(::InetPtonA(AF_INET, ip.c_str(), &address) != 1) {
      ErrorInterpreter("Error changing IP address", false);
      return false;
    }
    {
      std::unique_lock lock(m_configMutex);
      m_serverIP = ip;
    }
    UpdateInterpreter("Successfully set IP address: " + ip);
    return true;
  }

  int Socket::GetServerPort() const noexcept {
    std::shared_lock lock(m_configMutex);
    return m_serverPort;
  }

  bool Socket::SetServerPort(int port) {
    if(port <= 0 || port > 65535) {
      ErrorInterpreter("Error: port number attempt '" + std::to_string(port) + "' is not valid (must be a number: 1-65535)", false);
      return false;
    }
    {
      std::unique_lock lock(m_configMutex);
      m_serverPort = port;
    }
    UpdateInterpreter("Successfully set port number: " + std::to_string(port));
    return true;
  }

  bool Socket::SetServerPort(const std::string& port) {
    int portAttempt = 0;
    if(!StringToInt(port, portAttempt)) {
      ErrorInterpreter("Error parsing port value from '" + port + "'", false);
      return false;
    }
    return SetServerPort(portAttempt);
  }

  int Socket::GetMessageLength() const noexcept {
    return m_messageLength.load(std::memory_order_acquire);
  }

  bool Socket::SetMessageLength(int messageLength) {
    if(messageLength > 0) {
      m_messageLength = messageLength;
      return true;
    }
    ErrorInterpreter("Error: message length attempt '" + std::to_string(messageLength) + "' is not valid (must be a number > 0)", false);
    return false;
  }

  bool Socket::SetMessageLength(const std::string& messageLength) {
    int msgLenAttempt = 0;
    if(!StringToInt(messageLength, msgLenAttempt)) {
      ErrorInterpreter("Error parsing message length value from '" + messageLength + "'", false);
      return false;
    }
    return SetMessageLength(msgLenAttempt);
  }

  void Socket::SetTrafficUpdates(bool trafficUpdates) noexcept {
    m_trafficUpdates.store(trafficUpdates, std::memory_order_release);
  }

  bool Socket::Close() {
    if(IsClosing()) {
      return true;
    }
    SetClosing(true);
    SetActive(false);
    const bool socketClosed = CloseSocketSafe(m_thisSocket, true);
    const bool cleaned = Cleanup();
    m_workers.StopWorkers();
    m_workers.WaitForWorkers();
    SetConfigured(false);
    const bool wsaUnregistered = UnregisterWSA();
    return socketClosed && cleaned && wsaUnregistered;
  }

  bool Socket::GetActive() const noexcept {
    return IsActive();
  }

  bool Socket::CheckIP(const std::string& ip) noexcept {
    IN_ADDR address{};
    return ::InetPtonA(AF_INET, ip.c_str(), &address) == 1;
  }

  bool Socket::CheckPort(int port) noexcept {
    return port >= 1 && port <= 65535;
  }

  bool Socket::CheckPort(const std::string& port) {
    int portAttempt = 0;
    if(!StringToInt(port, portAttempt)) {
      return false;
    }
    return CheckPort(portAttempt);
  }

  Socket::Socket() {
    {
      std::unique_lock lock(m_errorHandlerMutex);
      m_errorHandler = nullptr;
      m_errorHandlerFaulted.store(true, std::memory_order_release);
    }
    {
      std::unique_lock lock(m_updateHandlerMutex);
      m_updateHandler = nullptr;
    }
    m_thisSocket.store(INVALID_SOCKET, std::memory_order_relaxed);
    m_serverIP = "127.0.0.1";
    m_serverPort = 55555;
    SetRegistered(false);
    SetActive(false);
    SetConfigured(false);
    SetClosing(false);
    SetTrafficUpdates(true);
    m_messageLength = 1000;
  }

  SOCKET Socket::GetSocket() const noexcept {
    return m_thisSocket.load(std::memory_order_acquire);
  }

  bool Socket::ReinitializeSocket(Protocol protocol, bool shutdown) {
    //Atomically detach the current handle
    SetConfigured(false);
    SOCKET oldSocket = m_thisSocket.exchange(INVALID_SOCKET, std::memory_order_acq_rel);
    if(oldSocket != INVALID_SOCKET) {
      CloseSocketSafe(oldSocket, shutdown);
    }
    //Initialize a new socket
    if(!Initialize(protocol)) {
      ErrorInterpreter("Reinitialization failed", false);
      return false;
    }
    SetConfigured(true);
    return true;
  }

  bool Socket::GetServiceAddress(Protocol protocol, sockaddr_in& outAddress) {
    std::string ip;
    int port = 0;
    {
      std::shared_lock lock(m_configMutex);
      ip = m_serverIP;
      port = m_serverPort;
    }
    return ParseSocketAddress(ip, port, protocol, outAddress);
  }

  bool Socket::Initialize(Protocol protocol) {
    m_workers.StopWorkers();
    m_workers.WaitForWorkers();
    m_workers = WorkerGroup{};
    if(!RegisterWSA()) {
      ErrorInterpreter("Error initializing socket: failed to register WSA", false);
      return false;
    }
    addrinfo hints{};
    if(!GetHints(hints, protocol, AF_INET, 0)) {
      ErrorInterpreter("Error initializing socket: unrecognized protocol", false);
      UnregisterWSA();
      return false;
    }
    std::string ip;
    int port = 0;
    {
      std::shared_lock lock(m_configMutex);
      ip = m_serverIP;
      port = m_serverPort;
    }
    const char* protoName = (protocol == Protocol::UDP ? "UDP" : "TCP");
    UpdateInterpreter(std::string("Initializing") + protoName + " socket " + ip + ":" + std::to_string(port));
    SOCKET socket = ::socket(hints.ai_family, hints.ai_socktype, hints.ai_protocol);
    if(socket == INVALID_SOCKET) {
      ErrorInterpreter("Error initializing socket: ", true);
      UnregisterWSA();
      return false;
    }
    m_thisSocket.store(socket, std::memory_order_release);
    SetClosing(false);
    UpdateInterpreter("Socket initialized successfully!");
    return true;
  }

  bool Socket::RegisterWSA() {
    if(IsRegistered()) {
      UpdateInterpreter("WSA already registered");
      return true;
    }
    bool failed = false;
    std::string msg;
    {
      std::scoped_lock lock(s_wsaMutex);
      if(s_wsaRefCount == 0) {
        WORD versionRequested = MAKEWORD(2, 2);
        int error = ::WSAStartup(versionRequested, &s_wsaData);
        if(error != 0) {
          failed = true;
          msg = "WSAStartup failed: " + std::to_string(error);
        } else if(s_wsaData.wVersion != versionRequested) {
          ::WSACleanup();
          failed = true;
          std::string requestedStr = std::to_string(LOBYTE(versionRequested)) + "." + std::to_string(HIBYTE(versionRequested));
          std::string foundStr = std::to_string(LOBYTE(s_wsaData.wVersion)) + "." + std::to_string(HIBYTE(s_wsaData.wVersion));
          msg = "Winsock version mismatch: found " + foundStr + ", required " + requestedStr;
        } else {
          msg = "WSA initialized";
        }
      } else {
        msg = "WSA already initialized";
      }
      if(!failed) {
        msg += " - status: ";
        msg += s_wsaData.szSystemStatus;
        ++s_wsaRefCount;
        SetRegistered(true);
      }
    }
    if(failed) {
      ErrorInterpreter(msg, false);
      return false;
    }
    UpdateInterpreter(msg);
    return true;
  }

  bool Socket::StartWorker(
    unsigned(__stdcall* workerFunction)(void*),
    void* context,
    unsigned stack,
    unsigned initFlags,
    unsigned* outID
  ) noexcept {
    return m_workers.StartWorker(workerFunction, context, stack, initFlags, outID);
  }

  bool Socket::StopRequested() const noexcept {
    return m_workers.StopRequested();
  }

  int Socket::ActiveWorkerCount() const noexcept {
    return m_workers.ActiveWorkerCount();
  }

  bool Socket::UnregisterWSA() {
    if(!IsRegistered()) {
      UpdateInterpreter("WSA never registered for this socket");
      return true;
    }
    bool failed = false;
    std::string msg = "";
    {
      std::scoped_lock lock(s_wsaMutex);
      if(!IsRegistered()) {
        msg = "WSA already unregistered for this socket";
      } else {
        SetRegistered(false);
        SetConfigured(false);
        SetActive(false);
        if(s_wsaRefCount > 0) {
          --s_wsaRefCount;
          if(s_wsaRefCount == 0) {
            int error = ::WSACleanup();
            if(error != 0) {
              msg = "WSACleanup failed: ";
              int code = WSAGetLastError();
              msg += std::to_string(code);
              msg += " - ";
              msg += DecodeSocketError(code);
              failed = true;
              ++s_wsaRefCount;
              SetRegistered(true);
            } else {
              msg = "WSA released successfully";
            }
          }
        } else {
          s_wsaRefCount = 0;
          msg = "WSA refcount underflow";
        }
        if(msg.empty()) {
          msg = "WSA unregistered for this socket - registered sockets remaining: " + std::to_string(s_wsaRefCount);
        }
      }
    }
    if(failed) {
      ErrorInterpreter(msg, false);
      return false;
    }
    UpdateInterpreter(msg);
    return true;
  }

  bool Socket::CloseSocketSafe(SOCKET& socketToClose, bool shutDownSocket) {
    UpdateInterpreter("Closing socket");
    if(socketToClose == INVALID_SOCKET) {
      UpdateInterpreter("Socket already closed");
      return true;
    }
    if(shutDownSocket) {
      ShutDownSocket(socketToClose);
    }
    if(::closesocket(socketToClose) == SOCKET_ERROR) {
      ErrorInterpreter("Error closing socket: ", true);
      return false;
    }
    UpdateInterpreter("Closed socket");
    socketToClose = INVALID_SOCKET;
    return true;
  }

  bool Socket::CloseSocketSafe(std::atomic<SOCKET>& socketToClose, bool shutDownSocket) {
    SOCKET socket = socketToClose.exchange(INVALID_SOCKET, std::memory_order_acq_rel);
    return CloseSocketSafe(socket, shutDownSocket);
  }

  bool Socket::ShutDownSocket(SOCKET& socketToShutDown) {
    if(::shutdown(socketToShutDown, SD_BOTH) == SOCKET_ERROR) {
      ErrorInterpreter("Error shutting down socket: ", true);
      return false;
    } else {
      UpdateInterpreter("Shut down socket");
      return true;
    }
  }

  bool Socket::IsRegistered() const noexcept {
    return m_wsaRegistered.load(std::memory_order_acquire);
  }

  void Socket::SetRegistered(bool registered) noexcept {
    m_wsaRegistered.store(registered, std::memory_order_release);
  }

  bool Socket::IsActive() const noexcept {
    return m_active.load(std::memory_order_acquire);
  }

  void Socket::SetActive(bool active) noexcept {
    m_active.store(active, std::memory_order_release);
  }

  bool Socket::IsConfigured() const noexcept {
    return m_configured.load(std::memory_order_acquire);
  }

  void Socket::SetConfigured(bool configured) noexcept {
    m_configured.store(configured, std::memory_order_release);
  }

  bool Socket::IsClosing() const noexcept {
    return m_closeAttempt.load(std::memory_order_acquire);
  }

  void Socket::SetClosing(bool closing) noexcept {
    m_closeAttempt.store(closing, std::memory_order_release);
  }

  bool Socket::TrafficUpdatesEnabled() const noexcept {
    return m_trafficUpdates.load(std::memory_order_acquire);
  }

  void Socket::TrafficUpdate(const std::string& trafficMessage) {
    if(!TrafficUpdatesEnabled()) {
      return;
    }
    UpdateInterpreter(trafficMessage);
  }

  void Socket::ErrorInterpreter(const std::string& errorMessage, bool hasCode) {
    std::string message = errorMessage;
    if(hasCode) {
      int code = WSAGetLastError();
      message += std::to_string(code);
      message += " - ";
      message += DecodeSocketError(code);
    }
    std::function<void(const std::string& errorMessage)> callback;
    {
      std::shared_lock lock(m_errorHandlerMutex);
      callback = m_errorHandler;
    }
    if(!callback || m_errorHandlerFaulted.load(std::memory_order_acquire)) {
      return;
    }
    try {
      callback(message);
    } catch(const std::exception& e) {
      m_errorHandlerFaulted.store(true, std::memory_order_release);
      FallbackLog("ErrorHandler callback exception:");
      FallbackLog(e.what());
    } catch(...) {
      m_errorHandlerFaulted.store(true, std::memory_order_release);
      FallbackLog("ErrorHandler callback exception: Unknown");
    }
  }

  void Socket::UpdateInterpreter(const std::string& updateMessage) {
    std::function<void(const std::string& updateMessage)> callback;
    {
      std::shared_lock lock(m_updateHandlerMutex);
      callback = m_updateHandler;
    }
    if(!callback) {
      return;
    }
    try {
      callback(updateMessage);
    } catch(const std::exception& e) {
      ErrorInterpreter(std::string("UpdateHandler callback exception: ") + e.what(), false);
    } catch(...) {
      ErrorInterpreter("UpdateHandler callback exception: unknown", false);
    }
  }

  std::string Socket::DecodeSocketError(int errorCode) {
    std::string result;
    LPSTR message = nullptr;

    // Call FormatMessageA to retrieve the error message
    DWORD chars = FormatMessageA(
      FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK | FORMAT_MESSAGE_ALLOCATE_BUFFER,
      nullptr,
      errorCode,
      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
      (LPSTR)&message,
      0,
      nullptr
    );

    if(chars > 0 && message != nullptr) {
      result.append(message);
      LocalFree(message);
    } else {
      result = "Unknown error code: " + std::to_string(errorCode);
    }
    return result;
  }

  std::string Socket::ConstructAddress(const std::string& ip, const std::string& port) {
    if(!CheckIP(ip) || !CheckPort(port)) {
      return std::string();
    }
    return ip + ":" + port;
  }

  std::string Socket::ConstructAddress(const std::string& ip, int port) {
    if(!CheckIP(ip) || !CheckPort(port)) {
      return std::string();
    }
    return ip + ":" + std::to_string(port);
  }

  std::string Socket::GetPeerAddress(const SOCKET& socket) {
    std::string socketIP = GetPeerIP(socket);
    int socketPort = GetPeerPort(socket);
    if(socketIP.empty() || socketPort == INVALID_PORT) {
      return std::string();
    }
    return ConstructAddress(socketIP, socketPort);
  }

  std::string Socket::GetPeerIP(const SOCKET& socket) {
    if(socket == INVALID_SOCKET) {
      return std::string();
    }
    sockaddr_in address{};
    int addressSize = sizeof(address);
    if(::getpeername(socket, reinterpret_cast<sockaddr*>(&address), &addressSize) != 0) {
      return std::string();
    }
    return GetSocketIP(address);
  }

  int Socket::GetPeerPort(const SOCKET& socket) noexcept {
    if(socket == INVALID_SOCKET) {
      return INVALID_PORT;
    }
    sockaddr_in address{};
    int addressSize = sizeof(address);
    if(::getpeername(socket, reinterpret_cast<sockaddr*>(&address), &addressSize) != 0) {
      return INVALID_PORT;
    }
    return GetSocketPort(address);
  }

  std::string Socket::GetLocalAddress(const SOCKET& socket) {
    std::string socketIP = GetLocalIP(socket);
    int socketPort = GetLocalPort(socket);
    if(socketIP.empty() || socketPort == INVALID_PORT) {
      return std::string();
    }
    return ConstructAddress(socketIP, socketPort);
  }

  std::string Socket::GetLocalIP(const SOCKET& socket) {
    if(socket == INVALID_SOCKET) {
      return std::string();
    }
    sockaddr_in address{};
    int addressSize = sizeof(address);
    if(::getsockname(socket, reinterpret_cast<sockaddr*>(&address), &addressSize) != 0) {
      return std::string();
    }
    return GetSocketIP(address);
  }

  int Socket::GetLocalPort(const SOCKET& socket) noexcept {
    if(socket == INVALID_SOCKET) {
      return INVALID_PORT;
    }
    sockaddr_in address{};
    int addressSize = sizeof(address);
    if(::getsockname(socket, reinterpret_cast<sockaddr*>(&address), &addressSize) != 0) {
      return INVALID_PORT;
    }
    return GetSocketPort(address);
  }

  std::string Socket::GetSocketAddress(const sockaddr_in& socket) {
    std::string socketIP = GetSocketIP(socket);
    int socketPort = GetSocketPort(socket);
    if(socketIP.empty() || socketPort == INVALID_PORT) {
      return std::string();
    }
    return ConstructAddress(socketIP, socketPort);
  }

  std::string Socket::GetSocketIP(const sockaddr_in& addr) {
    int addrLen = sizeof(addr);
    char ipStr[NI_MAXHOST] = {0};
    int result = ::getnameinfo(reinterpret_cast<const sockaddr*>(&addr), addrLen, ipStr, NI_MAXHOST, nullptr, 0, NI_NUMERICHOST);
    if(result != 0) {
      return std::string();
    }
    return std::string(ipStr);
  }

  int Socket::GetSocketPort(const sockaddr_in& addr) noexcept {
    return ::ntohs(addr.sin_port);
  }

  bool Socket::ParseSocketAddress(const std::string& address, Protocol protocol, sockaddr_in& out) {
    const auto delimiterPos = address.rfind(':');
    if(delimiterPos == std::string::npos || delimiterPos == address.size() - 1) {
      return false;
    }
    const std::string ip = address.substr(0, delimiterPos);
    const std::string port = address.substr(delimiterPos + 1);
    return ParseSocketAddress(ip, port, protocol, out);
  }

  bool Socket::ParseSocketAddress(const std::string& ip, int port, Protocol protocol, sockaddr_in& out) {
    const std::string portStr = std::to_string(port);
    return ParseSocketAddress(ip, portStr, protocol, out);
  }

  bool Socket::ParseSocketAddress(const std::string& ip, const std::string& port, Protocol protocol, sockaddr_in& out) {
    if(!CheckPort(port) || !CheckIP(ip)) {
      return false;
    }
    addrinfo hints = {};
    if(!GetHints(hints, protocol, AF_INET, 0)) {
      return false;
    }
    hints.ai_flags |= AI_NUMERICSERV; //Port is numeric
    IN_ADDR address{};
    if(::InetPtonA(AF_INET, ip.c_str(), &address) == 1) {
      hints.ai_flags |= AI_NUMERICHOST; //IP is numeric
    }

    addrinfo* result = nullptr;
    const int error = ::getaddrinfo(ip.c_str(), port.c_str(), &hints, &result);
    if(error != 0 || !result) {
      return false;
    }
    for(addrinfo* addressInfo = result; addressInfo != nullptr; addressInfo = addressInfo->ai_next) {
      if(addressInfo->ai_family == AF_INET && addressInfo->ai_addrlen >= sizeof(sockaddr_in)) {
        std::memcpy(&out, addressInfo->ai_addr, sizeof(sockaddr_in));
        ::freeaddrinfo(result);
        return true;
      }
    }
    ::freeaddrinfo(result);
    return false;
  }

  bool Socket::GetHints(addrinfo& outHints, Protocol protocol, int family, int flags) noexcept {
    outHints = {};
    switch(protocol) {
      case Protocol::UDP:
        outHints.ai_socktype = SOCK_DGRAM;
        outHints.ai_protocol = IPPROTO_UDP;
        break;
      case Protocol::TCP:
        outHints.ai_socktype = SOCK_STREAM;
        outHints.ai_protocol = IPPROTO_TCP;
        break;
      default:
        return false;
    }
    outHints.ai_family = family;
    outHints.ai_flags = flags;
    return true;
  }

  bool Socket::StringToInt(const std::string& intStr, int& outInt) noexcept {
    if(intStr.empty()) {
      return false;
    }
    int value = 0;
    const char* first = intStr.data();
    const char* last = first + intStr.size();
    auto [ptr, error] = std::from_chars(first, last, value, 10);
    if(error != std::errc{} || ptr != last) {
      return false;
    }
    outInt = value;
    return true;
  }

  void Socket::FallbackLog(const char* msg) noexcept {
#ifdef _WIN32
    ::OutputDebugStringA(msg);
    ::OutputDebugStringA("\r\n");
#endif
    // Best-effort stderr (OK if no console)
    std::fputs(msg, stderr);
    std::fputc('\n', stderr);
  }

  bool Socket::IsMulticastIPv4(const in_addr& address) noexcept {
    return (ntohl(address.s_addr) & 0xF0000000u) == 0xE0000000u;
  }

  bool Socket::IsInitializedIPv4(const sockaddr_in& socketAddress) noexcept {
    return socketAddress.sin_family == AF_INET;
  }

  bool Socket::IsValidEndpointIPv4(const sockaddr_in& socketAddress) noexcept {
    return socketAddress.sin_family == AF_INET && socketAddress.sin_port != 0 && socketAddress.sin_addr.s_addr != htonl(INADDR_ANY);
  }

  bool Socket::IsLimitedBroadcastIPv4(const in_addr& address) noexcept {
    return address.s_addr == htonl(INADDR_BROADCAST);
  }
} //namespace SocketLibrary
