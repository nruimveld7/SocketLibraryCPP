#include "pch.h"
#include "SocketLibrary/TCPServerSocket.h"

namespace SocketLibrary {
  TCPServerSocket::TCPServerSocket() {
    {
      std::unique_lock lock(m_onClientDisconnectMutex);
      m_onClientDisconnect = nullptr;
    }
    {
      std::unique_lock lock(m_onReadMutex);
      m_onRead = nullptr;
    }
    m_maxLength.store(64 * 1024, std::memory_order_relaxed);
    m_listenBacklog.store(64, std::memory_order_relaxed);
    m_maxConnections.store(10, std::memory_order_relaxed);
  }

  TCPServerSocket::~TCPServerSocket() noexcept {
    Close();
    {
      std::unique_lock lock(m_onClientDisconnectMutex);
      m_onClientDisconnect = nullptr;
    }
    {
      std::unique_lock lock(m_onReadMutex);
      m_onRead = nullptr;
    }
  }

  TCPServerSocket::TCPServerSocket(TCPServerSocket&& other) noexcept : TCPServerSocket() {
    *this = std::move(other);
  }

  TCPServerSocket& TCPServerSocket::operator=(TCPServerSocket&& other) noexcept {
    if(this == &other) {
      return *this;
    }
    const bool restart = other.IsActive();
    this->Close();
    Socket::operator=(std::move(other));
    m_maxLength.store(other.m_maxLength.load(std::memory_order_relaxed), std::memory_order_relaxed);
    m_listenBacklog.store(other.m_listenBacklog.load(std::memory_order_relaxed), std::memory_order_relaxed);
    m_maxConnections.store(other.m_maxConnections.load(std::memory_order_relaxed), std::memory_order_relaxed);
    {
      std::shared_lock sourceLock(other.m_socketOptionsMutex);
      std::unique_lock destinationLock(m_socketOptionsMutex);
      m_socketOptions = other.m_socketOptions;
    }
    {
      std::scoped_lock lock(m_onClientDisconnectMutex, other.m_onClientDisconnectMutex);
      m_onClientDisconnect = std::move(other.m_onClientDisconnect);
      other.m_onClientDisconnect = nullptr;
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

  void TCPServerSocket::SetOnClientDisconnect(std::function<void(const std::string& address)> onClientDisconnect) {
    std::unique_lock lock(m_onClientDisconnectMutex);
    m_onClientDisconnect = std::move(onClientDisconnect);
  }

  void TCPServerSocket::SetOnRead(std::function<void(unsigned char* message, size_t byteCount, SOCKET sender)> onRead) {
    std::unique_lock lock(m_onReadMutex);
    m_onRead = std::move(onRead);
  }

  int TCPServerSocket::GetMaxLength() const noexcept {
    return m_maxLength.load(std::memory_order_acquire);
  }

  bool TCPServerSocket::SetMaxLength(int maxLength) {
    if(maxLength > 0) {
      m_maxLength.store(maxLength, std::memory_order_release);
      return true;
    }
    ErrorInterpreter("Error: max length attempt '" + std::to_string(maxLength) + "' is not valid (must be a number > 0)", false);
    return false;
  }

  bool TCPServerSocket::SetMaxLength(const std::string& maxLength) {
    int maxLengthAttempt = 0;
    if(!StringToInt(maxLength, maxLengthAttempt)) {
      ErrorInterpreter("Error parsing max length value from '" + maxLength + "'", false);
      return false;
    }
    return SetMaxLength(maxLengthAttempt);
  }

  int TCPServerSocket::GetListenBacklog() const noexcept {
    return m_listenBacklog.load(std::memory_order_relaxed);
  }

  bool TCPServerSocket::SetListenBacklog(int listenBacklog) {
    if(listenBacklog > 0) {
      m_listenBacklog.store(listenBacklog, std::memory_order_relaxed);
      UpdateInterpreter("Successfully set listen backlog: " + std::to_string(listenBacklog));
      return true;
    }
    ErrorInterpreter("Error: listen backlog attempt '" + std::to_string(listenBacklog) + "' is not valid (must be a number > 0)", false);
    return false;
  }

  bool TCPServerSocket::SetListenBacklog(const std::string& listenBacklog) {
    int listenBuffAttempt = 0;
    if(!StringToInt(listenBacklog, listenBuffAttempt)) {
      ErrorInterpreter("Error parsing listen backlog value from '" + listenBacklog + "'", false);
      return false;
    }
    return SetListenBacklog(listenBuffAttempt);
  }

  int TCPServerSocket::GetMaxConnections() const noexcept {
    return m_maxConnections.load(std::memory_order_relaxed);
  }

  bool TCPServerSocket::SetMaxConnections(int maxConnections) {
    if(maxConnections > 0) {
      m_maxConnections.store(maxConnections, std::memory_order_relaxed);
      UpdateInterpreter("Successfully set max connections: " + std::to_string(maxConnections));
      return true;
    }
    ErrorInterpreter("Error: max connections attempt '" + std::to_string(maxConnections) + "' is not valid (must be a number > 0)", false);
    return false;
  }

  bool TCPServerSocket::SetMaxConnections(const std::string& maxConnections) {
    int maxConnAttempt = 0;
    if(!StringToInt(maxConnections, maxConnAttempt)) {
      ErrorInterpreter("Error parsing max connections value from '" + maxConnections + "'", false);
      return false;

    }
    return SetMaxConnections(maxConnAttempt);
  }

  size_t TCPServerSocket::GetNumConnections() const noexcept {
    return m_connections.Count();
  }

  bool TCPServerSocket::Open() {
    return Socket::Open();
  }

  bool TCPServerSocket::Close() {
    return Socket::Close();
  }

  std::vector<std::string> TCPServerSocket::GetClientAddresses() const {
    std::vector<std::string> addresses;
    m_connections.Snapshot(addresses);
    return addresses;
  }

  void TCPServerSocket::SetNoDelay(bool enabled, bool applyToAll) noexcept {
    {
      std::unique_lock lock(m_socketOptionsMutex);
      m_socketOptions.noDelay = enabled;
    }
    if(!applyToAll) {
      return;
    }
    std::vector<SOCKET> connections;
    m_connections.Snapshot(connections);
    for(SOCKET client : connections) {
      ApplySocketOptions(client);
    }
  }

  void TCPServerSocket::SetKeepAlive(bool enabled, DWORD timeMs, DWORD intervalMs, bool applyToAll) noexcept {
    {
      std::unique_lock lock(m_socketOptionsMutex);
      m_socketOptions.keepAlive = enabled;
      m_socketOptions.keepAliveTimeMs = timeMs;
      m_socketOptions.keepAliveIntervalMs = intervalMs;
    }
    if(!applyToAll) {
      return;
    }
    std::vector<SOCKET> connections;
    m_connections.Snapshot(connections);
    for(SOCKET client : connections) {
      ApplySocketOptions(client);
    }
  }

  bool TCPServerSocket::Startup() {
    //1) Create the TCP socket
    if(!Initialize(Protocol::TCP)) {
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
      SO_EXCLUSIVEADDRUSE,
      reinterpret_cast<const char*>(&option),
      sizeof(option)
    ) == SOCKET_ERROR) {
      ErrorInterpreter("Error setting exclusive address: ", true);
      return false;
    }
    //3) Build bind address and bind the socket
    UpdateInterpreter("Binding socket");
    sockaddr_in bindAddress{};
    int bindLength = sizeof(bindAddress);
    if(!GetServiceAddress(Protocol::TCP, bindAddress)) {
      ErrorInterpreter("Invalid server IP/Port", false);
      return false;
    }
    if(::bind(thisSocket, reinterpret_cast<const sockaddr*>(&bindAddress), bindLength) == SOCKET_ERROR) {
      ErrorInterpreter("Socket binding error: ", true);
      return false;
    }
    UpdateInterpreter("Binding successful!");
    //4) Listen on bound socket
    UpdateInterpreter("Preparing to listen for connections");
    int listenBacklog = m_listenBacklog.load(std::memory_order_relaxed);
    listenBacklog = (listenBacklog > SOMAXCONN) ? SOMAXCONN : (listenBacklog < 0 ? 1 : listenBacklog);
    if(::listen(thisSocket, listenBacklog) == SOCKET_ERROR) {
      ErrorInterpreter("Error listening on socket: ", true);
      return false;
    }
    SetConfigured(true);
    UpdateInterpreter("Ready to listen for connections");
    if(!StartWorker(&TCPServerSocket::StaticAcceptConnection, this)) {
      ErrorInterpreter("Thread creation error: ", true);
      return false;
    }
    return true;
  }

  bool TCPServerSocket::Cleanup() {
    UpdateInterpreter("Closing all connected client sockets");
    std::vector<SOCKET> connections;
    m_connections.Snapshot(connections);
    m_connections.Clear();
    for(SOCKET socket : connections) {
      if(socket != INVALID_SOCKET && !CloseSocketSafe(socket, true)) {
        ErrorInterpreter("Error closing client socket", false);
      }
    }
    return true;
  }

  bool TCPServerSocket::ReadyToAccept() const noexcept {
    const bool configured = GetConfigured();
    const bool wsaRegistered = GetRegistered();
    const bool closing = IsClosing();
    SOCKET thisSocket = GetSocket();
    return configured && wsaRegistered && !closing && thisSocket != INVALID_SOCKET;
  }

  unsigned __stdcall TCPServerSocket::StaticAcceptConnection(void* arg) noexcept {
    auto* serverSocket = static_cast<TCPServerSocket*>(arg);
    if(serverSocket) {
      serverSocket->AcceptConnection();
    }
    return 0;
  }

  void TCPServerSocket::AcceptConnection() {
    if(!SetState(State::Active)) {
      Close();
      return;
    }
    UpdateInterpreter("Accepting socket connections");
    if(!ReadyToAccept()) {
      ErrorInterpreter("Server socket not initialized", false);
      return;
    }
    SOCKET thisSocket = INVALID_SOCKET;
    while(ReadyToAccept() && !StopRequested()) {
      thisSocket = GetSocket();
      SOCKET acceptSocket = accept(thisSocket, nullptr, nullptr);
      if(acceptSocket == INVALID_SOCKET) {
        if(!IsActive() || StopRequested()) {
          return;
        }
        ErrorInterpreter("Error accepting connection: ", true);
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
        continue;
      }
      RegisterClient(acceptSocket);
    }
    if(IsActive()) {
      ErrorInterpreter("Error accepting connections: server socket not initialized", false);
    }
  }

  void TCPServerSocket::RegisterClient(SOCKET client) {
    if(!ApplySocketOptions(client)) {
      UpdateInterpreter("Failed to apply socket options");
    }
    bool reject = false;
    bool duplicate = false;
    int maxConnections = 0;
    std::string clientAddress = GetPeerAddress(client);
    maxConnections = m_maxConnections.load(std::memory_order_relaxed);
    ConnectionManager::AddResult addResult = m_connections.AddConnection(client, clientAddress, static_cast<size_t>(maxConnections));
    std::string message{};
    switch(addResult.code) {
      case ConnectionManager::AddResult::Code::Invalid:
        message = "Invalid client credentials - rejecting new client";
        break;
      case ConnectionManager::AddResult::Code::Exists:
        message = "Duplicate client detected - rejecting new client";
        break;
      case ConnectionManager::AddResult::Code::Full:
        message = "Reached max concurrent connections (" + std::to_string(addResult.count) + "/" + std::to_string(maxConnections) + ") - rejecting new client";
        break;
      case ConnectionManager::AddResult::Code::Added:
        message = "Accepted connection (" + std::to_string(addResult.count) + "/" + std::to_string(maxConnections) + "): " + clientAddress;
        break;
      default:
        message = "Unknown client error - rejecting new client";
        break;
    }
    UpdateInterpreter(message);
    if(addResult.code == ConnectionManager::AddResult::Code::Added) {
      auto params = std::make_unique<MessageHandlerParams>(MessageHandlerParams{this, client});
      if(!StartWorker(&TCPServerSocket::StaticMessageHandler, params.get())) {
        ErrorInterpreter("Thread creation error: ", true);
        m_connections.RemoveConnection(client);
        CloseSocketSafe(client, true);
        return;
      }
      params.release();
    } else {
      CloseSocketSafe(client, true);
    }
  }

  bool TCPServerSocket::ApplySocketOptions(SOCKET socket) noexcept {
    bool success = true;
    SocketOptions socketOptions;
    {
      std::shared_lock lock(m_socketOptionsMutex);
      socketOptions = m_socketOptions;
    }
    // TCP_NODELAY
    {
      const int flag = socketOptions.noDelay ? 1 : 0;
      if(setsockopt(
        socket,
        IPPROTO_TCP,
        TCP_NODELAY,
        reinterpret_cast<const char*>(&flag),
        sizeof(flag)
      ) == SOCKET_ERROR) {
        ErrorInterpreter("Failed to set TCP_NODELAY on client socket: ", true);
        success = false;
      }
    }
    // SO_KEEPALIVE
    {
      const int flag = socketOptions.keepAlive ? 1 : 0;
      if(setsockopt(
        socket,
        SOL_SOCKET,
        SO_KEEPALIVE,
        reinterpret_cast<const char*>(&flag),
        sizeof(flag)
      ) == SOCKET_ERROR) {
        ErrorInterpreter("Failed to set SO_KEEPALIVE on client socket: ", true);
        success = false;
      } else if(socketOptions.keepAlive) {
        tcp_keepalive keepAliveSettings{};
        keepAliveSettings.onoff = 1;
        keepAliveSettings.keepalivetime = socketOptions.keepAliveTimeMs;
        keepAliveSettings.keepaliveinterval = socketOptions.keepAliveIntervalMs;
        DWORD bytes = 0;
        if(WSAIoctl(
          socket,
          SIO_KEEPALIVE_VALS,
          &keepAliveSettings,
          sizeof(keepAliveSettings),
          nullptr,
          0,
          &bytes,
          nullptr,
          nullptr
        ) == SOCKET_ERROR) {
          ErrorInterpreter("Failed to tune keepalive on client socket: ", true);
          success = false;
        }
      }
    }
    return success;
  }

  unsigned __stdcall TCPServerSocket::StaticMessageHandler(void* arg) noexcept {
    std::unique_ptr<MessageHandlerParams> params(static_cast<MessageHandlerParams*>(arg));
    TCPServerSocket* serverSocket = params->serverSocket;
    SOCKET clientSocket = params->clientSocket;
    serverSocket->MessageHandler(clientSocket);
    return 0;
  }

  void TCPServerSocket::MessageHandler(SOCKET clientSocket) {
    std::vector<unsigned char> buffer;
    std::string clientAddress = GetPeerAddress(clientSocket);
    while(!StopRequested()) {
      int maxLength = GetMaxLength();
      maxLength = maxLength <= 0 ? 64 * 1024 : maxLength;
      maxLength = maxLength > INT_MAX ? INT_MAX : maxLength;
      if(buffer.size() < static_cast<size_t>(maxLength)) {
        buffer.resize(static_cast<size_t>(maxLength));
      }
      const int byteCount = ::recv(clientSocket, reinterpret_cast<char*>(buffer.data()), maxLength, 0);
      if(byteCount > 0) {
        TrafficUpdate("Received " + std::to_string(byteCount) + " bytes from " + clientAddress);
        OnRead(buffer.data(), static_cast<size_t>(byteCount), clientSocket);
        continue;
      }
      if(byteCount == 0) {
        UpdateInterpreter("Connection closed by client");
        break;
      }
      const int error = ::WSAGetLastError();
      if(error == WSAEINTR || error == WSAEWOULDBLOCK || error == WSAETIMEDOUT) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        continue;
      }
      ErrorInterpreter("Socket Error: ", true);
      break;
    }
    UpdateInterpreter("Disconnected client detected");
    if(CloseClientSocket(clientSocket)) {
      UpdateInterpreter("Closed disconnected client socket");
    } else {
      UpdateInterpreter("Failed to close disconnected client socket");
    }
    OnClientDisconnect(clientAddress);
  }

  void TCPServerSocket::Broadcast(const void* bytes, size_t byteCount) {
    if(!bytes || byteCount == 0) {
      ErrorInterpreter("Broadcast error: invalid buffer/length", false);
      return;
    }
    std::vector<SOCKET> connections;
    m_connections.Snapshot(connections);
    if(connections.empty()) {
      ErrorInterpreter("Broadcast error: no connections to broadcast over", false);
      return;
    }
    if(byteCount > static_cast<size_t>(std::numeric_limits<int>::max())) {
      ErrorInterpreter("Broadcast error: payload too large for WinSock", false);
      return;
    }
    TrafficUpdate("Broadcasting message: " + std::to_string(byteCount) + " bytes");
    size_t failCount = 0;
    size_t successCount = 0;
    for(size_t i = 0; i < connections.size(); ++i) {
      SOCKET client = connections[i];
      const int totalBytes = static_cast<int>(byteCount);
      UpdateInterpreter("Sending to client #" + std::to_string(i + 1));
      const int sentBytes = Send(bytes, byteCount, client);
      if(sentBytes != totalBytes) {
        ++failCount;
        continue;
      }
      ++successCount;
    }
    TrafficUpdate("# Failed Broadcasts: " + std::to_string(failCount));
    TrafficUpdate("# Successful Broadcasts: " + std::to_string(successCount));
    if(failCount + successCount != connections.size()) {
      TrafficUpdate("Mismatch: fails + successes != connection count");
    }
  }

  int TCPServerSocket::Send(const void* bytes, size_t byteCount, const std::string& targetIP, const std::string& targetPort) {
    return Send(bytes, byteCount, ConstructAddress(targetIP, targetPort));
  }

  int TCPServerSocket::Send(const void* bytes, size_t byteCount, const std::string& targetIP, int targetPort) {
    return Send(bytes, byteCount, ConstructAddress(targetIP, targetPort));
  }

  int TCPServerSocket::Send(const void* bytes, size_t byteCount, const std::string& targetAddress) {
    if(targetAddress.empty()) {
      ErrorInterpreter("Send error: invalid target address", false);
      return 0;
    }
    SOCKET target = INVALID_SOCKET;
    target = m_connections.FindSocket(targetAddress);
    if(target == INVALID_SOCKET) {
      ErrorInterpreter("Send error: unable to find connected client with address '" + targetAddress + "'", false);
      return 0;
    }
    return Send(bytes, byteCount, target);
  }

  int TCPServerSocket::Send(const void* bytes, size_t byteCount) {
    SOCKET target = INVALID_SOCKET;
    if(m_connections.Count() == 1) {
      std::vector<SOCKET> connection;
      m_connections.Snapshot(connection);
      if(!connection.empty()) {
        target = connection.front();
      }
    }
    if(target == INVALID_SOCKET) {
      ErrorInterpreter("Send error: requires only one connected client", false);
      return 0;
    }
    return Send(bytes, byteCount, target);
  }

  int TCPServerSocket::Send(const void* bytes, size_t byteCount, SOCKET target) {
    if(!bytes || byteCount == 0) {
      ErrorInterpreter("Send error: invalid buffer/length", false);
      return 0;
    }
    if(byteCount > static_cast<size_t>(std::numeric_limits<int>::max())) {
      ErrorInterpreter("Send error: payload too large for WinSock", false);
      return 0;
    }
    std::string targetAddress = GetPeerAddress(target);
    TrafficUpdate("Sending message to " + targetAddress + " - " + std::to_string(byteCount) + " bytes");
    const int totalBytes = static_cast<int>(byteCount);
    const int sentBytes = SendAll(target, static_cast<const char*>(bytes), totalBytes);
    if(sentBytes != totalBytes) {
      ErrorInterpreter("Error sending message to " + targetAddress + ": ", true);
      CloseClientSocket(target);
    } else {
      TrafficUpdate("Successfully sent message");
    }
    return sentBytes;
  }

  int TCPServerSocket::SendAll(SOCKET socket, const char* buffer, int bufferSize) {
    int totalSent = 0;
    while(totalSent < bufferSize) {
      const int sentBytes = ::send(socket, buffer + totalSent, bufferSize - totalSent, 0);
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

  bool TCPServerSocket::CloseClientSocket(SOCKET clientSocket) {
    bool found = false;
    found = m_connections.RemoveConnection(clientSocket);
    if(found) {
      UpdateInterpreter("Found client socket in connections list");
    }
    if(!CloseSocketSafe(clientSocket, true)) {
      ErrorInterpreter("Unable to close client socket", false);
      return false;
    }
    return true;
  }

  void TCPServerSocket::OnClientDisconnect(const std::string& address) {
    std::function<void(const std::string& address)> callback;
    {
      std::shared_lock lock(m_onClientDisconnectMutex);
      callback = m_onClientDisconnect;
    }
    if(!callback) {
      UpdateInterpreter("Client disconnected");
      return;
    }
    try {
      callback(address);
    } catch(const std::exception& e) {
      ErrorInterpreter(std::string("OnClientDisconnect callback exception: ") + e.what(), false);
    } catch(...) {
      ErrorInterpreter("OnClientDisconnect callback exception: unknown", false);
    }
  }

  void TCPServerSocket::OnRead(unsigned char* message, size_t byteCount, SOCKET sender) {
    std::function<void(unsigned char* message, size_t byteCount, SOCKET sender)> callback;
    {
      std::shared_lock lock(m_onReadMutex);
      callback = m_onRead;
    }
    if(!callback) {
      std::string update = "Received message";
      if(sender != INVALID_SOCKET) {
        update += " from " + GetPeerAddress(sender);
      }
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
