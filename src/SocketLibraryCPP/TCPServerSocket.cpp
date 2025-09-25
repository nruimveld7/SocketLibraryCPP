#include "pch.h"
#include "SocketLibrary/TCPServerSocket.h"

TCPServerSocket::TCPServerSocket() {
	{
		std::unique_lock lock(m_onClientDisconnectMutex);
		m_onClientDisconnect = nullptr;
	}
	{
		std::unique_lock lock(m_onReadMutex);
		m_onRead = nullptr;
	}
	m_listenBacklog.store(1, std::memory_order_relaxed);
	m_maxConnections.store(2, std::memory_order_relaxed);
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

void TCPServerSocket::SetOnClientDisconnect(std::function<void()> onClientDisconnect) {
	std::unique_lock lock(m_onClientDisconnectMutex);
	m_onClientDisconnect = std::move(onClientDisconnect);
}

void TCPServerSocket::SetOnRead(std::function<void(unsigned char* message, int byteCount, SOCKET sender)> onRead) {
	std::unique_lock lock(m_onReadMutex);
	m_onRead = std::move(onRead);
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
	if(!StringToInt(listenBacklog, &listenBuffAttempt)) {
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
    UpdateConnectionBuckets(static_cast<size_t>(maxConnections));
		UpdateInterpreter("Successfully set max connections: " + std::to_string(maxConnections));
		return true;
	}
	ErrorInterpreter("Error: max connections attempt '" + std::to_string(maxConnections) + "' is not valid (must be a number > 0)", false);
	return false;
}

bool TCPServerSocket::SetMaxConnections(const std::string& maxConnections) {
	int maxConnAttempt = 0;
	if(!StringToInt(maxConnections, &maxConnAttempt)) {
		ErrorInterpreter("Error parsing max connections value from '" + maxConnections + "'", false);
		return false;

	}
	return SetMaxConnections(maxConnAttempt);
}

size_t TCPServerSocket::GetNumConnections() const noexcept {
  std::shared_lock lock(m_connectionsMutex);
  return m_connections.size();
}

bool TCPServerSocket::Open() {
	if(!Initialize(SOCK_STREAM)) {
		ErrorInterpreter("Error initializing socket", false);
		return false;
	}
  int option = 1;
  if(setsockopt(
    m_thisSocket,
    SOL_SOCKET,
    SO_EXCLUSIVEADDRUSE,
    reinterpret_cast<const char*>(&option),
    sizeof(option)
  )) {
    ErrorInterpreter("Error setting exclusive address: ", true);
    UnregisterWSA();
    return false;
  }
	UpdateInterpreter("Binding socket");
	if(::bind(m_thisSocket, (SOCKADDR*)&m_service, sizeof(m_service)) == SOCKET_ERROR) {
		ErrorInterpreter("Socket binding error: ", true);
		UnregisterWSA();
		return false;
	}
	UpdateInterpreter("Binding successful!");
	UpdateInterpreter("Preparing to listen for connections");
  int listenBacklog = m_listenBacklog.load(std::memory_order_relaxed);
  if(::listen(m_thisSocket, (listenBacklog > SOMAXCONN ? SOMAXCONN : listenBacklog)) == SOCKET_ERROR) {
		ErrorInterpreter("Error listening on socket: ", true);
		UnregisterWSA();
		return false;
	}
  SetConfigured(true);
  SetClosing(false);
	UpdateInterpreter("Ready to listen for connections");
  if(!StartWorker(&TCPServerSocket::StaticAcceptConnection, this)) {
    ErrorInterpreter("Thread creation error: ", true);
    UnregisterWSA();
    return false;
  }
  return true;
}

bool TCPServerSocket::Close() {
  return Socket::Close();
}

std::vector<std::string> TCPServerSocket::GetClientAddresses() const {
  std::vector<std::string> addresses;
  {
    std::shared_lock lock(m_connectionsMutex);
    addresses.reserve(m_socketToAddress.size());
    for(const auto& [socket, address] : m_socketToAddress) {
      addresses.push_back(address);
    }
  }
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
  {
    std::shared_lock lock(m_connectionsMutex);
    connections.assign(m_connections.begin(), m_connections.end());
  }
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
  {
    std::shared_lock lock(m_connectionsMutex);
    connections.assign(m_connections.begin(), m_connections.end());
  }
  for(SOCKET client : connections) {
    ApplySocketOptions(client);
  }
}

bool TCPServerSocket::ReadyToAccept() const noexcept {
  const bool configured = IsConfigured();
  const bool wsaRegistered = IsRegistered();
  return configured && wsaRegistered && m_thisSocket != INVALID_SOCKET;
}

unsigned __stdcall TCPServerSocket::StaticAcceptConnection(void* arg) noexcept {
  auto* serverSocket = static_cast<TCPServerSocket*>(arg);
  if(serverSocket) {
    serverSocket->AcceptConnection();
  }
  return 0;
}

void TCPServerSocket::AcceptConnection() {
  SetActive(true);
	UpdateInterpreter("Accepting socket connections");
  if(!ReadyToAccept()) {
		ErrorInterpreter("Server socket not initialized", false);
		return;
	}
  while(ReadyToAccept() && !StopRequested()) {
    SOCKET acceptSocket = accept(m_thisSocket, nullptr, nullptr);
    if(acceptSocket == INVALID_SOCKET) {
      if(IsClosing() || !IsActive() || StopRequested()) {
        return;
      }
      ErrorInterpreter("Error accepting connection: ", true);
      continue;
    }
    RegisterClient(acceptSocket);
	}
  if(IsActive() && !IsClosing()) {
    ErrorInterpreter("Error accepting connections: server socket not initialized", false);
  }
}

void TCPServerSocket::RegisterClient(SOCKET client) {
  if(!ApplySocketOptions(client)) {
    UpdateInterpreter("Failed to apply socket options - rejecting client");
    CloseSocketSafe(client, true);
    return;
  }
  size_t connectionCount = 0;
  bool reject = false;
  bool duplicate = false;
  int maxConnections = 0;
  std::string clientAddress;
  {
    std::unique_lock lock(m_connectionsMutex);
    maxConnections = m_maxConnections.load(std::memory_order_relaxed);
    if(m_connections.size() >= static_cast<size_t>(maxConnections)) {
      reject = true;
    } else {
      auto [it, inserted] = m_connections.insert(client);
      if(!inserted) {
        duplicate = true;
      } else {
        clientAddress = GetSocketAddress(client);
        if(!clientAddress.empty()) {
          m_addressToSocket[clientAddress] = client;
          m_socketToAddress[client] = clientAddress;
        }
        connectionCount = m_connections.size();
      }
    }
  }
  if(reject || duplicate) {
    if(reject) {
      UpdateInterpreter("Reached max concurrent connections - rejecting new client");
    }
    if(duplicate) {
      UpdateInterpreter("Duplicate client socket detected - rejecting new client");
    }
    CloseSocketSafe(client, true);
    return;
  }
	std::string msg = "Accepted connection (" + std::to_string(connectionCount) + " of " + std::to_string(maxConnections) + "): ";
	if(clientAddress.empty()) {
		msg += "Unknown address";
	} else {
		msg += clientAddress;
	}
	UpdateInterpreter(msg);
  auto params = std::make_unique<MessageHandlerParams>(MessageHandlerParams{this, client});
  if(!StartWorker(&TCPServerSocket::StaticMessageHandler, params.get())) {
    ErrorInterpreter("Thread creation error: ", true);
    {
      std::unique_lock lock(m_connectionsMutex);
      m_connections.erase(client);
    }
    CloseSocketSafe(client, true);
    return;
  }
  params.release();
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

void TCPServerSocket::UpdateConnectionBuckets(size_t desiredSize) {
  try {
    std::unique_lock lock(m_connectionsMutex);
    const size_t actualSize = m_connections.size();
    if(desiredSize > actualSize) {
      m_connections.reserve(desiredSize);
      m_addressToSocket.reserve(desiredSize);
      m_socketToAddress.reserve(desiredSize);
    }
    if(actualSize == 0) {
      m_connections.rehash(0);
      m_addressToSocket.rehash(0);
      m_socketToAddress.rehash(0);
      return;
    }
    const double maxLoadFactor = static_cast<double>(m_connections.max_load_factor());
    const size_t minBuckets = static_cast<size_t>(std::ceil(static_cast<double>(actualSize) / maxLoadFactor));
    constexpr size_t maxBuckets = std::numeric_limits<size_t>::max();
    const size_t shrinkTrigger = (minBuckets > (maxBuckets >> 1) ? maxBuckets : (minBuckets << 1));
    if(m_connections.bucket_count() > shrinkTrigger) {
      m_connections.rehash(minBuckets);
      m_addressToSocket.rehash(minBuckets);
      m_socketToAddress.rehash(minBuckets);
    }
  } catch(const std::bad_alloc&) {
    ErrorInterpreter("UpdateConnectionBuckets: memory allocation failure", false);
  } catch(...) {
    ErrorInterpreter("UpdateConnectionBuckets: unknown error", false);
  }
}

unsigned __stdcall TCPServerSocket::StaticMessageHandler(void* arg) noexcept {
  std::unique_ptr<MessageHandlerParams> params(static_cast<MessageHandlerParams*>(arg));
  TCPServerSocket* serverSocket = params->serverSocket;
  SOCKET clientSocket = params->clientSocket;
  serverSocket->MessageHandler(clientSocket);
  return 0;
}

void TCPServerSocket::MessageHandler(SOCKET clientSocket) {
  int lastMessageLength = -1;
  std::vector<unsigned char> buffer;
	while(!StopRequested()) {
    int messageLength = GetMessageLength();
    if(messageLength <= 0) {
      ErrorInterpreter("Invalid message length: " + std::to_string(messageLength), false);
      break;
    }
    if(messageLength != lastMessageLength) {
      buffer.resize(messageLength);
      lastMessageLength = messageLength;
    }
		const int byteCount = ::recv(clientSocket, reinterpret_cast<char*>(buffer.data()), messageLength, 0);
		if(byteCount > 0) {
			UpdateInterpreter("Received " + std::to_string(byteCount) + " bytes");
			OnRead(buffer.data(), byteCount, clientSocket);
      continue;
    }
    if(byteCount == 0) {
      UpdateInterpreter("Connection closed by client");
    } else {
      ErrorInterpreter("Error checking connection: ", true);
    }
    UpdateInterpreter("Disconnected client detected");
    if(CloseClientSocket(clientSocket)) {
      UpdateInterpreter("Closed disconnected client socket");
    } else {
      UpdateInterpreter("Failed to close disconnected client socket");
    }
    OnClientDisconnect();
    break;
  }
}

void TCPServerSocket::Broadcast(const void* bytes, size_t byteCount) {
  if(!bytes || byteCount == 0) {
    ErrorInterpreter("Broadcast error: invalid buffer/length", false);
    return;
  }
  std::vector<SOCKET> connections;
  {
    std::shared_lock lock(m_connectionsMutex);
    connections.assign(m_connections.begin(), m_connections.end());
  }
  if(connections.empty()) {
    ErrorInterpreter("Broadcast error: no connections to broadcast over", false);
    return;
  }
  if(byteCount > static_cast<size_t>(std::numeric_limits<int>::max())) {
    ErrorInterpreter("Broadcast error: payload too large for WinSock", false);
    return;
  }
  UpdateInterpreter("Broadcasting message: " + std::to_string(byteCount) + " bytes");
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
  UpdateInterpreter("# Failed Broadcasts: " + std::to_string(failCount));
  UpdateInterpreter("# Successful Broadcasts: " + std::to_string(successCount));
  if(failCount + successCount != connections.size()) {
    ErrorInterpreter("Mismatch: fails + successes != connection count", false);
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
  {
    std::shared_lock lock(m_connectionsMutex);
    auto it = m_addressToSocket.find(targetAddress);
    if(it != m_addressToSocket.end()) {
      target = it->second;
    }
  }
  if(target == INVALID_SOCKET) {
    ErrorInterpreter("Send error: unable to find connected client with address '" + targetAddress + "'", false);
    return 0;
  }
  return Send(bytes, byteCount, target);
}

int TCPServerSocket::Send(const void* bytes, size_t byteCount) {
  SOCKET target = INVALID_SOCKET;
  {
    std::shared_lock lock(m_connectionsMutex);
    if(m_connections.size() == 1) {
      target = *m_connections.begin();
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
  UpdateInterpreter("Sending message to " + GetSocketAddress(target) + " - " + std::to_string(byteCount) + " bytes");
  const int totalBytes = static_cast<int>(byteCount);
  const int sentBytes = SendAll(target, static_cast<const char*>(bytes), totalBytes);
  if(sentBytes != totalBytes) {
    ErrorInterpreter("Error sending message: ", true);
    CloseClientSocket(target);
  } else {
    UpdateInterpreter("Successfully sent message");
  }
  return sentBytes;
}

int TCPServerSocket::SendAll(SOCKET socket, const char* buffer, int bufferSize) {
  int totalSent = 0;
  while(totalSent < bufferSize) {
    const int sentBytes = ::send(socket, buffer + totalSent, bufferSize - totalSent, 0);
    if(sentBytes == SOCKET_ERROR) {
      const int err = WSAGetLastError();
      if(err == WSAEINTR) {
        //Brief backoff
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
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

bool TCPServerSocket::Cleanup() {
  UpdateInterpreter("Closing server socket");
  const bool socketClosed = CloseSocketSafe(m_thisSocket, false);
  UpdateInterpreter("Closing all connected client sockets");
  std::vector<SOCKET> connections;
  {
    std::unique_lock lock(m_connectionsMutex);
    connections.reserve(m_connections.size());
    connections.assign(m_connections.begin(), m_connections.end());
    m_connections.clear();
    m_addressToSocket.clear();
    m_socketToAddress.clear();
    m_connections.rehash(0);
    m_addressToSocket.rehash(0);
    m_socketToAddress.rehash(0);
  }
  for(SOCKET socket : connections) {
    if(socket != INVALID_SOCKET && !CloseSocketSafe(socket, true)) {
      ErrorInterpreter("Error closing client socket", false);
    }
  }
  return socketClosed;
}

bool TCPServerSocket::CloseClientSocket(SOCKET clientSocket) {
  bool found = false;
  std::string address;
  {
    std::unique_lock lock(m_connectionsMutex);
    auto itConnection = m_connections.find(clientSocket);
    if(itConnection == m_connections.end()) {
      //Already removed; idempotent success
      return true;
    }
    found = true;
    m_connections.erase(itConnection);
    if(auto itAddress = m_socketToAddress.find(clientSocket); itAddress != m_socketToAddress.end()) {
      address = std::move(itAddress->second);
      if(!address.empty()) {
        m_addressToSocket.erase(address);
      }
    }
  }
  if(found) {
    UpdateInterpreter("Found client socket in connections list");
  }
  if(!CloseSocketSafe(clientSocket, true)) {
    ErrorInterpreter("Unable to close client socket", false);
    return false;
  }
  return true;
}

void TCPServerSocket::OnClientDisconnect() {
  std::function<void()> callback;
  {
    std::shared_lock lock(m_onClientDisconnectMutex);
    callback = m_onClientDisconnect;
  }
  if(!callback) {
    UpdateInterpreter("Client disconnected");
    return;
  }
  try {
    callback();
  } catch(const std::exception& e) {
    ErrorInterpreter(std::string("OnClientDisconnect callback exception: ") + e.what(), false);
  } catch(...) {
    ErrorInterpreter("OnClientDisconnect callback exception: unknown", false);
  }
}

void TCPServerSocket::OnRead(unsigned char* message, int byteCount, SOCKET sender) {
  std::function<void(unsigned char* message, int byteCount, SOCKET sender)> callback;
  {
    std::shared_lock lock(m_onReadMutex);
    callback = m_onRead;
  }
  if(!callback) {
    std::string update = "Received message";
    if(sender != INVALID_SOCKET) {
      update += " from " + GetSocketAddress(sender);
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
