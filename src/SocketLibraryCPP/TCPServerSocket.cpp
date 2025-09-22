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

TCPServerSocket::~TCPServerSocket() {
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

int TCPServerSocket::GetListenBacklog() const {
	return m_listenBacklog.load(std::memory_order_relaxed);
}

bool TCPServerSocket::SetListenBacklog(int listenBacklog) {
	if(listenBacklog > 0) {
		m_listenBacklog.store(listenBacklog, std::memory_order_relaxed);
		UpdateInterpreter("Successfully Set Listen Backlog: " + std::to_string(listenBacklog));
		return true;
	}
	ErrorInterpreter("Error: Listen Backlog Attempt '" + std::to_string(listenBacklog) + "' Is Not Valid (Must Be A Number > 0)", false);
	return false;
}

bool TCPServerSocket::SetListenBacklog(const std::string& listenBacklog) {
	int listenBuffAttempt = 0;
	if(!StringToInt(listenBacklog, &listenBuffAttempt)) {
		ErrorInterpreter("Error Parsing Listen Backlog Value From '" + listenBacklog + "'", false);
		return false;
	}
	return SetListenBacklog(listenBuffAttempt);
}

int TCPServerSocket::GetMaxConnections() const {
	return m_maxConnections.load(std::memory_order_relaxed);
}

bool TCPServerSocket::SetMaxConnections(int maxConnections) {
	if(maxConnections > 0) {
		m_maxConnections.store(maxConnections, std::memory_order_relaxed);
		UpdateInterpreter("Successfully set max connections: " + std::to_string(maxConnections));
    {
      std::unique_lock lock(m_connectionsMutex);
      const size_t actualSize = m_connections.size();
      const size_t desiredSize = static_cast<size_t>(maxConnections);
      if(desiredSize > actualSize) {
        m_connections.reserve(desiredSize);
      }
      const size_t minBuckets = static_cast<size_t>(std::ceil(actualSize / m_connections.max_load_factor()));
      if(m_connections.bucket_count() > minBuckets * 2) {
        m_connections.rehash(minBuckets);
      }
    }
		return true;
	}
	ErrorInterpreter("Error: Max connections attempt '" + std::to_string(maxConnections) + "' is not valid (must be a number > 0)", false);
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

size_t TCPServerSocket::GetNumConnections() const {
  std::shared_lock lock(m_connectionsMutex);
  return m_connections.size();
}

bool TCPServerSocket::Open() {
	try {
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
		if(bind(m_thisSocket, (SOCKADDR*)&m_service, sizeof(m_service)) == SOCKET_ERROR) {
			ErrorInterpreter("Socket binding error: ", true);
			UnregisterWSA();
			return false;
		}
		UpdateInterpreter("Binding successful!");
		UpdateInterpreter("Preparing to listen for connections");
    int listenBacklog = m_listenBacklog.load(std::memory_order_relaxed);
    if(listen(m_thisSocket, (listenBacklog > SOMAXCONN ? SOMAXCONN : listenBacklog)) == SOCKET_ERROR) {
			ErrorInterpreter("Error listening on socket: ", true);
			UnregisterWSA();
			return false;
		}
		m_configured.store(true, std::memory_order_release);
		m_closeAttempt.store(false, std::memory_order_release);
		UpdateInterpreter("Ready to listen for connections");
    uintptr_t threadPtr = _beginthreadex(nullptr, 0, &TCPServerSocket::StaticAcceptConnection, this, 0, nullptr);
    HANDLE threadHandle = reinterpret_cast<HANDLE>(threadPtr);
		if(threadHandle == nullptr) {
			ErrorInterpreter("Thread creation error: ", true);
			UnregisterWSA();
			return false;
		}
		CloseHandle(threadHandle);
		return true;
	} catch(const std::exception& e) {
		std::string error = e.what();
		ErrorInterpreter("Open error: " + error, false);
		throw;
	} catch(...) {
		ErrorInterpreter("Open: Unknown error", false);
		throw;
	}
	return false;
}

bool TCPServerSocket::Close() {
  m_active.store(false, std::memory_order_release);
  m_closeAttempt.store(true, std::memory_order_release);
  UpdateInterpreter("Closing server socket");
  if(!CloseSocketSafe(m_thisSocket, false)) {
    UpdateInterpreter("Error closing server socket");
  } else {
    UpdateInterpreter("Server socket closed");
  }
  UpdateInterpreter("Closing all connected client sockets");
  bool success = true;
  while(true) {
    SOCKET closeSocket = INVALID_SOCKET;
    {
      std::unique_lock lock(m_connectionsMutex);
      if(m_connections.empty()) {
        break;
      }
      auto it = m_connections.begin();
      closeSocket = (it != m_connections.end() ? *it : INVALID_SOCKET);
      if(it != m_connections.end()) {
        m_connections.erase(it);
      }
    }
    if(closeSocket != INVALID_SOCKET) {
      if(CloseSocketSafe(closeSocket, true)) {
        UpdateInterpreter("Client socket closed");
      } else {
        success = false;
        ErrorInterpreter("Error closing client socket", false);
      }
    }
  }
  if(!success) {
    ErrorInterpreter("Error closing one or more connected client socket", false);
    return false;
  }
  UpdateInterpreter("All connected client sockets closed");
  return UnregisterWSA();
}

std::vector<std::string> TCPServerSocket::GetClientAddresses() const {
  std::shared_lock lock(m_connectionsMutex);
  std::vector<std::string> clientAddresses;
  clientAddresses.reserve(m_connections.size());
  for(SOCKET client : m_connections) {
    std::string clientAddress = GetSocketAddress(client);
    if(!clientAddress.empty()) {
      clientAddresses.push_back(clientAddress);
    }
  }
  return clientAddresses;
}

void TCPServerSocket::SetNoDelay(bool enabled, bool applyToAll) noexcept {
  m_socketOptions.noDelay = enabled;
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
  m_socketOptions.keepAlive = enabled;
  m_socketOptions.keepAliveTimeMs = timeMs;
  m_socketOptions.keepAliveIntervalMs = intervalMs;
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

//---- Broadcast(bytes) ----
void TCPServerSocket::Broadcast(const void* bytes, size_t byteCount) {
  try {
    if(bytes == nullptr || byteCount == 0) {
      ErrorInterpreter("Broadcast: invalid buffer/length", false);
      return;
    }
    std::vector<SOCKET> connections;
    {
      std::shared_lock lock(m_connectionsMutex);
      connections.assign(m_connections.begin(), m_connections.end());
    }
    if(connections.empty()) {
      ErrorInterpreter("No connections to broadcast over", false);
      return;
    }
    if(byteCount > static_cast<size_t>(std::numeric_limits<int>::max())) {
      ErrorInterpreter("Broadcast: payload too large for WinSock", false);
      return;
    }
    UpdateInterpreter("Broadcasting message: " + std::to_string(byteCount) + " bytes");
    const char* data = static_cast<const char*>(bytes);
    size_t failCount = 0;
    size_t successCount = 0;
    for(size_t i = 0; i < connections.size(); ++i) {
      SOCKET client = connections[i];
      UpdateInterpreter("Sending to client #" + std::to_string(i + 1));
      const int totalBytes = static_cast<int>(byteCount);
      const int sentBytes = SendAll(client, data, totalBytes);
      if(sentBytes != totalBytes) {
        ErrorInterpreter("Error sending message: ", true);
        ++failCount;
        CloseClientSocket(client);
        continue;
      }
      ++successCount;
      const std::string clientAddress = GetSocketAddress(client);
      UpdateInterpreter(clientAddress.empty()
        ? "Successful broadcast: Unable to obtain client IP"
        : "Successful broadcast: " + clientAddress);
    }
    UpdateInterpreter("# Failed Broadcasts: " + std::to_string(failCount));
    UpdateInterpreter("# Successful Broadcasts: " + std::to_string(successCount));
    if(failCount + successCount != connections.size()) {
      ErrorInterpreter("Mismatch: fails + successes != connection count", false);
    }
  } catch(const std::exception& e) {
    ErrorInterpreter(std::string("Broadcast error: ") + e.what(), false);
    throw;
  } catch(...) {
    ErrorInterpreter("Broadcast: Unknown error", false);
    throw;
  }
}

//---- Send(bytes, targetAddress) ----
int TCPServerSocket::Send(const void* bytes, size_t byteCount, const std::string& targetAddress) {
  try {
    if(bytes == nullptr || byteCount == 0) {
      ErrorInterpreter("Send(bytes, targetAddress): invalid buffer/length", false);
      return 0;
    }
    if(byteCount > static_cast<size_t>(std::numeric_limits<int>::max())) {
      ErrorInterpreter("Send(bytes, targetAddress): payload too large for WinSock", false);
      return 0;
    }
    UpdateInterpreter("BEGIN Send(bytes, targetAddress)");
    SOCKET target = INVALID_SOCKET;
    {
      std::shared_lock lock(m_connectionsMutex);
      for(SOCKET socket : m_connections) {
        if(GetSocketAddress(socket) == targetAddress) {
          target = socket;
          break;
        }
      }
    }
    if(target == INVALID_SOCKET) {
      ErrorInterpreter("Unable to find connected client with address '" + targetAddress + "'", false);
      UpdateInterpreter("END Send(bytes, targetAddress)");
      return 0;
    }
    UpdateInterpreter("Sending message to " + targetAddress + " - " + std::to_string(byteCount) + " Bytes");
    const int totalBytes = static_cast<int>(byteCount);
    const int sentBytes = SendAll(target, static_cast<const char*>(bytes), totalBytes);
    if(sentBytes != totalBytes) {
      ErrorInterpreter("Error sending message: ", true);
      CloseClientSocket(target);
    } else {
      UpdateInterpreter("Successfully sent message");
    }
    UpdateInterpreter("END Send(bytes, targetAddress)");
    return sentBytes;
  } catch(const std::exception& e) {
    ErrorInterpreter(std::string("Send(bytes, targetAddress) Error: ") + e.what(), false);
    throw;
  } catch(...) {
    ErrorInterpreter("Send(bytes, targetAddress): Unknown Error", false);
    throw;
  }
}

//---- Send(bytes) for exactly one connection ----
int TCPServerSocket::Send(const void* bytes, size_t byteCount) {
  try {
    if(bytes == nullptr || byteCount == 0) {
      ErrorInterpreter("Send(bytes): invalid buffer/length", false);
      return 0;
    }
    if(byteCount > static_cast<size_t>(std::numeric_limits<int>::max())) {
      ErrorInterpreter("Send(bytes): payload too large for WinSock", false);
      return 0;
    }
    UpdateInterpreter("BEGIN Send(bytes)");
    SOCKET target = INVALID_SOCKET;
    {
      std::shared_lock lock(m_connectionsMutex);
      if(m_connections.size() == 1) {
        target = *m_connections.begin();
      }
    }
    if(target == INVALID_SOCKET) {
      ErrorInterpreter("Requires Only One Connected Client", false);
      UpdateInterpreter("END Send(bytes)");
      return 0;
    }
    const int totalBytes = static_cast<int>(byteCount);
    const int sentBytes = Send(bytes, byteCount, target);
    UpdateInterpreter("END Send(bytes)");
    return sentBytes;
  } catch(const std::exception& e) {
    ErrorInterpreter(std::string("Send(bytes) Error: ") + e.what(), false);
    throw;
  } catch(...) {
    ErrorInterpreter("Send(bytes): Unknown Error", false);
    throw;
  }
}

//---- Send(bytes, SOCKET) ----
int TCPServerSocket::Send(const void* bytes, size_t byteCount, SOCKET target) {
  try {
    if(bytes == nullptr || byteCount == 0) {
      ErrorInterpreter("Send(bytes, SOCKET): invalid buffer/length", false);
      return 0;
    }
    if(byteCount > static_cast<size_t>(std::numeric_limits<int>::max())) {
      ErrorInterpreter("Send(bytes, SOCKET): payload too large for WinSock", false);
      return 0;
    }
    UpdateInterpreter("BEGIN Send(bytes, SOCKET)");
    UpdateInterpreter("Sending Message To " + GetSocketAddress(target) + " - " + std::to_string(byteCount) + " bytes");

    const int totalBytes = static_cast<int>(byteCount);
    const int sentBytes = SendAll(target, static_cast<const char*>(bytes), totalBytes);
    if(sentBytes != totalBytes) {
      ErrorInterpreter("Error sending message: ", true);
      CloseClientSocket(target);
    } else {
      UpdateInterpreter("Successfully sent message");
    }
    UpdateInterpreter("END Send(bytes, SOCKET)");
    return sentBytes;
  } catch(const std::exception& e) {
    ErrorInterpreter(std::string("Send(bytes, SOCKET) Error: ") + e.what(), false);
    throw;
  } catch(...) {
    ErrorInterpreter("Send(bytes, SOCKET): Unknown Error", false);
    throw;
  }
}

bool TCPServerSocket::ReadyToAccept() const noexcept {
  const bool configured = m_configured.load(std::memory_order_acquire);
  const bool wsaRegistered = m_wsaRegistered.load(std::memory_order_acquire);
  return configured && wsaRegistered && m_thisSocket != INVALID_SOCKET;
}

unsigned __stdcall TCPServerSocket::StaticAcceptConnection(void* arg) {
  auto* serverSocket = static_cast<TCPServerSocket*>(arg);
  if(serverSocket) {
    serverSocket->AcceptConnection();
  }
  return 0;
}

void TCPServerSocket::AcceptConnection() {
	try {
		m_active.store(true, std::memory_order_release);
		UpdateInterpreter("Accepting socket connections");
    if(!ReadyToAccept()) {
			ErrorInterpreter("Server socket not initialized", false);
			return;
		}
    while(ReadyToAccept()) {
      SOCKET acceptSocket = accept(m_thisSocket, nullptr, nullptr);
      if(acceptSocket == INVALID_SOCKET) {
        if(m_closeAttempt.load(std::memory_order_acquire) || !m_active.load(std::memory_order_acquire)) {
          return;
        }
        ErrorInterpreter("Error accepting connection: ", true);
        continue;
      }
      RegisterClient(acceptSocket);
		}
    if(m_active.load(std::memory_order_acquire) && !m_closeAttempt.load(std::memory_order_acquire)) {
      ErrorInterpreter("Error accepting connections: Server socket not initialized", false);
    }
	} catch(const std::exception& e) {
		std::string error = e.what();
		ErrorInterpreter("Accept error: " + error, false);
		throw;
	} catch(...) {
		ErrorInterpreter("Accept: Unknown error", false);
		throw;
	}
}

void TCPServerSocket::RegisterClient(SOCKET client) {
  try {
    if(!ApplySocketOptions(client)) {
      UpdateInterpreter("Failed to apply socket options - rejecting client");
      CloseSocketSafe(client, true);
      return;
    }
    size_t connectionCount = 0;
    bool reject = false;
    bool duplicate = false;
    const int maxConnections = m_maxConnections.load(std::memory_order_relaxed);
    {
      std::unique_lock lock(m_connectionsMutex);
      if(m_connections.size() >= static_cast<size_t>(maxConnections)) {
        reject = true;
      } else {
        auto [it, inserted] = m_connections.insert(client);
        if(!inserted) {
          duplicate = true;
        } else {
          connectionCount = m_connections.size();
        }
      }
    }
    if(reject || duplicate) {
      if(reject) {
        UpdateInterpreter("Reached max concurrent connections - Rejecting new client");
      }
      if(duplicate) {
        UpdateInterpreter("Duplicate client socket detected - Rejecting new client");
      }
      CloseSocketSafe(client, true);
      return;
    }
		std::string clientAddress = GetSocketAddress(client);
		std::string msg = "Accepted connection (" + std::to_string(connectionCount) + " of " + std::to_string(maxConnections) + "): ";
		if(clientAddress.empty()) {
			msg += "Unknown address";
		} else {
			msg += clientAddress;
		}
		UpdateInterpreter(msg);
    auto* params = new MessageHandlerParams{this, client};
    uintptr_t threadPtr = _beginthreadex(nullptr, 0, &TCPServerSocket::StaticMessageHandler, params, 0, nullptr);
    HANDLE threadHandle = reinterpret_cast<HANDLE>(threadPtr);
		if(threadHandle) {
			CloseHandle(threadHandle);
		} else {
      {
        std::unique_lock lock(m_connectionsMutex);
        m_connections.erase(client);
      }
      CloseSocketSafe(client, true);
      delete params;
			ErrorInterpreter("Thread creation error: ", true);
		}
	} catch(const std::exception& e) {
		std::string error = e.what();
		ErrorInterpreter("Register error: " + error, false);
		throw;
	} catch(...) {
		ErrorInterpreter("Register: Unknown error", false);
		throw;
	}
}

bool TCPServerSocket::ApplySocketOptions(SOCKET socket) noexcept {
  bool success = true;
  // TCP_NODELAY
  {
    const int flag = m_socketOptions.noDelay ? 1 : 0;
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
    const int flag = m_socketOptions.keepAlive ? 1 : 0;
    if(setsockopt(
      socket,
      SOL_SOCKET,
      SO_KEEPALIVE,
      reinterpret_cast<const char*>(&flag),
      sizeof(flag)
    ) == SOCKET_ERROR) {
      ErrorInterpreter("Failed to set SO_KEEPALIVE on client socket: ", true);
      success = false;
    } else if(m_socketOptions.keepAlive) {
      tcp_keepalive keepAliveSettings{};
      keepAliveSettings.onoff = 1;
      keepAliveSettings.keepalivetime = m_socketOptions.keepAliveTimeMs;
      keepAliveSettings.keepaliveinterval = m_socketOptions.keepAliveIntervalMs;
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

unsigned __stdcall TCPServerSocket::StaticMessageHandler(void* arg) {
  auto* params = static_cast<MessageHandlerParams*>(arg);
  if(params) {
    params->serverSocket->MessageHandler(params->clientSocket);
    delete params;
  }
  return 0;
}

void TCPServerSocket::MessageHandler(SOCKET clientSocket) {
	try {
    int lastMessageLength = -1;
    std::vector<unsigned char> buffer;
		while(true) {
      int messageLength = m_messageLength.load(std::memory_order_relaxed);
      if(messageLength != lastMessageLength) {
        buffer.resize(messageLength);
        lastMessageLength = messageLength;
      }
			const int byteCount = ::recv(clientSocket, reinterpret_cast<char*>(buffer.data()), messageLength, 0);
			if(byteCount > 0) {
				UpdateInterpreter("Received " + std::to_string(byteCount) + " bytes");
				OnRead(buffer.data(), byteCount, clientSocket);
      } else {
        if(byteCount == 0) {
          UpdateInterpreter("Connection closed by client");
        } else {
          ErrorInterpreter("Error checking connection: ", true);
        }
        UpdateInterpreter("Disconnected client detected");
        if(CloseClientSocket(clientSocket)) {
          UpdateInterpreter("Closed cisconnected client socket");
        } else {
          UpdateInterpreter("Failed to close disconnected client socket");
        }
        OnClientDisconnect();
        break;
      }
		}
	} catch(const std::exception& e) {
		std::string error = e.what();
		ErrorInterpreter("Message handler error: " + error, false);
		throw;
	} catch(...) {
		ErrorInterpreter("Message handler: Unknown error", false);
		throw;
	}
}

int TCPServerSocket::SendAll(SOCKET socket, const char* buffer, int bufferSize) {
  int totalSent = 0;
  while(totalSent < bufferSize) {
    const int sentBytes = ::send(socket, buffer + totalSent, bufferSize - totalSent, 0);
    if(sentBytes == SOCKET_ERROR) {
      const int err = WSAGetLastError();
      if(err == WSAEWOULDBLOCK || err == WSAEINTR) {
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

bool TCPServerSocket::CloseClientSocket(SOCKET clientSocket) {
  bool found = false;
  {
    std::unique_lock lock(m_connectionsMutex);
    auto it = m_connections.find(clientSocket);
    if(it == m_connections.end()) {
      //Already removed; idempotent success
      return true;
    }
    found = true;
    m_connections.erase(it);
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
	if(callback) {
		callback();
	} else {
		UpdateInterpreter("Client disconnected");
	}
}

void TCPServerSocket::OnRead(unsigned char* message, int byteCount, SOCKET sender) {
  std::function<void(unsigned char* message, int byteCount, SOCKET sender)> callback;
  {
    std::shared_lock lock(m_onReadMutex);
    callback = m_onRead;
  }
	if(callback) {
		callback(message, byteCount, sender);
	} else {
		std::string update = "Received message";
		if(sender != INVALID_SOCKET) {
      update += " from " + GetSocketAddress(sender);
		}
		UpdateInterpreter(update);
	}
}
