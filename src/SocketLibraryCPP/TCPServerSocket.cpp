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
	m_listenBacklog = 1;
	m_maxConnections = 2;
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

void TCPServerSocket::SetOnRead(std::function<void(unsigned char* message, int byteCount, SOCKET* sender)> onRead) {
	std::unique_lock lock(m_onReadMutex);
	m_onRead = std::move(onRead);
}

int TCPServerSocket::GetListenBacklog() {
	return m_listenBacklog;
}

bool TCPServerSocket::SetListenBacklog(int listenBacklog) {
	if(listenBacklog > 0) {
		m_listenBacklog = listenBacklog;
		UpdateInterpreter("Successfully Set Listen Backlog: " + std::to_string(listenBacklog));
		return true;
	}
	ErrorInterpreter("Error: Listen Backlog Attempt '" + std::to_string(listenBacklog) + "' Is Not Valid (Must Be A Number > 0)", false);
	return false;
}

bool TCPServerSocket::SetListenBacklog(std::string listenBacklog) {
	int listenBuffAttempt = 0;
	if(!StringToInt(listenBacklog, &listenBuffAttempt)) {
		ErrorInterpreter("Error Parsing Listen Backlog Value From '" + listenBacklog + "'", false);
		return false;
	}
	return SetListenBacklog(listenBuffAttempt);
}

int TCPServerSocket::GetMaxConnections() {
	return m_maxConnections;
}

bool TCPServerSocket::SetMaxConnections(int maxConnections) {
	if(maxConnections > 0) {
		m_maxConnections = maxConnections;
		UpdateInterpreter("Successfully Set Max Connections: " + std::to_string(maxConnections));
		return true;
	}
	ErrorInterpreter("Error: Max Connections Attempt '" + std::to_string(maxConnections) + "' Is Not Valid (Must Be A Number > 0)", false);
	return false;
}

bool TCPServerSocket::SetMaxConnections(std::string maxConnections) {
	int maxConnAttempt = 0;
	if(!StringToInt(maxConnections, &maxConnAttempt)) {
		ErrorInterpreter("Error Parsing Max Connections Value From '" + maxConnections + "'", false);
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
			ErrorInterpreter("Error Initializing Socket", false);
			return false;
		}
		UpdateInterpreter("Binding Socket");
		if(bind(m_thisSocket, (SOCKADDR*)&m_service, sizeof(m_service)) == SOCKET_ERROR) {
			ErrorInterpreter("Socket Binding Error: ", true);
			UnregisterWSA();
			return false;
		}
		UpdateInterpreter("Binding Successful!");
		UpdateInterpreter("Preparing To Listen For Connections");
		if(listen(m_thisSocket, m_listenBacklog) == SOCKET_ERROR) {
			ErrorInterpreter("Error Listening On Socket: ", true);
			UnregisterWSA();
			return false;
		}
		m_configured = true;
		m_closeAttempt = false;
		UpdateInterpreter("Ready To Listen For Connections");
    uintptr_t threadPtr = _beginthreadex(nullptr, 0, &TCPServerSocket::StaticAcceptConnection, this, 0, nullptr);
    HANDLE threadHandle = reinterpret_cast<HANDLE>(threadPtr);
		if(threadHandle == nullptr) {
			ErrorInterpreter("Thread Creation Error: ", true);
			UnregisterWSA();
			return false;
		}
		CloseHandle(threadHandle);
		return true;
	} catch(const std::exception& e) {
		std::string error = e.what();
		ErrorInterpreter("Open Error: " + error, false);
		throw;
	} catch(...) {
		ErrorInterpreter("Open: Unknown Error", false);
		throw;
	}
	return false;
}

bool TCPServerSocket::Close() {
  m_active = false;
  m_closeAttempt = true;
  UpdateInterpreter("Closing Server Socket");
  if(!CloseSocketSafe(m_thisSocket, false)) {
    UpdateInterpreter("Error Closing Server Socket");
  } else {
    UpdateInterpreter("Server Socket Closed");
  }
  UpdateInterpreter("Closing All Connected Client Sockets");
  bool success = true;
  while(true) {
    SOCKET closeSocket = INVALID_SOCKET;
    {
      std::unique_lock lock(m_connectionsMutex);
      if(m_connections.empty()) {
        break;
      }
      closeSocket = m_connections.back();
      m_connections.pop_back();
    }
    if(closeSocket != INVALID_SOCKET) {
      if(CloseSocketSafe(closeSocket, true)) {
        UpdateInterpreter("Client Socket Closed");
      } else {
        success = false;
        ErrorInterpreter("Error Closing Client Socket", false);
      }
    }
  }
  if(!success) {
    ErrorInterpreter("Error Closing One Or More Connected Client Socket", false);
    return false;
  }
  UpdateInterpreter("All Connected Client Sockets Closed");
  return UnregisterWSA();
}

std::vector<std::string> TCPServerSocket::GetClientAddresses() {
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
      connections = m_connections;
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
    ErrorInterpreter(std::string("Broadcast Error: ") + e.what(), false);
    throw;
  } catch(...) {
    ErrorInterpreter("Broadcast: Unknown Error", false);
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
      ErrorInterpreter("Error Sending Message: ", true);
    } else {
      UpdateInterpreter("Successfully Sent Message");
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
        target = m_connections.front();
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
      ErrorInterpreter("Error Sending Message: ", true);
    } else {
      UpdateInterpreter("Successfully Sent Message");
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

unsigned __stdcall TCPServerSocket::StaticAcceptConnection(void* arg) {
  auto* serverSocket = static_cast<TCPServerSocket*>(arg);
  if(serverSocket) {
    serverSocket->AcceptConnection();
  }
  return 0;
}

void TCPServerSocket::AcceptConnection() {
	try {
		m_active = true;
		UpdateInterpreter("Accepting Socket Connections");
		if(!m_configured || !m_wsaRegistered || m_thisSocket == INVALID_SOCKET) {
			ErrorInterpreter("Server Socket Not Initialized", false);
			return;
		}
		while(m_configured && m_wsaRegistered && m_thisSocket != INVALID_SOCKET) {
      SOCKET acceptSocket = accept(m_thisSocket, nullptr, nullptr);
      if(acceptSocket == INVALID_SOCKET) {
        if(m_closeAttempt || !m_active) {
          return;
        }
        ErrorInterpreter("Error Accepting Connection: ", true);
        continue;
      }
      RegisterClient(acceptSocket);
		}
    if(m_active && !m_closeAttempt) {
      ErrorInterpreter("Error Accepting Connections: Server Socket Not Initialized", false);
    }
	} catch(const std::exception& e) {
		std::string error = e.what();
		ErrorInterpreter("Accept Error: " + error, false);
		throw;
	} catch(...) {
		ErrorInterpreter("Accept: Unknown Error", false);
		throw;
	}
}

void TCPServerSocket::RegisterClient(SOCKET client) {
  try {
    size_t connectionCount;
    {
      std::unique_lock lock(m_connectionsMutex);
      if(m_connections.size() >= static_cast<size_t>(m_maxConnections)) {
        UpdateInterpreter("Reached Max Concurrent Connections - Rejecting New Client");
        CloseSocketSafe(client, true);
        return;
      }
      m_connections.push_back(client);
      connectionCount = m_connections.size();
    }
		std::string clientAddress = GetSocketAddress(client);
		std::string msg = "Accepted Connection (" + std::to_string(connectionCount) + " Of " + std::to_string(m_maxConnections) + "): ";
		if(clientAddress.empty()) {
			msg += "Unknown Address";
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
      delete params;
			ErrorInterpreter("Thread Creation Error: ", true);
		}
	} catch(const std::exception& e) {
		std::string error = e.what();
		ErrorInterpreter("Register Error: " + error, false);
		throw;
	} catch(...) {
		ErrorInterpreter("Register: Unknown Error", false);
		throw;
	}
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
		while(true) {
			std::vector<unsigned char> buffer(m_messageLength);
			int byteCount = ::recv(clientSocket, reinterpret_cast<char*>(buffer.data()), m_messageLength, 0);
			if(byteCount > 0) {
				UpdateInterpreter("Received " + std::to_string(byteCount) + " Bytes");
				OnRead(buffer.data(), byteCount, &clientSocket);
			} else {
				ErrorInterpreter("Error Checking Connection: ", true);
				UpdateInterpreter("Disconnected Client Detected");
				if(CloseClientSocket(clientSocket)) {
					OnClientDisconnect();
					UpdateInterpreter("Closed Disconnected Client Socket");
				} else {
					UpdateInterpreter("Failed To Close Disconnected Client Socket");
				}
				OnRead(nullptr, -1, nullptr);
				break;
			}
		}
	} catch(const std::exception& e) {
		std::string error = e.what();
		ErrorInterpreter("Message Handler Error: " + error, false);
		throw;
	} catch(...) {
		ErrorInterpreter("Message Handler: Unknown Error", false);
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
  std::unique_lock lock(m_connectionsMutex);
  auto it = std::find(m_connections.begin(), m_connections.end(), clientSocket);
  if(it == m_connections.end()) {
    ErrorInterpreter("Error Finding Socket In Connections List", false);
    return false;
  }
  UpdateInterpreter("Found Client Socket In Connections List");
  if(!CloseSocketSafe(clientSocket, true)) {
    ErrorInterpreter("Unable To Close Client Socket", false);
    return false;
  }
  m_connections.erase(it);
  return true;
}

void TCPServerSocket::OnClientDisconnect() {
  std::function<void()> callback;
  {
    std::unique_lock lock(m_onClientDisconnectMutex);
    callback = m_onClientDisconnect;
  }
	if(callback) {
		callback();
	} else {
		UpdateInterpreter("Client Disconnected");
	}
}

void TCPServerSocket::OnRead(unsigned char* message, int byteCount, SOCKET* sender) {
  std::function<void(unsigned char* message, int byteCount, SOCKET* sender)> callback;
  {
    std::unique_lock lock(m_onReadMutex);
    callback = m_onRead;
  }
	if(callback) {
		callback(message, byteCount, sender);
	} else {
		std::string update = "Received Message";
		if(sender) {
      update += " From " + GetSocketAddress(*sender);
		}
		UpdateInterpreter(update);
	}
}
