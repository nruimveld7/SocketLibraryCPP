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
	m_listenBufferSize = 1;
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

int TCPServerSocket::GetListenBufferSize() {
	return m_listenBufferSize;
}

bool TCPServerSocket::SetListenBufferSize(int listenBufferSize) {
	if(listenBufferSize > 0) {
		m_listenBufferSize = listenBufferSize;
		UpdateInterpreter("Successfully Set Listen Buffer Size: " + std::to_string(listenBufferSize));
		return true;
	}
	ErrorInterpreter("Error: Listen Buffer Attempt '" + std::to_string(listenBufferSize) + "' Is Not Valid (Must Be A Number > 0)", false);
	return false;
}

bool TCPServerSocket::SetListenBufferSize(std::string listenBufferSize) {
	int listenBuffAttempt = 0;
	if(!StringToInt(listenBufferSize, &listenBuffAttempt)) {
		ErrorInterpreter("Error Parsing Listen Buffer Value From '" + listenBufferSize + "'", false);
		return false;
	}
	return SetListenBufferSize(listenBuffAttempt);
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

int TCPServerSocket::GetNumConnections() {
	return m_numConnections.load(std::memory_order_relaxed);
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
			//if(m_wsaRegistered) {
			UnregisterWSA();
			//}
			return false;
		}
		UpdateInterpreter("Binding Successful!");
		UpdateInterpreter("Preparing To Listen For Connections");
		if(listen(m_thisSocket, m_listenBufferSize) == SOCKET_ERROR) {
			ErrorInterpreter("Error Listening On Socket: ", true);
			//if(m_wsaRegistered) {
			UnregisterWSA();
			//}
			return false;
		}
		m_configured = true;
		m_closeAttempt = false;
		UpdateInterpreter("Ready To Listen For Connections");
		HANDLE hThread = CreateThread(nullptr, 0, &TCPServerSocket::StaticAcceptConnection, this, 0, nullptr);
		if(hThread == nullptr) {
			ErrorInterpreter("Thread Creation Error: ", true);
			//if(m_wsaRegistered) {
			UnregisterWSA();
			//}
			return false;
		}
		CloseHandle(hThread);
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

DWORD WINAPI TCPServerSocket::StaticAcceptConnection(LPVOID lpParam) {
	auto* serverSocket = reinterpret_cast<TCPServerSocket*>(lpParam);
	if(serverSocket) {
		serverSocket->AcceptConnection();
		return 0;
	}
	return 1;
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
			if(m_numConnections.load(std::memory_order_relaxed) >= m_maxConnections) {
				UpdateInterpreter("Reached Max Concurrent Connections - Will Resume Accepting Connections When A Client Socket Disconnects");
				if(CloseSocketSafe(m_thisSocket, false)) {
					m_configured = false;
					return;
				}
				continue;
			}
			SOCKET acceptSocket = accept(m_thisSocket, nullptr, nullptr);
			if(acceptSocket == INVALID_SOCKET) {
				ErrorInterpreter("Error Accepting Connection: ", true);
				continue;
			}
			RegisterClient(acceptSocket);
		}
		ErrorInterpreter("Error Accepting Connections: Server Socket Not Initialized", false);
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
		std::unique_lock lock(m_connectionsMutex);
		m_connections.push_back(client);
		m_numConnections.fetch_add(1, std::memory_order_relaxed);
		std::string clientAddress = GetSocketAddress(client);
		std::string msg = "Accepted Connection (" + std::to_string(m_numConnections.load(std::memory_order_relaxed)) + " Of " + std::to_string(m_maxConnections) + "): ";
		if(clientAddress.empty()) {
			msg += "Unknown Address";
		} else {
			msg += clientAddress;
		}
		UpdateInterpreter(msg);
		MessageHandlerParams* params = new MessageHandlerParams();
		params->serverSocket = this;
		params->clientSocket = m_connections.back();
		lock.unlock();
		HANDLE hThread = CreateThread(nullptr, 0, &TCPServerSocket::StaticMessageHandler, params, 0, nullptr);
		if(hThread) {
			CloseHandle(hThread);
		} else {
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

DWORD WINAPI TCPServerSocket::StaticMessageHandler(LPVOID lpParam) {
	auto* params = reinterpret_cast<MessageHandlerParams*>(lpParam);
	if(params) {
		params->serverSocket->MessageHandler(params->clientSocket);
		delete params;
		return 0;
	}
	return 1;
}

void TCPServerSocket::MessageHandler(SOCKET clientSocket) {
	try {
		while(true) {
			std::vector<unsigned char> buffer(m_messageLength);
			int byteCount = recv(clientSocket, reinterpret_cast<char*>(buffer.data()), m_messageLength, 0);
			if(byteCount > 0) {
				UpdateInterpreter("Received " + std::to_string(byteCount) + " Bytes");
				OnRead(buffer.data(), byteCount, &clientSocket);
			} else {
				ErrorInterpreter("Error Checking Connection: ", true);
				UpdateInterpreter("Disconnected Client Detected");
				if(CloseClientSocket(clientSocket)) {
					OnClientDisconnect();
					UpdateInterpreter("Closed Disconnected Client Socket");
					if(!m_configured && !m_closeAttempt && (int)(m_numConnections.load(std::memory_order_relaxed)) < m_maxConnections) {
						Open();
					}
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
	m_numConnections.fetch_sub(1, std::memory_order_relaxed);
	return true;
}

bool TCPServerSocket::Close() {
	m_active = false;
	m_closeAttempt = true;
	UpdateInterpreter("Closing Server Socket");
	if(!CloseSocketSafe(m_thisSocket, false)) {
		UpdateInterpreter("Error Closing Server Socket");
		return false;
	}
	UpdateInterpreter("Server Socket Closed");
	UpdateInterpreter("Closing All Connected Client Sockets");
	bool success = true;
	std::unique_lock lock(m_connectionsMutex);
	for(auto it = m_connections.rbegin(); it != m_connections.rend(); ++it) {
		if(CloseSocketSafe(*it, true)) {
			m_connections.pop_back();
			UpdateInterpreter("Client Socket Closed");
		} else {
			success = false;
			ErrorInterpreter("Error Closing Client Socket", false);
		}
	}
	lock.unlock();
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
	for(const auto& client : m_connections) {
		std::string clientAddress = GetSocketAddress(client);
		if(clientAddress != "") {
			clientAddresses.push_back(clientAddress);
		}
	}
	return clientAddresses;
}

void TCPServerSocket::OnClientDisconnect() {
	std::unique_lock lock(m_onClientDisconnectMutex);
	if(m_onClientDisconnect) {
		m_onClientDisconnect();
	} else {
		UpdateInterpreter("Client Disconnected");
	}
}

void TCPServerSocket::OnRead(unsigned char* message, int byteCount, SOCKET* sender) {
	std::unique_lock lock(m_onReadMutex);
	if(m_onRead) {
		m_onRead(message, byteCount, sender);
	} else {
		std::string message = "Received Message";
		if(sender) {
			message += " From " + GetSocketAddress(*sender);
		}
		UpdateInterpreter(message);
	}
}