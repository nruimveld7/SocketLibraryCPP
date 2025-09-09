#include "pch.h"
#include "SocketLibrary/TCPClientSocket.h"

TCPClientSocket::TCPClientSocket() {
	{
		std::unique_lock lock(m_onDisconnectMutex);
		m_onDisconnect = nullptr;
	}
	{
		std::unique_lock lock(m_onReadMutex);
		m_onRead = nullptr;
	}
	m_connected = false;
	m_connectionDelay = 5;
	m_cancelConnect = false;
}

TCPClientSocket::~TCPClientSocket() {
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

int TCPClientSocket::GetConnectionDelay() {
	return m_connectionDelay.load();
}

bool TCPClientSocket::SetConnectionDelay(int connectionDelay) {
	if(connectionDelay >= 0) {
		m_connectionDelay = connectionDelay;
		UpdateInterpreter("Successfully Set Connection Delay: " + std::to_string(connectionDelay));
		return true;
	} else {
		ErrorInterpreter("Error: Connection Delay Attempt '" + std::to_string(connectionDelay) + "' Is Not Valid (Must Be A Number > 0)", false);
		return false;
	}
}

bool TCPClientSocket::SetConnectionDelay(std::string connectionDelay) {
	int connDelayAttempt = 0;
	if(StringToInt(connectionDelay, &connDelayAttempt)) {
		return SetConnectionDelay(connDelayAttempt);
	} else {
		ErrorInterpreter("Error Parsing Connection Delay Value From '" + connectionDelay + "'", false);
		return false;
	}
}

bool TCPClientSocket::GetConnected() {
	return m_connected.load();
}

bool TCPClientSocket::GetConnecting() {
	return m_connecting.load();
}

bool TCPClientSocket::Open() {
	m_cancelConnect = false;
	if(Initialize(SOCK_STREAM)) {
		m_closeAttempt = false;
		m_configured = true;
		UpdateInterpreter("Ready To Connect");
		HANDLE hThread = CreateThread(nullptr, 0, &TCPClientSocket::StaticConnect, this, 0, nullptr);
		if(hThread != nullptr) {
			CloseHandle(hThread);
			return true;
		} else {
			ErrorInterpreter("Thread Creation Error: ", true);
			return false;
		}
	} else {
		UpdateInterpreter("Error Initializing Socket");
		return false;
	}
}

DWORD WINAPI TCPClientSocket::StaticConnect(LPVOID lpParam) {
	TCPClientSocket* clientSocket = static_cast<TCPClientSocket*>(lpParam);
	if(clientSocket != nullptr) {
		clientSocket->Connect();
		return 0;
	}
	return 1;
}

void TCPClientSocket::Connect() {
	UpdateInterpreter("Attempting Socket Connection");
	while(m_configured && m_wsaRegistered && !m_connected.load() && m_thisSocket != INVALID_SOCKET) {
		m_connecting = true;
		while(!m_connected.load() && !m_cancelConnect.load()) {
			if(connect(m_thisSocket, (SOCKADDR*)&m_service, sizeof(m_service)) != SOCKET_ERROR) {
				m_connected = true;
				m_active = true;
				UpdateInterpreter("Client Connected!");
			} else {
				ErrorInterpreter("Error Connecting To Socket: ", true);
				std::stringstream ss;
				ss << m_connectionDelay.load();
				UpdateInterpreter("Trying Again In " + ss.str() + " Seconds");
				Sleep(m_connectionDelay.load() * 1000);
			}
		}
		m_connecting = false;
		while(m_connected.load()) {
			if(MessageHandler()) {
				break;
			}
		}
		if(m_cancelConnect.load()) {
			UpdateInterpreter("Connection Attempt Cancelled");
			break;
		}
	}
	ErrorInterpreter("Client Socket Not Yet Initialized", false);
}

bool TCPClientSocket::MessageHandler() {
	bool error = false;
	char* buffer = (char*)malloc(sizeof(char) * m_messageLength);
	if(buffer != nullptr) {
		int byteCount = recv(m_thisSocket, buffer, m_messageLength, 0);
		if(byteCount > 0) {
			//ReceivedData
			std::stringstream ss;
			ss << byteCount;
			UpdateInterpreter("Received " + ss.str() + " Bytes");
		} else if(byteCount == 0) {
			error = true;
			if(!m_closeAttempt) {
				//Server disconnected
				ErrorInterpreter("Error Checking Connection: ", true);
				OnDisconnect();
				/*
				UpdateInterpreter("Forcibly Closing The Connection");
				if(Close()) {
					Open();
				} else {
					UpdateInterpreter("Failed To Forcibly Close The Connection");
				}
				*/
			}
		} else {
			if(!m_closeAttempt) {
				//Error
				error = true;
				ErrorInterpreter("Error Checking Connection: ", true);
				OnDisconnect();
				/*
				UpdateInterpreter("Forcibly Closing The Connection");
				if(Close()) {
					Open();
				} else {
					UpdateInterpreter("Failed To Forcibly Close The Connection");
				}
				*/
			}
		}
		if(error) {
			OnRead(nullptr, -1);
		} else {
			OnRead(reinterpret_cast<unsigned char*>(buffer), byteCount);
		}
	}
	free(buffer);
	return error;
}

bool TCPClientSocket::Close() {
	m_active = false;
	m_closeAttempt = true;
	//Call OnDisconnect Here
	if(m_connected.load()) {
		OnDisconnect();
		UpdateInterpreter("Closing Client Socket");
		if(CloseSocketSafe(m_thisSocket, true)) {
			UpdateInterpreter("Client Socket Closed");
			m_connected = false;
			if(UnregisterWSA()) {
				return true;
			} else {
				return false;
			}
		} else {
			UpdateInterpreter("Error Closing Client Socket");
			return false;
		}
	} else if(!m_cancelConnect.load()) {
		UpdateInterpreter("Cancelling Connection Attempt");
		m_cancelConnect = true;
		m_configured = false;
		return true;
	} else {
		return true;
	}
}

void TCPClientSocket::OnDisconnect() {
	m_connected = false;
	std::unique_lock lock(m_onDisconnectMutex);
	if(m_onDisconnect) {
		m_onDisconnect();
	} else {
		UpdateInterpreter("Disconnected");
	}
}

void TCPClientSocket::OnRead(unsigned char* message, int byteCount) {
	std::unique_lock lock(m_onReadMutex);
	if(m_onRead) {
		m_onRead(message, byteCount);
	} else {
		UpdateInterpreter("Received Message");
	}
}