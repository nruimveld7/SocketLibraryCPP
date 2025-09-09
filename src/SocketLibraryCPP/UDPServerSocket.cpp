#include "pch.h"
#include "SocketLibrary/UDPServerSocket.h"

UDPServerSocket::UDPServerSocket() : m_target() {
	{
		std::unique_lock lock(m_onReadMutex);
		m_onRead = nullptr;
	}
	m_target.sin_family = AF_UNSPEC;
}

UDPServerSocket::~UDPServerSocket() {
	Close();
	{
		std::unique_lock lock(m_onReadMutex);
		m_onRead = nullptr;
	}
}

bool UDPServerSocket::Open() {
	/*
	if(!SetIP("0.0.0.0")) {
		ErrorInterpreter("Error Setting Server IP For Initialization", false);
		return false;
	}*/
	if(!Initialize(SOCK_DGRAM)) {
		ErrorInterpreter("Error Initializing Socket", false);
		return false;
	}
	if(m_target.sin_family == AF_UNSPEC) {
		m_target = m_service;
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
	m_configured = true;
	UpdateInterpreter("Preparing To Listen For Messages");
	HANDLE hThread = CreateThread(nullptr, 0, &UDPServerSocket::StaticMessageHandler, this, 0, nullptr);
	if(hThread == nullptr) {
		ErrorInterpreter("Thread Creation Error: ", true);
		//if(m_wsaRegistered) {
			UnregisterWSA();
		//}
		return false;
	}
	CloseHandle(hThread);
	UpdateInterpreter("Ready To Send Messages");
	return true;
}

bool UDPServerSocket::Close() {
	m_active = false;
	UpdateInterpreter("Closing Server Socket");
	if(!CloseSocketSafe(m_thisSocket, true)) {
		UpdateInterpreter("Error Closing Server Socket");
		return false;
	}
	UpdateInterpreter("Server Socket Closed");
	if(!UnregisterWSA()) {
		return false;
	}
	return true;
}

void UDPServerSocket::SetOnRead(std::function<void(unsigned char* message, int byteCount, sockaddr_in* sender)> onRead) {
	{
		std::unique_lock lock(m_onReadMutex);
		m_onRead = std::move(onRead);
	}
}

DWORD WINAPI UDPServerSocket::StaticMessageHandler(LPVOID lpParam) {
	auto* serverSocket = reinterpret_cast<UDPServerSocket*>(lpParam);
	if(serverSocket) {
		serverSocket->MessageHandler();
		return 0;
	}
	return 1;
}

void UDPServerSocket::MessageHandler() {
	m_active = true;
	while(true) {
		std::vector<unsigned char> buffer(m_messageLength);
		sockaddr_in clientAddr;
		int addrLen = sizeof(clientAddr);

		int byteCount = recvfrom(
			m_thisSocket,
			reinterpret_cast<char*>(buffer.data()),
			m_messageLength,
			0,
			(sockaddr*)&clientAddr,
			&addrLen
		);
		if(!m_active) {
			break;
		}
		if(byteCount > 0) {
			UpdateInterpreter("Received " + std::to_string(byteCount) + " Bytes");
			OnRead(buffer.data(), byteCount, &clientAddr);
		} else {
			if(byteCount == 0) {
				ErrorInterpreter("Connection Closed By Peer", false);
			} else {
				ErrorInterpreter("Error Receiving Message: ", true);
			}
			OnRead(nullptr, -1, nullptr);
			break;
		}
	}
}

void UDPServerSocket::OnRead(unsigned char* message, int byteCount, sockaddr_in* sender) {
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