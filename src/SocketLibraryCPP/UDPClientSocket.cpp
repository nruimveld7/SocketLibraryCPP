#include "pch.h"
#include "SocketLibrary/UDPClientSocket.h"

UDPClientSocket::UDPClientSocket() : m_target() {
	{
		std::unique_lock lock(m_onReadMutex);
		m_onRead = nullptr;
	}
	m_target.sin_family = AF_UNSPEC;
}

UDPClientSocket::~UDPClientSocket() {
	Close();
	{
		std::unique_lock lock(m_onReadMutex);
		m_onRead = nullptr;
	}
}

void UDPClientSocket::SetOnRead(std::function<void(unsigned char* message, int byteCount)> onRead) {
	std::unique_lock lock(m_onReadMutex);
	m_onRead = std::move(onRead);
}

bool UDPClientSocket::Open() {
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
	HANDLE hThread = CreateThread(nullptr, 0, &UDPClientSocket::StaticMessageHandler, this, 0, nullptr);
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

bool UDPClientSocket::Close() {
	m_active = false;
	UpdateInterpreter("Closing Client Socket");
	if(!CloseSocketSafe(m_thisSocket, true)) {
		UpdateInterpreter("Error Closing Client Socket");
		return false;
	}
	UpdateInterpreter("Client Socket Closed");
	if(!UnregisterWSA()) {
		return false;
	}
	return true;
}

DWORD WINAPI UDPClientSocket::StaticMessageHandler(LPVOID lpParam) {
	auto* clientSocket = reinterpret_cast<UDPClientSocket*>(lpParam);
	if(clientSocket) {
		clientSocket->MessageHandler();
		return 0;
	}
	return 1;
}

void UDPClientSocket::MessageHandler() {
	m_active = true;
	while(true) {
		std::vector<unsigned char> buffer(m_messageLength);
		sockaddr_in serverAddr;
		int addrLen = sizeof(serverAddr);

		int byteCount = recvfrom(
			m_thisSocket,
			reinterpret_cast<char*>(buffer.data()),
			m_messageLength,
			0,
			(sockaddr*)&serverAddr,
			&addrLen
		);
		if(!m_active) {
			break;
		}
		if(byteCount > 0) {
			UpdateInterpreter("Received " + std::to_string(byteCount) + " Bytes");
			OnRead(buffer.data(), byteCount);
		} else {
			if(byteCount == 0) {
				ErrorInterpreter("Connection Closed By Server", false);
			} else {
				ErrorInterpreter("Error Receiving Message: ", true);
			}
			OnRead(nullptr, -1);
			break;
		}
	}
}

void UDPClientSocket::OnRead(unsigned char* message, int byteCount) {
	std::unique_lock lock(m_onReadMutex);
	if(m_onRead) {
		m_onRead(message, byteCount);
	} else {
		UpdateInterpreter("Received Message");
	}
}