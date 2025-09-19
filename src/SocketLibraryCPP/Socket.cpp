#include "pch.h"
#include "SocketLibrary/Socket.h"

int Socket::s_wsaRefCount{0};
std::mutex Socket::s_wsaMutex;
WSADATA Socket::s_wsaData = {};

Socket::Socket() : m_service() {
	{
		std::unique_lock lock(m_errorHandlerMutex);
		m_errorHandler = nullptr;
	}
	{
		std::unique_lock lock(m_updateHandlerMutex);
		m_updateHandler = nullptr;
	}
	m_thisSocket = INVALID_SOCKET;
	m_ip = "127.0.0.1";
	m_portNum = 55555;
	m_wsaRegistered = false;
	m_active = false;
	m_configured = false;
	m_messageLength = 1000;
	m_closeAttempt = false;
}

Socket::~Socket() noexcept {
	UnregisterWSA();
	{
		std::unique_lock lock(m_errorHandlerMutex);
		m_errorHandler = nullptr;
	}
	{
		std::unique_lock lock(m_updateHandlerMutex);
		m_updateHandler = nullptr;
	}
}

void Socket::SetErrorHandler(std::function<void(const std::string& errorMessage)> errorHandler) {
	std::unique_lock lock(m_errorHandlerMutex);
	m_errorHandler = std::move(errorHandler);
}

void Socket::SetUpdateHandler(std::function<void(const std::string& updateMessage)> updateHandler) {
	std::unique_lock lock(m_updateHandlerMutex);
	m_updateHandler = std::move(updateHandler);
}

std::string Socket::GetName() const {
  return m_name;
}

bool Socket::SetName(const std::string& name) {
  m_name = name;
  return true;
}

std::string Socket::GetIP() const {
	return m_ip;
}

bool Socket::SetIP(const std::string& ip) {
	if(inet_pton(AF_INET, ip.c_str(), &m_service.sin_addr) == 1) {
		m_ip = ip;
		UpdateInterpreter("Successfully Set IP Address: " + ip);
		return true;
	}
	ErrorInterpreter("Error Changing IP Address: ", true);
	return false;
}

int Socket::GetPortNum() const {
	return m_portNum;
}

bool Socket::SetPortNum(int portNum) {
	if(portNum > 0 && portNum <= 65535) {
		m_portNum = portNum;
		UpdateInterpreter("Successfully Set Port Number: " + std::to_string(portNum));
		return true;
	}
	ErrorInterpreter("Error: Port Number Attempt '" + std::to_string(portNum) + "' Is Not Valid (Must Be A Number: 1-65535)", false);
	return false;
}

bool Socket::SetPortNum(const std::string& portNum) {
	int portAttempt = 0;
	if(!StringToInt(portNum, &portAttempt)) {
		ErrorInterpreter("Error Parsing Port Value From '" + portNum + "'", false);
		return false;
	}
	return SetPortNum(portAttempt);
}

int Socket::GetMessageLength() const {
	return m_messageLength;
}

bool Socket::SetMessageLength(int messageLength) {
	if(messageLength > 0) {
		m_messageLength = messageLength;
		return true;
	}
	ErrorInterpreter("Error: Message Length Attempt '" + std::to_string(messageLength) + "' Is Not Valid (Must Be A Number > 0)", false);
	return false;
}

bool Socket::SetMessageLength(const std::string& messageLength) {
	int msgLenAttempt = 0;
	if(!StringToInt(messageLength, &msgLenAttempt)) {
		ErrorInterpreter("Error Parsing Message Length Value From '" + messageLength + "'", false);
		return false;
	}
	return SetMessageLength(msgLenAttempt);
}

bool Socket::GetActive() const noexcept {
	return m_active.load(std::memory_order_acquire);
}

bool Socket::CheckIP(const std::string& ip) {
	sockaddr_in temp;
	if(inet_pton(AF_INET, ip.c_str(), &temp.sin_addr) == 1) {
		return true;
	}
	return false;
}

bool Socket::CheckPort(int port) {
	if(port > 0 && port <= 65535) {
		return true;
	}
	return false;
}

bool Socket::CheckPort(const std::string& port) {
	int portAttempt = 0;
	try {
		size_t pos = 0;
		int intAttempt = std::stoi(port, &pos);
		if(pos == port.length()) {
			portAttempt = intAttempt;
			return CheckPort(portAttempt);
		}
	} catch(...) {
		return false;
	}
	return false;
}

bool Socket::Initialize(int socketType) {
	if(!RegisterWSA()) {
		ErrorInterpreter("Error Initializing Socket: Winsock dll Not Found", false);
		return false;
	}
	std::string typeName = "";
	int protocol = -1;
	if(socketType == SOCK_DGRAM) {
		typeName = "UDP";
		protocol = IPPROTO_UDP;
	} else if(socketType == SOCK_STREAM) {
		typeName = "TCP";
		protocol = IPPROTO_TCP;
	}
	if(typeName == "" || protocol == -1) {
		ErrorInterpreter("Error Initializing Socket: Unrecognized Socket Type", false);
		return false;
	}
	UpdateInterpreter("Initializing " + typeName + " Socket " + m_ip + ":" + std::to_string(m_portNum));
	m_thisSocket = socket(AF_INET, socketType, protocol);
	if(m_thisSocket == INVALID_SOCKET) {
		ErrorInterpreter("Error Initializing Socket: ", true);
		UnregisterWSA();
		return false;
	}
	m_service.sin_family = AF_INET;
	if(inet_pton(AF_INET, m_ip.c_str(), &m_service.sin_addr) != 1) {
		ErrorInterpreter("Error Initializing Socket: ", true);
		UnregisterWSA();
		return false;
	}
	m_service.sin_port = htons(m_portNum);
	UpdateInterpreter("Socket Initialized Successfully!");
	return true;
}

bool Socket::RegisterWSA() {
	std::lock_guard<std::mutex> lock(s_wsaMutex);
	if(m_wsaRegistered) {
		UpdateInterpreter("WSA Already Registered");
		return true;
	}
	if(s_wsaRefCount == 0) {
		WORD wVersionRequested = MAKEWORD(2, 2);
		int error = WSAStartup(wVersionRequested, &s_wsaData);
		if(error != 0) {
			ErrorInterpreter("Error Finding Winsock dll: " + std::to_string(error), false);
			return false;
		}
		UpdateInterpreter("Winsock dll Found");
	} else {
		UpdateInterpreter("Winsock dll Already Attached");
	}
	std::string msg = "Winsock Status: ";
	msg += s_wsaData.szSystemStatus;
	UpdateInterpreter(msg);
	++s_wsaRefCount;
	m_wsaRegistered.store(true, std::memory_order_release);
	return true;
}

bool Socket::UnregisterWSA() {
	CloseSocketSafe(m_thisSocket, true);
	std::lock_guard<std::mutex> lock(s_wsaMutex);
	if(!m_wsaRegistered.load(std::memory_order_acquire)) {
		UpdateInterpreter("WSA Never Registered");
		return true;
	}
	m_wsaRegistered.store(false, std::memory_order_release);
	m_configured.store(false, std::memory_order_release);
	m_active.store(false, std::memory_order_release);
	if(s_wsaRefCount == 0) {
		UpdateInterpreter("WSA Never Registered");
		return true;
	}
	s_wsaRefCount--;
	if(s_wsaRefCount == 0) {
		UpdateInterpreter("Releasing Winsock dll");
		int error = WSACleanup();
		if(error != 0) {
			ErrorInterpreter("Winsock dll Not Released - Error: ", true);
			s_wsaRefCount++;
			m_wsaRegistered.store(true, std::memory_order_release);
			return false;
		}
		UpdateInterpreter("Winsock dll Released");
		return true;
	}
	std::string msg = "WSA Unregistered, but still in use. Remaining count: " + std::to_string(s_wsaRefCount);
	UpdateInterpreter(msg);
	return true;
}

bool Socket::CloseSocketSafe(SOCKET& socketToClose, bool shutDownSocket) {
	if(socketToClose == INVALID_SOCKET) {
		UpdateInterpreter("Socket Already Closed");
		return true;
	}
	if(shutDownSocket) {
		if(!ShutDownSocket(socketToClose)) {
			return false;
		}
	}
	if(closesocket(socketToClose) == SOCKET_ERROR) {
		ErrorInterpreter("Error Closing Socket: ", true);
		return false;
	}
	UpdateInterpreter("Closed Socket");
	socketToClose = INVALID_SOCKET;
	return true;
}

bool Socket::ShutDownSocket(SOCKET& socketToShutDown) {
	if(shutdown(socketToShutDown, SD_BOTH) == SOCKET_ERROR) {
		ErrorInterpreter("Error Shutting Down Socket: ", true);
		return false;
	} else {
		UpdateInterpreter("Shut Down Socket");
		return true;
	}
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
    std::unique_lock lock(m_errorHandlerMutex);
    callback = m_errorHandler;
  }
  if(callback) {
    callback(message);
  }
}

void Socket::UpdateInterpreter(const std::string& updateMessage) {
  std::function<void(const std::string& updateMessage)> callback;
  {
    std::unique_lock lock(m_updateHandlerMutex);
    callback = m_updateHandler;
  }
  if(callback) {
    callback(updateMessage);
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

std::string Socket::ConstructAddress(const std::string& ip, int port) {
	return ip + ":" + std::to_string(port);
}

std::string Socket::GetSocketAddress(SOCKET socket) {
	std::string socketIP = GetSocketIP(socket);
	int socketPort = GetSocketPort(socket);
	if(!socketIP.empty() && socketPort != INVALID_PORT) {
		return ConstructAddress(socketIP, socketPort);
	}
	return "";
}

std::string Socket::GetSocketAddress(const sockaddr_in& socket) {
	std::string socketIP = GetSocketIP(socket);
	int socketPort = GetSocketPort(socket);
	if(!socketIP.empty() && socketPort != INVALID_PORT) {
		return ConstructAddress(socketIP, socketPort);
	}
	return "";
}

std::string Socket::GetSocketIP(SOCKET socket) {
	if(socket == INVALID_SOCKET) {
		return std::string();
	}
	sockaddr_in addr;
	int addrLen = sizeof(addr);
	if(getpeername(socket, reinterpret_cast<sockaddr*>(&addr), &addrLen) != 0) {
		return std::string();
	}
	return GetSocketIP(addr);
}

std::string Socket::GetSocketIP(const sockaddr_in& addr) {
	int addrLen = sizeof(addr);
	char ipStr[NI_MAXHOST] = {0};
	int result = getnameinfo(reinterpret_cast<const sockaddr*>(&addr), addrLen, ipStr, NI_MAXHOST, nullptr, 0, NI_NUMERICHOST);
	if(result != 0) {
		return std::string();
	}
	return std::string(ipStr);
}

int Socket::GetSocketPort(SOCKET socket) {
	if(socket == INVALID_SOCKET) {
		return INVALID_PORT;
	}
	sockaddr_in addr;
	int addrLen = sizeof(addr);
	if(getpeername(socket, reinterpret_cast<sockaddr*>(&addr), &addrLen) != 0) {
		return INVALID_PORT;
	}
	return GetSocketPort(addr);
}

int Socket::GetSocketPort(const sockaddr_in& addr) {
	return ntohs(addr.sin_port);
}

bool Socket::StringToInt(const std::string& convertToInt, int* outInt) {
	try {
		size_t pos = 0;
		int intAttempt = std::stoi(convertToInt, &pos);
		if(pos == convertToInt.length()) {
			*outInt = intAttempt;
			return true;
		}
  } catch(...) {
    return false;
  }
	return false;
}
