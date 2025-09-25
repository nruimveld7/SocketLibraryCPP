#include "pch.h"
#include "SocketLibrary/Socket.h"

int Socket::s_wsaRefCount{0};
std::mutex Socket::s_wsaMutex;
WSADATA Socket::s_wsaData = {};

Socket::~Socket() noexcept {
  m_workers.StopWorkers();
  (void)m_workers.WaitForWorkers();
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
  : m_thisSocket(other.m_thisSocket),
  m_service(other.m_service),
  m_name(std::move(other.m_name)),
  m_ip(std::move(other.m_ip)),
  m_portNum(other.m_portNum),
  m_messageLength(other.m_messageLength.load(std::memory_order_relaxed)),
  m_wsaRegistered(other.m_wsaRegistered.load(std::memory_order_relaxed)),
  m_active(other.m_active.load(std::memory_order_relaxed)),
  m_configured(other.m_configured.load(std::memory_order_relaxed)),
  m_closeAttempt(other.m_closeAttempt.load(std::memory_order_relaxed)) {
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
  other.m_thisSocket = INVALID_SOCKET;
  other.m_wsaRegistered = false;
  other.m_active = false;
  other.m_configured = false;
  other.m_closeAttempt = false;
  other.m_portNum = INVALID_PORT;
  other.m_name.clear();
  other.m_ip.clear();
  std::memset(&other.m_service, 0, sizeof(other.m_service));
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
    m_service = other.m_service;
    m_name = std::move(other.m_name);
    m_ip = std::move(other.m_ip);
    m_portNum = other.m_portNum;
    m_messageLength = other.m_messageLength.load(std::memory_order_relaxed);
    m_wsaRegistered = other.m_wsaRegistered.load(std::memory_order_relaxed);
    m_active = other.m_active.load(std::memory_order_relaxed);
    m_configured = other.m_configured.load(std::memory_order_relaxed);
    m_closeAttempt = other.m_closeAttempt.load(std::memory_order_relaxed);
    //Steal the handle last.
    m_thisSocket = other.m_thisSocket;
    //Invalidate source.
    other.m_thisSocket = INVALID_SOCKET;
    other.m_wsaRegistered = false;
    other.m_active = false;
    other.m_configured = false;
    other.m_closeAttempt = false;
    other.m_portNum = INVALID_PORT;
    other.m_name.clear();
    other.m_ip.clear();
    std::memset(&other.m_service, 0, sizeof(other.m_service));
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
  return m_name;
}

bool Socket::SetName(const std::string& name) {
  m_name = name;
  return true;
}

std::string Socket::GetIP() const noexcept {
	return m_ip;
}

bool Socket::SetIP(const std::string& ip) {
	if(inet_pton(AF_INET, ip.c_str(), &m_service.sin_addr) == 1) {
		m_ip = ip;
		UpdateInterpreter("Successfully set IP address: " + ip);
		return true;
	}
	ErrorInterpreter("Error changing IP address", false);
	return false;
}

int Socket::GetPortNum() const noexcept {
	return m_portNum;
}

bool Socket::SetPortNum(int portNum) {
	if(portNum > 0 && portNum <= 65535) {
		m_portNum = portNum;
		UpdateInterpreter("Successfully set port number: " + std::to_string(portNum));
		return true;
	}
	ErrorInterpreter("Error: port number attempt '" + std::to_string(portNum) + "' is not valid (must be a number: 1-65535)", false);
	return false;
}

bool Socket::SetPortNum(const std::string& portNum) {
	int portAttempt = 0;
	if(!StringToInt(portNum, &portAttempt)) {
		ErrorInterpreter("Error parsing port value from '" + portNum + "'", false);
		return false;
	}
	return SetPortNum(portAttempt);
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
	if(!StringToInt(messageLength, &msgLenAttempt)) {
		ErrorInterpreter("Error parsing message length value from '" + messageLength + "'", false);
		return false;
	}
	return SetMessageLength(msgLenAttempt);
}

bool Socket::Close() {
  SetActive(false);
  SetClosing(true);
  const bool socketClosed = Cleanup();
  SetConfigured(false);
  StopWorkers();
  (void)WaitForWorkers();
  const bool wsaUnregistered = UnregisterWSA();
  return socketClosed && wsaUnregistered;
}

bool Socket::GetActive() const noexcept {
	return IsActive();
}

bool Socket::CheckIP(const std::string& ip) noexcept {
	sockaddr_in temp;
	if(inet_pton(AF_INET, ip.c_str(), &temp.sin_addr) == 1) {
		return true;
	}
	return false;
}

bool Socket::CheckPort(int port) noexcept {
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

Socket::Socket() : m_service() {
  {
    std::unique_lock lock(m_errorHandlerMutex);
    m_errorHandler = nullptr;
    m_errorHandlerFaulted.store(true, std::memory_order_release);
  }
  {
    std::unique_lock lock(m_updateHandlerMutex);
    m_updateHandler = nullptr;
  }
  m_thisSocket = INVALID_SOCKET;
  m_ip = "127.0.0.1";
  m_portNum = 55555;
  SetRegistered(false);
  SetActive(false);
  SetConfigured(false);
  SetClosing(false);
  m_messageLength = 1000;
}

bool Socket::Initialize(int socketType) {
	if(!RegisterWSA()) {
		ErrorInterpreter("Error initializing socket: failed to register WSA", false);
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
  } else {
    ErrorInterpreter("Error initializing socket: unrecognized socket type", false);
    UnregisterWSA();
    return false;
  }
	UpdateInterpreter("Initializing " + typeName + " socket " + m_ip + ":" + std::to_string(m_portNum));
	m_thisSocket = socket(AF_INET, socketType, protocol);
	if(m_thisSocket == INVALID_SOCKET) {
		ErrorInterpreter("Error initializing socket: ", true);
		UnregisterWSA();
		return false;
	}
	m_service.sin_family = AF_INET;
	if(inet_pton(AF_INET, m_ip.c_str(), &m_service.sin_addr) != 1) {
		ErrorInterpreter("Error initializing socket: ", true);
		UnregisterWSA();
		return false;
	}
	m_service.sin_port = htons(m_portNum);
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
void Socket::StopWorkers() noexcept {
  m_workers.StopWorkers();
}

bool Socket::StopRequested() const noexcept {
  return m_workers.StopRequested();
}

bool Socket::WaitForWorkers() noexcept {
  return m_workers.WaitForWorkers();
}

int Socket::ActiveWorkerCount() const noexcept {
  return m_workers.ActiveWorkerCount();
}

bool Socket::UnregisterWSA() {
	CloseSocketSafe(m_thisSocket, true);
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

std::string Socket::GetSocketAddress(const SOCKET& socket) {
	std::string socketIP = GetSocketIP(socket);
	int socketPort = GetSocketPort(socket);
  if(socketIP.empty() || socketPort == INVALID_PORT) {
    return std::string();
  }
	return ConstructAddress(socketIP, socketPort);
	
}

std::string Socket::GetSocketAddress(const sockaddr_in& socket) {
	std::string socketIP = GetSocketIP(socket);
	int socketPort = GetSocketPort(socket);
  if(socketIP.empty() || socketPort == INVALID_PORT) {
    return std::string();
  }
	return ConstructAddress(socketIP, socketPort);
}

std::string Socket::GetSocketIP(const SOCKET& socket) {
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

bool Socket::ParseSocketAddress(const std::string& address, int socketType, sockaddr_in& out) {
  auto delimiterPos = address.rfind(':');
  if(delimiterPos == std::string::npos || delimiterPos == address.size() - 1) {
    return false;
  }
  const std::string ip = address.substr(0, delimiterPos);
  const std::string port = address.substr(delimiterPos + 1);
  addrinfo hints = {};
  hints.ai_family = AF_INET;
  if(socketType == SOCK_DGRAM) {
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
  } else if(socketType == SOCK_STREAM) {
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
  } else {
    return false;
  }
  addrinfo* result = nullptr;
  const int error = getaddrinfo(ip.c_str(), port.c_str(), &hints, &result);
  if(error != 0 || !result) {
    return false;
  }
  bool found = false;
  for(addrinfo* addressInfo = result; addressInfo != nullptr; addressInfo = addressInfo->ai_next) {
    if(addressInfo->ai_family == AF_INET) {
      std::memcpy(&out, addressInfo->ai_addr, sizeof(sockaddr_in));
      found = true;
      break;
    }
  }
  freeaddrinfo(result);
  return found;
}

int Socket::GetSocketPort(const SOCKET& socket) noexcept {
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

int Socket::GetSocketPort(const sockaddr_in& addr) noexcept {
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
  return address.s_addr == INADDR_BROADCAST;
}
