#include "pch.h"
#include "SocketLibrary/UDPServerSocket.h"

UDPServerSocket::UDPServerSocket() : m_target() {
	{
		std::unique_lock lock(m_onReadMutex);
		m_onRead = nullptr;
	}
  m_target = {};
}

UDPServerSocket::~UDPServerSocket() noexcept {
	Close();
	{
		std::unique_lock lock(m_onReadMutex);
		m_onRead = nullptr;
	}
}

void UDPServerSocket::SetOnRead(std::function<void(unsigned char* message, int byteCount, sockaddr_in sender)> onRead) {
  {
    std::unique_lock lock(m_onReadMutex);
    m_onRead = std::move(onRead);
  }
}

bool UDPServerSocket::Open() {
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
		UnregisterWSA();
		return false;
	}
	UpdateInterpreter("Binding Successful!");
	m_configured = true;
	UpdateInterpreter("Preparing To Listen For Messages");
  uintptr_t threadPtr = _beginthreadex(nullptr, 0, &UDPServerSocket::StaticMessageHandler, this, 0, nullptr);
  HANDLE threadHandle = reinterpret_cast<HANDLE>(threadPtr);
  if(!threadHandle) {
    ErrorInterpreter("Thread creation error: ", true);
    UnregisterWSA();
    return false;
  }
  CloseHandle(threadHandle);
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

unsigned __stdcall UDPServerSocket::StaticMessageHandler(void* arg) {
  auto* serverSocket = static_cast<UDPServerSocket*>(arg);
  if(serverSocket) {
    serverSocket->MessageHandler();
  }
  return 0;
}

void UDPServerSocket::MessageHandler() {
	m_active.store(true, std::memory_order_release);
  int lastMessageLength = -1;
  std::vector<unsigned char> buffer;
	while(true) {
    int messageLength = GetMessageLength();
    if(messageLength != lastMessageLength) {
      buffer.resize(messageLength);
      lastMessageLength = messageLength;
    }
		sockaddr_in clientAddr;
		int addrLen = sizeof(clientAddr);
		int byteCount = ::recvfrom(
			m_thisSocket,
			reinterpret_cast<char*>(buffer.data()),
			m_messageLength,
			0,
			(sockaddr*)&clientAddr,
			&addrLen
		);
		if(!m_active.load(std::memory_order_acquire)) {
			break;
		}
		if(byteCount >= 0) {
			UpdateInterpreter("Received " + std::to_string(byteCount) + " Bytes");
			OnRead(buffer.data(), byteCount, clientAddr);
      continue;
		}
		ErrorInterpreter("Error Receiving Message: ", true);
		break;
	}
}

int UDPServerSocket::Send(const void* bytes, size_t byteCount, const std::string& targetIP, const std::string& targetPort) {
  return Send(bytes, byteCount, ConstructAddress(targetIP, targetPort));
}

int UDPServerSocket::Send(const void* bytes, size_t byteCount, const std::string& targetIP, int targetPort) {
  return Send(bytes, byteCount, ConstructAddress(targetIP, targetPort));
}

int UDPServerSocket::Send(const void* bytes, size_t byteCount, const std::string& targetAddress) {
  if(targetAddress.empty()) {
    ErrorInterpreter("Send error: invalid target address", false);
    return 0;
  }
  sockaddr_in target{};
  if(!ParseSocketAddress(targetAddress, SOCK_DGRAM, target)) {
    ErrorInterpreter("Send error: invalid target address format", false);
    return 0;
  }
  return Send(bytes, byteCount, target);
}

int UDPServerSocket::Send(const void* bytes, size_t byteCount, const sockaddr_in& target) {
  if(!IsValidEndpointIPv4(target)) {
    ErrorInterpreter("Send error: invalid target address", false);
    return 0;
  }
  {
    std::unique_lock lock(m_targetMutex);
    m_target = target;
  }
  return Send(bytes, byteCount);
}

int UDPServerSocket::Send(const void* bytes, size_t byteCount) {
  if(!bytes || byteCount == 0) {
    ErrorInterpreter("Send error: invalid buffer/length", false);
    return 0;
  }
  if(byteCount > static_cast<size_t>(std::numeric_limits<int>::max())) {
    ErrorInterpreter("Send error: payload too large for WinSock", false);
    return 0;
  }
  bool configured = m_configured.load(std::memory_order_acquire);
  bool registered = m_wsaRegistered.load(std::memory_order_acquire);
  if(!(configured && registered && m_thisSocket != INVALID_SOCKET)) {
    ErrorInterpreter("Send error: socket is not initialized/connected", false);
    return 0;
  }
  sockaddr_in target{};
  {
    std::shared_lock lock(m_targetMutex);
    target = m_target;
  }
  if(!IsValidEndpointIPv4(target)) {
    ErrorInterpreter("Send error: invalid target address", false);
    return 0;
  }
  UpdateInterpreter("Sending message to: " + GetSocketAddress(target) + " - " + std::to_string(byteCount) + " bytes");
  const int totalBytes = static_cast<int>(byteCount);
  const int sentBytes = SendAll(target, static_cast<const char*>(bytes), totalBytes);
  if(sentBytes != totalBytes) {
    ErrorInterpreter("Error sending message: ", true);
  } else {
    UpdateInterpreter("Successfully sent message");
  }
  return sentBytes;
}

int UDPServerSocket::SendAll(sockaddr_in socket, const char* buffer, int bufferSize) {
  int totalSent = 0;
  while(totalSent < bufferSize) {
    const int sentBytes = ::sendto(
      m_thisSocket,
      buffer + totalSent,
      bufferSize - totalSent,
      0,
      reinterpret_cast<SOCKADDR*>(&socket),
      sizeof(socket)
    );
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
      //Not sure what this indicates on UDP?
      return totalSent;
    }
    totalSent += sentBytes;
  }
  return totalSent;
}

void UDPServerSocket::OnRead(unsigned char* message, int byteCount, sockaddr_in sender) {
  std::function<void(unsigned char* message, int byteCount, sockaddr_in sender)> callback;
  {
    std::unique_lock lock(m_onReadMutex);
    callback = m_onRead;
  }
  if(!callback) {
    std::string update = "Received message";
    update += " from " + GetSocketAddress(sender);
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
