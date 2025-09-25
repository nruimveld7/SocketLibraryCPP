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
		ErrorInterpreter("Error initializing socket", false);
		return false;
	}
	if(m_target.sin_family == AF_UNSPEC) {
		m_target = m_service;
	}
	UpdateInterpreter("Binding socket");
	if(bind(m_thisSocket, (SOCKADDR*)&m_service, sizeof(m_service)) == SOCKET_ERROR) {
		ErrorInterpreter("Socket binding error: ", true);
		UnregisterWSA();
		return false;
	}
	UpdateInterpreter("Binding successful!");
  SetConfigured(true);
	UpdateInterpreter("Preparing to listen for messages");
  if(!StartWorker(&UDPServerSocket::StaticMessageHandler, this)) {
    ErrorInterpreter("Thread creation error: ", true);
    UnregisterWSA();
    return false;
  }
	UpdateInterpreter("Ready to send messages");
	return true;
}

bool UDPServerSocket::Close() {
  return Socket::Close();
}

unsigned __stdcall UDPServerSocket::StaticMessageHandler(void* arg) noexcept {
  auto* serverSocket = static_cast<UDPServerSocket*>(arg);
  if(serverSocket) {
    serverSocket->MessageHandler();
  }
  return 0;
}

void UDPServerSocket::MessageHandler() {
  SetActive(true);
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
			messageLength,
			0,
			(sockaddr*)&clientAddr,
			&addrLen
		);
		if(!IsActive()) {
			break;
		}
		if(byteCount >= 0) {
			UpdateInterpreter("Received " + std::to_string(byteCount) + " bytes");
			OnRead(buffer.data(), byteCount, clientAddr);
      continue;
		}
		ErrorInterpreter("Error receiving message: ", true);
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
  if(!(IsConfigured() && IsRegistered()  && m_thisSocket != INVALID_SOCKET)) {
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

bool UDPServerSocket::Cleanup() {
  UpdateInterpreter("Closing server socket");
  const bool socketClosed = CloseSocketSafe(m_thisSocket, false);
  return socketClosed;
}

void UDPServerSocket::OnRead(unsigned char* message, int byteCount, sockaddr_in sender) {
  std::function<void(unsigned char* message, int byteCount, sockaddr_in sender)> callback;
  {
    std::shared_lock lock(m_onReadMutex);
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
