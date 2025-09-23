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
	m_connected.store(false, std::memory_order_relaxed);
	m_connectionDelay.store(5, std::memory_order_relaxed);
	m_cancelConnect.store(false, std::memory_order_relaxed);
  m_connecting.store(false, std::memory_order_relaxed);
}

TCPClientSocket::~TCPClientSocket() noexcept {
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

int TCPClientSocket::GetConnectionDelay() const noexcept {
	return m_connectionDelay.load(std::memory_order_acquire);
}

bool TCPClientSocket::SetConnectionDelay(int connectionDelay) {
	if(connectionDelay >= 1) {
		m_connectionDelay = connectionDelay;
		UpdateInterpreter("Successfully set connection delay: " + std::to_string(connectionDelay));
		return true;
	} else {
		ErrorInterpreter("Error: Connection delay attempt '" + std::to_string(connectionDelay) + "' is not valid (must be a number > 0)", false);
		return false;
	}
}

bool TCPClientSocket::SetConnectionDelay(const std::string& connectionDelay) {
	int connDelayAttempt = 0;
	if(StringToInt(connectionDelay, &connDelayAttempt)) {
		return SetConnectionDelay(connDelayAttempt);
	} else {
		ErrorInterpreter("Error parsing connection delay value from '" + connectionDelay + "'", false);
		return false;
	}
}

bool TCPClientSocket::GetConnected() const noexcept {
	return m_connected.load(std::memory_order_acquire);
}

bool TCPClientSocket::GetConnecting() const noexcept {
	return m_connecting.load(std::memory_order_acquire);
}

bool TCPClientSocket::Open() {
	m_cancelConnect.store(false, std::memory_order_release);
	if(Initialize(SOCK_STREAM)) {
		m_closeAttempt.store(false, std::memory_order_release);
    m_configured.store(true, std::memory_order_release);
		UpdateInterpreter("Ready to connect");
    uintptr_t threadPtr = _beginthreadex(nullptr, 0, &TCPClientSocket::StaticConnect, this, 0, nullptr);
    HANDLE threadHandle = reinterpret_cast<HANDLE>(threadPtr);
    if(!threadHandle) {
      ErrorInterpreter("Thread creation error: ", true);
      UnregisterWSA();
      return false;
    }
    CloseHandle(threadHandle);
    return true;
	} else {
		UpdateInterpreter("Error initializing socket");
		return false;
	}
}

bool TCPClientSocket::Close() {
  m_active.store(false, std::memory_order_release);
  m_closeAttempt.store(true, std::memory_order_release);
  UpdateInterpreter("Closing client socket");
  m_cancelConnect.store(true, std::memory_order_release);
  m_connecting.store(false, std::memory_order_release);
  const bool wasConnected = m_connected.exchange(false, std::memory_order_acq_rel);
  const bool socketClosed = CloseSocketSafe(m_thisSocket, wasConnected);
  if(wasConnected) {
    OnDisconnect();
  }
  m_configured.store(false, std::memory_order_release);
  const bool wsaUnregistered = UnregisterWSA();
  return socketClosed && wsaUnregistered;
}

bool TCPClientSocket::ReadyToConnect() const noexcept {
  const bool configured = m_configured.load(std::memory_order_acquire);
  const bool wsaRegistered = m_wsaRegistered.load(std::memory_order_acquire);
  const bool connected = m_connected.load(std::memory_order_acquire);
  return configured && wsaRegistered && m_thisSocket != INVALID_SOCKET && !connected;
}

unsigned __stdcall TCPClientSocket::StaticConnect(void* arg) {
  auto* clientSocket = static_cast<TCPClientSocket*>(arg);
  if(clientSocket) {
    clientSocket->Connect();
  }
  return 0;
}

void TCPClientSocket::Connect() {
	UpdateInterpreter("Attempting socket connection");
  if(!ReadyToConnect()) {
    ErrorInterpreter("Socket not initialized", false);
    return;
  }
  while(ReadyToConnect()) {
    m_connecting.store(true, std::memory_order_release);
    while(!m_connected.load(std::memory_order_acquire) && !m_cancelConnect.load(std::memory_order_acquire)) {
      if(::connect(m_thisSocket, reinterpret_cast<SOCKADDR*>(&m_service), sizeof(m_service)) != SOCKET_ERROR) {
        m_connected.store(true, std::memory_order_release);
        m_active.store(true, std::memory_order_release);
        UpdateInterpreter("Client connected!");
        break;
      }
      ErrorInterpreter("Error connecting to socket: ", true);
      const int delay = m_connectionDelay.load(std::memory_order_relaxed);
      UpdateInterpreter("Trying again in " + std::to_string(delay) + " seconds");
      std::this_thread::sleep_for(std::chrono::seconds(delay));
    }
    m_connecting.store(false, std::memory_order_release);
    if(m_cancelConnect.load(std::memory_order_acquire)) {
      UpdateInterpreter("Connection attempt cancelled");
      return;
    }
    while(m_connected.load(std::memory_order_acquire)) {
      if(!MessageHandler()) {
        break;
      }
    }
    if(!m_cancelConnect.load(std::memory_order_acquire)) {
      CloseSocketSafe(m_thisSocket, false);
      if(!Initialize(SOCK_STREAM)) {
        ErrorInterpreter("Reconnect: reinitialization failed", false);
        return;
      }
    }
  }
}

bool TCPClientSocket::MessageHandler() {
  static thread_local int lastMessageLength = -1;
  static thread_local std::vector<unsigned char> buffer;
  const int messageLength = GetMessageLength();
  if(messageLength != lastMessageLength) {
    buffer.resize(messageLength);
    lastMessageLength = messageLength;
  }
  const int byteCount = ::recv(m_thisSocket, reinterpret_cast<char*>(buffer.data()), messageLength, 0);
  if(byteCount > 0) {
    UpdateInterpreter("Received " + std::to_string(byteCount) + " bytes");
    OnRead(buffer.data(), byteCount);
    return true;
  }
  if(byteCount == 0) {
    UpdateInterpreter("Connection closed by server");
  } else {
    ErrorInterpreter("Error checking connection: ", true);
  }
  OnDisconnect();
  return false;
}

int TCPClientSocket::Send(const void* bytes, size_t byteCount) {
  if(!bytes || byteCount == 0) {
    ErrorInterpreter("Send(bytes): invalid buffer/length", false);
    return 0;
  }
  if(byteCount > static_cast<size_t>(std::numeric_limits<int>::max())) {
    ErrorInterpreter("Send(bytes): payload too large for WinSock", false);
    return 0;
  }
  bool configured = m_configured.load(std::memory_order_acquire);
  bool registered = m_wsaRegistered.load(std::memory_order_acquire);
  bool connected = m_connected.load(std::memory_order_acquire);
  if(!(configured && registered && connected && m_thisSocket != INVALID_SOCKET)) {
    ErrorInterpreter("Socket is not initialized/connected", false);
    return 0;
  }
  UpdateInterpreter("Sending message - " + std::to_string(byteCount) + " Bytes");
  const int totalBytes = static_cast<int>(byteCount);
  const int sentBytes = SendAll(static_cast<const char*>(bytes), totalBytes);
  if(sentBytes != totalBytes) {
    ErrorInterpreter("Error sending message: ", true);
  } else {
    UpdateInterpreter("Successfully sent message");
  }
  return sentBytes;
}

int TCPClientSocket::SendAll(const char* buffer, int bufferSize) {
  int totalSent = 0;
  while(totalSent < bufferSize) {
    const int sentBytes = ::send(m_thisSocket, buffer + totalSent, bufferSize - totalSent, 0);
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

void TCPClientSocket::OnDisconnect() {
	m_connected.store(false, std::memory_order_release);
  std::function<void()> callback;
  {
    std::shared_lock lock(m_onDisconnectMutex);
    callback = m_onDisconnect;
  }
  if(!callback) {
    UpdateInterpreter("Disconnected");
    return;
  }
  try {
    callback();
  } catch(const std::exception& e) {
    ErrorInterpreter(std::string("OnDisconnect callback exception: ") + e.what(), false);
  } catch(...) {
    ErrorInterpreter("OnDisconnect callback exception: unknown", false);
  }
}

void TCPClientSocket::OnRead(unsigned char* message, int byteCount) {
  std::function<void(unsigned char* message, int byteCount)> callback;
  {
    std::shared_lock lock(m_onReadMutex);
    callback = m_onRead;
  }
  if(!callback) {
    UpdateInterpreter("Received message");
    return;
  }
  try {
    callback(message, byteCount);
  } catch(const std::exception& e) {
    ErrorInterpreter(std::string("OnRead callback exception: ") + e.what(), false);
  } catch(...) {
    ErrorInterpreter("OnRead callback exception: unknown", false);
  }
}
