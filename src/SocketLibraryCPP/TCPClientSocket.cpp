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
		ErrorInterpreter("Error: connection delay attempt '" + std::to_string(connectionDelay) + "' is not valid (must be a number > 0)", false);
		return false;
	}
}

bool TCPClientSocket::SetConnectionDelay(const std::string& connectionDelay) {
	int connDelayAttempt = 0;
	if(StringToInt(connectionDelay, connDelayAttempt)) {
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
  //1) Create the TCP socket
  SetCancelling(false);
  if(!Initialize(Protocol::TCP)) {
    ErrorInterpreter("Error initializing socket", false);
    Close();
    return false;
  }
  if(m_thisSocket == INVALID_SOCKET) {
    ErrorInterpreter("Socket no longer initialized", false);
    Close();
    return false;
  }
  //2) Attempt to connect to server socket
  SetConfigured(true);
  SetClosing(false);
	UpdateInterpreter("Ready to connect");
  if(!StartWorker(&TCPClientSocket::StaticConnect, this)) {
    ErrorInterpreter("Thread creation error: ", true);
    Close();
    return false;
  }
  return true;
}

bool TCPClientSocket::Close() {
  return Socket::Close();
}

bool TCPClientSocket::ReadyToConnect() const noexcept {
  const bool configured = IsConfigured();
  const bool registered = IsRegistered();
  const bool connected = IsConnected();
  return !connected && configured && registered && m_thisSocket != INVALID_SOCKET;
}

unsigned __stdcall TCPClientSocket::StaticConnect(void* arg) noexcept {
  auto* clientSocket = static_cast<TCPClientSocket*>(arg);
  if(clientSocket) {
    clientSocket->Connect();
  }
  return 0;
}

void TCPClientSocket::Connect() {
  while(ReadyToConnect() && !StopRequested()) {
    //Try to connect (retry inside ConnectAttempt)
    if(!IsConnected() && !IsCancelling()) {
      if(!ConnectAttempt()) {
        if(StopRequested() || IsCancelling()) {
          return;
        }
        if(!ReadyToConnect()) {
          return;
        }
        continue;
      }
    }
    //Process messages while connected
    while(IsConnected() && !StopRequested()) {
      if(!MessageHandler()) {
        break;
      }
    }
    if(StopRequested() || IsCancelling()) {
      return;
    }
    //Reinitialize for reconnect and loop
    CloseSocketSafe(m_thisSocket, false);
    if(!Initialize(Protocol::TCP)) {
      ErrorInterpreter("Reconnect: reinitialization failed", false);
      return;
    }
    SetConfigured(true);
  }
}

bool TCPClientSocket::ConnectAttempt() {
  if(m_thisSocket == INVALID_SOCKET) {
    ErrorInterpreter("Socket no longer initialized", false);
    Close();
    return false;
  }
  SetConnecting(true);
  UpdateInterpreter("Attempting socket connection");
  while(!IsCancelling() && !StopRequested() && ReadyToConnect()) {
    if(IsConnected()) {
      SetConnecting(false);
      return true;
    }
    sockaddr_in address{};
    int addressSize = sizeof(address);
    if(!GetServiceAddress(Protocol::TCP, address)) {
      ErrorInterpreter("Invalid server IP/Port", false);
      Close();
      return false;
    }
    if(::connect(m_thisSocket, reinterpret_cast<SOCKADDR*>(&address), addressSize) != SOCKET_ERROR) {
      SetConnected(true);
      SetActive(true);
      SetConnecting(false);
      UpdateInterpreter("Client connected!");
      return true;
    }
    ErrorInterpreter("Error connecting to socket: ", true);
    if(m_thisSocket == INVALID_SOCKET) {
      ErrorInterpreter("Socket no longer initialized", false);
      SetConnecting(false);
      Close();
      return false;
    }
    int delay = m_connectionDelay.load(std::memory_order_relaxed);
    if(delay <= 0) {
      delay = 1;
    }
    for(int i = 0; i < delay; ++i) {
      if(IsCancelling() || StopRequested()) {
        SetConnecting(true);
        return false;
      }
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }
  }
  SetConnecting(false);
  return false;
}

bool TCPClientSocket::MessageHandler() {
  static thread_local int lastMessageLength = -1;
  static thread_local std::vector<unsigned char> buffer;
  const int messageLength = GetMessageLength();
  if(messageLength <= 0) {
    ErrorInterpreter("Invalid message length: " + std::to_string(messageLength), false);
    OnDisconnect();
    return false;
  }
  if(messageLength != lastMessageLength) {
    buffer.resize(messageLength);
    lastMessageLength = messageLength;
  }
  const int byteCount = ::recv(m_thisSocket, reinterpret_cast<char*>(buffer.data()), messageLength, 0);
  if(byteCount > 0) {
    TrafficUpdate("Received " + std::to_string(byteCount) + " bytes");
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
  if(!(IsConfigured() && IsRegistered() && IsConnected() && m_thisSocket != INVALID_SOCKET)) {
    ErrorInterpreter("Socket is not initialized/connected", false);
    return 0;
  }
  TrafficUpdate("Sending message - " + std::to_string(byteCount) + " Bytes");
  const int totalBytes = static_cast<int>(byteCount);
  const int sentBytes = SendAll(static_cast<const char*>(bytes), totalBytes);
  if(sentBytes != totalBytes) {
    ErrorInterpreter("Error sending message: ", true);
  } else {
    TrafficUpdate("Successfully sent message");
  }
  return sentBytes;
}

int TCPClientSocket::SendAll(const char* buffer, int bufferSize) {
  int totalSent = 0;
  while(totalSent < bufferSize) {
    const int sentBytes = ::send(m_thisSocket, buffer + totalSent, bufferSize - totalSent, 0);
    if(sentBytes == SOCKET_ERROR) {
      const int err = WSAGetLastError();
      if(err == WSAEINTR) {
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

bool TCPClientSocket::IsConnected() const noexcept {
  return m_connected.load(std::memory_order_acquire);
}

void TCPClientSocket::SetConnected(bool connected) noexcept {
  m_connected.store(connected, std::memory_order_release);
}

bool TCPClientSocket::IsCancelling() const noexcept {
  return m_cancelConnect.load(std::memory_order_acquire);
}

void TCPClientSocket::SetCancelling(bool cancelling) noexcept {
  m_cancelConnect.store(cancelling, std::memory_order_release);
}

bool TCPClientSocket::IsConnecting() const noexcept {
  return m_connecting.load(std::memory_order_acquire);
}

void TCPClientSocket::SetConnecting(bool connecting) noexcept {
  m_connecting.store(connecting, std::memory_order_release);
}

bool TCPClientSocket::Cleanup() {
  UpdateInterpreter("Closing client socket");
  SetCancelling(true);
  SetConnecting(false);
  const bool wasConnected = m_connected.exchange(false, std::memory_order_acq_rel);
  const bool socketClosed = CloseSocketSafe(m_thisSocket, wasConnected);
  if(wasConnected) {
    OnDisconnect();
  }
  return socketClosed;
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
