#pragma once

#include "SocketLibrary/WinSock2First.h"
#include <string>
#include <functional>
#include <shared_mutex>
#include <atomic>
#include <type_traits>
#include "SocketLibrary/Socket.h"

class TCPClientSocket : public Socket {
public:
	TCPClientSocket();
	~TCPClientSocket() noexcept override;
	void SetOnDisconnect(std::function<void()> onDisconnect);
	void SetOnRead(std::function<void(unsigned char* message, int byteCount)> onRead);
	int GetConnectionDelay() const noexcept;
	bool SetConnectionDelay(int newDelay);
	bool SetConnectionDelay(const std::string& newDelay);
	bool GetConnected() const noexcept;
	bool GetConnecting() const noexcept;
	bool Open();
	bool Close();

	template <typename T>
	int Send(const T* buffer, size_t bufferSize) {
    static_assert(!std::is_void_v<T>, "T cannot be void");
    static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable");
    if(bufferSize > (std::numeric_limits<size_t>::max() / sizeof(T))) {
      ErrorInterpreter("Send error: payload too large for WinSock", false);
      return 0;
    }
    const size_t bytes = bufferSize * sizeof(T);
    return Send(static_cast<const void*>(buffer), bytes);
	}

private:
  bool ReadyToConnect() const noexcept;
  static unsigned __stdcall StaticConnect(void* arg);
	void Connect();
	bool MessageHandler();
  int Send(const void* bytes, size_t byteCount);
  int SendAll(const char* buffer, int bufferSize);
	void OnDisconnect();
	void OnRead(unsigned char* message, int byteCount);
	std::atomic<bool> m_connected;
	std::atomic<int> m_connectionDelay;
	std::atomic<bool> m_cancelConnect;
	std::atomic<bool> m_connecting;
	std::function<void()> m_onDisconnect;
	std::shared_mutex m_onDisconnectMutex;
	std::function<void(unsigned char* message, int byteCount)> m_onRead;
	std::shared_mutex m_onReadMutex;
};
