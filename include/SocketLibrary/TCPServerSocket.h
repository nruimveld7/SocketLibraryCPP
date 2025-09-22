#pragma once

#include "SocketLibrary/WinSock2First.h"
#include <string>
#include <vector>
#include <functional>
#include <shared_mutex>
#include <unordered_set>
#include <mutex>
#include <exception>
#include <type_traits>
#include "SocketLibrary/Socket.h"

class TCPServerSocket : public Socket {
public:
	TCPServerSocket();
	~TCPServerSocket();
	void SetOnClientDisconnect(std::function<void()> onClientDisconnect);
	void SetOnRead(std::function<void(unsigned char* message, int byteCount, SOCKET sender)> onRead);
	int GetListenBacklog() const;
	bool SetListenBacklog(int newSize);
	bool SetListenBacklog(const std::string& newSize);
	int GetMaxConnections() const;
	bool SetMaxConnections(int newMax);
	bool SetMaxConnections(const std::string& newMax);
	size_t GetNumConnections() const;
	bool Open();
	bool Close();
	std::vector<std::string> GetClientAddresses() const;
  void SetNoDelay(bool enabled, bool applyToAll = false) noexcept;
  void SetKeepAlive(bool enabled, DWORD timeMs = 30'000, DWORD intervalMs = 10'000, bool applyToAll = false) noexcept;
  void Broadcast(const void* bytes, size_t byteCount);
  int Send(const void* bytes, size_t byteCount, const std::string& targetAddress);
  int Send(const void* bytes, size_t byteCount); // requires exactly 1 connection
  int Send(const void* bytes, size_t byteCount, SOCKET target);

	template <typename T>
	void Broadcast(const T* buffer, size_t bufferSize) {
    static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable");
    const size_t bytes = bufferSize * sizeof(T);
    Broadcast(static_cast<const void*>(buffer), bytes);
	}

  template <typename T>
  int Send(const T* buffer, size_t bufferSize, const std::string& targetIP, int targetPort) {
    static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable");
    const size_t bytes = bufferSize * sizeof(T);
    const std::string address = ConstructAddress(targetIP, targetPort);
    return Send(static_cast<const void*>(buffer), bytes, address);
  }

  template <typename T>
  int Send(const T* buffer, size_t bufferSize, const std::string& targetAddress) {
    static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable");
    const size_t bytes = bufferSize * sizeof(T);
    return Send(static_cast<const void*>(buffer), bytes, targetAddress);
  }

  template <typename T>
  int Send(const T* buffer, size_t bufferSize) {
    static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable");
    const size_t bytes = bufferSize * sizeof(T);
    return Send(static_cast<const void*>(buffer), bytes);
  }

  template <typename T>
  int Send(const T* buffer, size_t bufferSize, SOCKET target) {
    static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable");
    const size_t bytes = bufferSize * sizeof(T);
    return Send(static_cast<const void*>(buffer), bytes, target);
  }

private:
  struct SocketOptions {
    bool noDelay = true;
    bool keepAlive = false;
    DWORD keepAliveTimeMs = 30'000;
    DWORD keepAliveIntervalMs = 10'000;
  } m_socketOptions;
	struct MessageHandlerParams {
		TCPServerSocket* serverSocket;
		SOCKET clientSocket;
	};
  bool ReadyToAccept() const noexcept;
  static unsigned __stdcall StaticAcceptConnection(void* arg);
	void AcceptConnection();
	void RegisterClient(SOCKET socket);
  bool ApplySocketOptions(SOCKET socket) noexcept;
  static unsigned __stdcall StaticMessageHandler(void* arg);
	void MessageHandler(SOCKET acceptSocket);
  int SendAll(SOCKET s, const char* data, int total);
	bool CloseClientSocket(SOCKET clientSocket);
	void OnClientDisconnect();
	void OnRead(unsigned char* message, int byteCount, SOCKET sender);
	std::unordered_set<SOCKET> m_connections;
	mutable std::shared_mutex m_connectionsMutex;
	std::atomic<int> m_listenBacklog;
	std::atomic<int> m_maxConnections;
	std::function<void()> m_onClientDisconnect;
	std::shared_mutex m_onClientDisconnectMutex;
	std::function<void(unsigned char* message, int byteCount, SOCKET sender)> m_onRead;
	std::shared_mutex m_onReadMutex;
};
