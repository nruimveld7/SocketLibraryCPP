#pragma once

#include "SocketLibrary/WinSock2First.h"
#include <string>
#include <vector>
#include <functional>
#include <shared_mutex>
#include <unordered_set>
#include <cmath>
#include <limits>
#include <atomic>
#include <mutex>
#include <exception>
#include <type_traits>
#include "SocketLibrary/Socket.h"

class TCPServerSocket : public Socket {
public:
	TCPServerSocket();
	~TCPServerSocket() noexcept override;
	void SetOnClientDisconnect(std::function<void()> onClientDisconnect);
	void SetOnRead(std::function<void(unsigned char* message, int byteCount, SOCKET sender)> onRead);
	int GetListenBacklog() const noexcept;
	bool SetListenBacklog(int newSize);
	bool SetListenBacklog(const std::string& newSize);
	int GetMaxConnections() const noexcept;
	bool SetMaxConnections(int newMax);
	bool SetMaxConnections(const std::string& newMax);
	size_t GetNumConnections() const noexcept;
	bool Open();
	bool Close();
	std::vector<std::string> GetClientAddresses() const;
  void SetNoDelay(bool enabled, bool applyToAll = false) noexcept;
  void SetKeepAlive(bool enabled, DWORD timeMs = 30'000, DWORD intervalMs = 10'000, bool applyToAll = false) noexcept;

	template <typename T>
	void Broadcast(const T* buffer, size_t bufferSize) {
    static_assert(!std::is_void_v<T>, "T cannot be void");
    static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable");
    const size_t bytes = bufferSize * sizeof(T);
    Broadcast(static_cast<const void*>(buffer), bytes);
	}

  template <typename T>
  int Send(const T* buffer, size_t bufferSize, const std::string& targetIP, const std::string& targetPort) {
    static_assert(!std::is_void_v<T>, "T cannot be void");
    static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable");
    if(bufferSize > (std::numeric_limits<size_t>::max() / sizeof(T))) {
      ErrorInterpreter("Send error: payload too large for WinSock", false);
      return 0;
    }
    const size_t bytes = bufferSize * sizeof(T);
    return Send(static_cast<const void*>(buffer), bytes, targetIP, targetPort);
  }

  template <typename T>
  int Send(const T* buffer, size_t bufferSize, const std::string& targetIP, int targetPort) {
    static_assert(!std::is_void_v<T>, "T cannot be void");
    static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable");
    if(bufferSize > (std::numeric_limits<size_t>::max() / sizeof(T))) {
      ErrorInterpreter("Send error: payload too large for WinSock", false);
      return 0;
    }
    const size_t bytes = bufferSize * sizeof(T);
    return Send(static_cast<const void*>(buffer), bytes, targetIP, targetPort);
  }

  template <typename T>
  int Send(const T* buffer, size_t bufferSize, const std::string& targetAddress) {
    static_assert(!std::is_void_v<T>, "T cannot be void");
    static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable");
    if(bufferSize > (std::numeric_limits<size_t>::max() / sizeof(T))) {
      ErrorInterpreter("Send error: payload too large for WinSock", false);
      return 0;
    }
    const size_t bytes = bufferSize * sizeof(T);
    return Send(static_cast<const void*>(buffer), bytes, targetAddress);
  }

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

  template <typename T>
  int Send(const T* buffer, size_t bufferSize, SOCKET target) {
    static_assert(!std::is_void_v<T>, "T cannot be void");
    static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable");
    if(bufferSize > (std::numeric_limits<size_t>::max() / sizeof(T))) {
      ErrorInterpreter("Send error: payload too large for WinSock", false);
      return 0;
    }
    const size_t bytes = bufferSize * sizeof(T);
    return Send(static_cast<const void*>(buffer), bytes, target);
  }

private:
  struct SocketOptions {
    bool noDelay = true;
    bool keepAlive = false;
    DWORD keepAliveTimeMs = 30'000;
    DWORD keepAliveIntervalMs = 10'000;
  };
	struct MessageHandlerParams {
		TCPServerSocket* serverSocket;
		SOCKET clientSocket;
	};
  bool ReadyToAccept() const noexcept;
  static unsigned __stdcall StaticAcceptConnection(void* arg);
	void AcceptConnection();
	void RegisterClient(SOCKET socket);
  bool ApplySocketOptions(SOCKET socket) noexcept;
  void UpdateConnectionBuckets(size_t desiredSize);
  static unsigned __stdcall StaticMessageHandler(void* arg);
	void MessageHandler(SOCKET acceptSocket);
  void Broadcast(const void* bytes, size_t byteCount);
  int Send(const void* bytes, size_t byteCount, const std::string& targetIP, const std::string& targetPort);
  int Send(const void* bytes, size_t byteCount, const std::string& targetIP, int targetPort);
  int Send(const void* bytes, size_t byteCount, const std::string& targetAddress);
  int Send(const void* bytes, size_t byteCount);
  int Send(const void* bytes, size_t byteCount, SOCKET target);
  int SendAll(SOCKET socket, const char* buffer, int bufferSize);
	bool CloseClientSocket(SOCKET clientSocket);
	void OnClientDisconnect();
	void OnRead(unsigned char* message, int byteCount, SOCKET sender);
	std::unordered_set<SOCKET> m_connections;
	mutable std::shared_mutex m_connectionsMutex;
	std::atomic<int> m_listenBacklog;
	std::atomic<int> m_maxConnections;
  SocketOptions m_socketOptions;
  std::shared_mutex m_socketOptionsMutex;
	std::function<void()> m_onClientDisconnect;
	std::shared_mutex m_onClientDisconnectMutex;
	std::function<void(unsigned char* message, int byteCount, SOCKET sender)> m_onRead;
	std::shared_mutex m_onReadMutex;
};
