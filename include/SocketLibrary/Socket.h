#pragma once

#include "SocketLibrary/WinSock2First.h"
#include <string>
#include <functional>
#include <mutex>
#include <shared_mutex>
#include <atomic>

inline constexpr int INVALID_PORT = -1;

class Socket {
public:
	Socket();
	virtual ~Socket() noexcept;
  //Non-copyable: prevent accidental double-close / slicing.
  Socket(const Socket&) = delete;
  Socket& operator=(const Socket&) = delete;
  //Movable: transfer ownership of the OS handle and state.
  Socket(Socket&& other) noexcept;
  Socket& operator=(Socket&& other) noexcept;
	void SetErrorHandler(std::function<void(const std::string& errorMessage)> errorHandler);
	void SetUpdateHandler(std::function<void(const std::string& updateMessage)> updateHandler);
  std::string GetName() const;
  bool SetName(const std::string& name);
  std::string GetIP() const;
	bool SetIP(const std::string& ip);
  int GetPortNum() const noexcept;
	bool SetPortNum(int portNum);
	bool SetPortNum(const std::string& portNum);
  int GetMessageLength() const noexcept;
	bool SetMessageLength(int messageLength);
	bool SetMessageLength(const std::string& messageLength);
  bool GetActive() const noexcept;
	static bool CheckIP(const std::string& ip) noexcept;
  static bool CheckPort(int port) noexcept;
  static bool CheckPort(const std::string& port);
  bool operator==(const Socket& other) const noexcept {
    const SOCKET thisSocket = m_thisSocket;
    const SOCKET otherSocket = other.m_thisSocket;
    return thisSocket != INVALID_SOCKET && otherSocket != INVALID_SOCKET && thisSocket == otherSocket;
  }
  bool operator!=(const Socket& other) const noexcept {
    return !(*this == other);
  }

protected:
	bool Initialize(int socketType);
	bool RegisterWSA();
	bool UnregisterWSA();
	bool CloseSocketSafe(SOCKET& socketToClose, bool shutDownSocket);
	bool ShutDownSocket(SOCKET& socketToShutDown);
	void ErrorInterpreter(const std::string& errorMessage, bool hasCode);
	void UpdateInterpreter(const std::string& updateMessage);
  static std::string DecodeSocketError(int errorCode);
  static std::string ConstructAddress(const std::string& ip, const std::string& port);
  static std::string ConstructAddress(const std::string& ip, int port);
  static std::string GetSocketAddress(const SOCKET& client);
  static std::string GetSocketAddress(const sockaddr_in& addr);
  static std::string GetSocketIP(const SOCKET& socket);
  static std::string GetSocketIP(const sockaddr_in& addr);
  static bool ParseSocketAddress(const std::string& address, int socketType, sockaddr_in& out);
  static int GetSocketPort(const SOCKET& socket) noexcept;
  static int GetSocketPort(const sockaddr_in& addr) noexcept;
  static bool StringToInt(const std::string& convertToInt, int* outInt);
  static void FallbackLog(const char* msg) noexcept;
  static constexpr bool IsInitializedIPv4(const sockaddr_in& socketAddress) noexcept;
  static constexpr bool IsValidEndpointIPv4(const sockaddr_in& socketAddress) noexcept;
  static constexpr bool IsMulticastIPv4(const in_addr& address) noexcept;
  static constexpr bool IsLimitedBroadcastIPv4(const in_addr& address) noexcept;
	SOCKET m_thisSocket;
	sockaddr_in m_service;
  std::string m_name;
	std::string m_ip;
	int m_portNum;
  std::atomic<int> m_messageLength;
	std::atomic<bool> m_wsaRegistered;
	std::atomic<bool> m_active;
	std::atomic<bool> m_configured;
	std::atomic<bool> m_closeAttempt;
	std::function<void(const std::string& errorMessage)> m_errorHandler;
	std::shared_mutex m_errorHandlerMutex;
  std::atomic<bool> m_errorHandlerFaulted;
	std::function<void(const std::string& updateMessage)> m_updateHandler;
	std::shared_mutex m_updateHandlerMutex;
	static int s_wsaRefCount;
	static std::mutex s_wsaMutex;
	static WSADATA s_wsaData;
};
