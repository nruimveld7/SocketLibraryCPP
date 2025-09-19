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
	~Socket() noexcept;
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
	static bool CheckIP(const std::string& ip);
  static bool CheckPort(int port) noexcept;
  static bool CheckPort(const std::string& port);
	bool operator==(const Socket& other) const {
		return this == &other;
	}

	bool operator!=(const Socket& other) const {
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
  static std::string ConstructAddress(const std::string& ip, int port);
  static std::string GetSocketAddress(SOCKET client);
  static std::string GetSocketAddress(const sockaddr_in& addr);
  static std::string GetSocketIP(SOCKET socket);
  static std::string GetSocketIP(const sockaddr_in& addr);
  static int GetSocketPort(SOCKET socket);
  static int GetSocketPort(const sockaddr_in& addr);
  static bool StringToInt(const std::string& convertToInt, int* outInt);
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
	std::function<void(std::string errorMessage)> m_errorHandler;
	std::shared_mutex m_errorHandlerMutex;
	std::function<void(std::string updateMessage)> m_updateHandler;
	std::shared_mutex m_updateHandlerMutex;
	static int s_wsaRefCount;
	static std::mutex s_wsaMutex;
	static WSADATA s_wsaData;
};
