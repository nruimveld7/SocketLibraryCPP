#pragma once

#include "SocketLibrary/WinSock2First.h"
#include <string>
#include <functional>
#include <shared_mutex>
#include <atomic>

#define INVALID_PORT -1

class Socket {
public:
	Socket();
	~Socket();
	void SetErrorHandler(std::function<void(std::string errorMessage)> errorHandler);
	void SetUpdateHandler(std::function<void(std::string updateMessage)> updateHandler);
	std::string GetIP();
	bool SetIP(std::string newIP);
	int GetPortNum();
	bool SetPortNum(int newPortNum);
	bool SetPortNum(std::string newPortNum);
	int GetMessageLength();
	bool SetMessageLength(int newLength);
	bool SetMessageLength(std::string newLength);
	bool GetActive();
	std::string GetName();
	bool SetName(std::string name);
	static bool CheckIP(std::string ip);
	static bool CheckPort(int port);
	static bool CheckPort(std::string port);
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
	void ErrorInterpreter(std::string errorMessage, bool hasCode);
	void UpdateInterpreter(std::string updateMessage);
	std::string DecodeSocketError(int errorCode);
	std::string ConstructAddress(const std::string& ip, int port);
	std::string GetSocketAddress(SOCKET client);
	std::string GetSocketAddress(sockaddr_in& addr);
	std::string GetSocketIP(SOCKET socket);
	std::string GetSocketIP(sockaddr_in& addr);
	int GetSocketPort(SOCKET socket);
	int GetSocketPort(sockaddr_in& addr);
	bool StringToInt(std::string convertToInt, int* outInt);
	SOCKET m_thisSocket;
	sockaddr_in m_service;
	std::string m_ip;
	int m_portNum;
	bool m_wsaRegistered;
	bool m_active;
	bool m_configured;
	int m_messageLength;
	bool m_closeAttempt;
	std::string m_name;
	std::function<void(std::string errorMessage)> m_errorHandler;
	std::shared_mutex m_errorHandlerMutex;
	std::function<void(std::string updateMessage)> m_updateHandler;
	std::shared_mutex m_updateHandlerMutex;
	static std::atomic<int> s_wsaRefCount;
	static std::mutex s_wsaMutex;
	static WSADATA s_wsaData;
};