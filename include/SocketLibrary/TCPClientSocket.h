#pragma once

#include "SocketLibrary/WinSock2First.h"
#include <string>
#include <functional>
#include <shared_mutex>
#include <atomic>
#include "SocketLibrary/Socket.h"

class TCPClientSocket : public Socket {
public:
	TCPClientSocket();
	~TCPClientSocket();
	void SetOnDisconnect(std::function<void()> onDisconnect);
	void SetOnRead(std::function<void(unsigned char* message, int byteCount)> onRead);
	int GetConnectionDelay();
	bool SetConnectionDelay(int newDelay);
	bool SetConnectionDelay(std::string newDelay);
	bool GetConnected();
	bool GetConnecting();
	bool Open();
	bool Close();
	template <typename T>
	int Send(T* buffer, int buffLen) {
		UpdateInterpreter("Sending Message: " + std::to_string(buffLen) + " Bytes");
		if(m_configured && m_wsaRegistered && m_connected && m_thisSocket != INVALID_SOCKET) {
			//Convert buffer to byte array
			const char* sendBuff = reinterpret_cast<const char*>(buffer);
			int byteCount = send(m_thisSocket, sendBuff, buffLen, 0);
			if(byteCount <= 0) {
				ErrorInterpreter("Error Sending Mesage: ", true);
			}
			return byteCount;
		} else {
			ErrorInterpreter("Socket Is Not Initialized", false);
			return 0;
		}
	}

private:
	static DWORD WINAPI StaticConnect(LPVOID lpParam);
	void Connect();
	bool MessageHandler();
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