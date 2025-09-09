#pragma once

#include "SocketLibrary/WinSock2First.h"
#include <string>
#include <functional>
#include <shared_mutex>
#include <type_traits>
#include "SocketLibrary/Socket.h"

class UDPServerSocket : public Socket {
public:
	UDPServerSocket();
	~UDPServerSocket();
	bool Open();
	bool Close();
	void SetOnRead(std::function<void(unsigned char* message, int byteCount, sockaddr_in* sender)> onRead);
	template <typename T>
	int Send(T* buffer, int buffLen, sockaddr_in* target) {
		if(!target) {
			ErrorInterpreter("Error: Invalid Target Provided", false);
			return 0;
		}
		sockaddr_in temp = m_target;
		m_target = *target;
		if(inet_pton(AF_INET, inet_ntoa(target->sin_addr), &m_target.sin_addr) != 1) {
			ErrorInterpreter("Error Changing Target: ", true);
			m_target = temp;
			return 0;
		}
		int port = ntohs(m_target.sin_port);
		if(port <= 0 || port > 65535) {
			ErrorInterpreter("Error Changing Target: Port Out of Range", false);
			m_target = temp;
			return 0;
		}
		return Send(buffer, buffLen);
	}
	template <typename T>
	int Send(T* buffer, int buffLen, std::string ip, int port) {
		sockaddr_in temp = m_target;
		if(inet_pton(AF_INET, ip.c_str(), &m_target.sin_addr) != 1) {
			ErrorInterpreter("Error Changing Target: ", true);
			m_target = temp;
			return 0;
		}
		if(port < 0 || port > 65535) {
			ErrorInterpreter("Error Changing Target: Port Out Of Range", false);
			m_target = temp;
			return 0;
		}
		m_target.sin_port = htons(port);
		return Send(buffer, buffLen);
	}
	template <typename T>
	int Send(T* buffer, int buffLen) {
		static_assert(!std::is_same<T, std::string>::value, "std::string must be passed as const char* or c_str()");
		if(buffer == nullptr || buffLen <= 0) {
			ErrorInterpreter("Invalid buffer or buffer length", false);
			return 0;
		}
		UpdateInterpreter("Sending Message: " + std::to_string(buffLen) + " Bytes");
		if(m_configured && m_wsaRegistered && m_thisSocket != INVALID_SOCKET) {
			//Convert buffer to byte array
			const unsigned char* sendBuff = reinterpret_cast<const unsigned char*>(buffer);
			int byteCount = sendto(
				m_thisSocket,
				reinterpret_cast<const char*>(sendBuff),
				buffLen,
				0,
				reinterpret_cast<SOCKADDR*>(&m_target),
				sizeof(m_target)
			);
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
	static DWORD WINAPI StaticMessageHandler(LPVOID lpParam);
	void MessageHandler();
	void OnRead(unsigned char* message, int byteCount, sockaddr_in* sender);
	sockaddr_in m_target;
	std::function<void(unsigned char* message, int byteCount, sockaddr_in* sender)> m_onRead;
	std::shared_mutex m_onReadMutex;
};