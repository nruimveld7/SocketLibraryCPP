#pragma once

#include "SocketLibrary/WinSock2First.h"
#include <string>
#include <vector>
#include <functional>
#include <shared_mutex>
#include <atomic>
#include <exception>
#include "SocketLibrary/Socket.h"

class TCPServerSocket : public Socket {
public:
	TCPServerSocket();
	~TCPServerSocket();
	void SetOnClientDisconnect(std::function<void()> onClientDisconnect);
	void SetOnRead(std::function<void(unsigned char* message, int byteCount, SOCKET* sender)> onRead);
	int GetListenBufferSize();
	bool SetListenBufferSize(int newSize);
	bool SetListenBufferSize(std::string newSize);
	int GetMaxConnections();
	bool SetMaxConnections(int newMax);
	bool SetMaxConnections(std::string newMax);
	int GetNumConnections();
	bool Open();
	bool Close();
	std::vector<std::string> GetClientAddresses();
	template <typename T>
	void Broadcast(T* buffer, int buffLen) {
		try {
			int currentConnections = m_numConnections.load(std::memory_order_relaxed);
			if(currentConnections == 0) {
				ErrorInterpreter("No connections to broadcast over", false);
				return;
			}
			std::size_t failCount = 0;
			std::size_t successCount = 0;
			UpdateInterpreter("Broadcasting message: " + std::to_string(buffLen) + " Bytes");
			//Convert buffer to byte array
			const unsigned char* sendBuff = reinterpret_cast<const unsigned char*>(buffer);
			std::unique_lock lock(m_connectionsMutex);
			for(std::size_t i = 0; i < m_connections.size(); ++i) {
				UpdateInterpreter("Sending to client #" + std::to_string(i + 1));
				SOCKET client = m_connections[i];
				int byteCount = send(client, reinterpret_cast<const char*>(sendBuff), buffLen, 0);
				if(byteCount <= 0) {
					ErrorInterpreter("Error sending message: ", true);
					failCount++;
					continue;
				}
				successCount++;
				std::string clientAddress = GetSocketAddress(client);
				if(clientAddress == "") {
					UpdateInterpreter("Successful broadcast: Unable to obtain client IP");
					continue;
				}
				UpdateInterpreter("Successful broadcast: " + clientAddress);
			}
			lock.unlock();
			UpdateInterpreter("# Failed Broadcasts: " + std::to_string(failCount));
			UpdateInterpreter("# Successful Broadcasts: " + std::to_string(successCount));
			if(failCount + successCount != m_connections.size()) {
				ErrorInterpreter("Number of fails and successes does not match connection count...", false);
			}
		} catch(const std::exception& e) {
			std::string error = e.what();
			ErrorInterpreter("Broadcast Error: " + error, false);
			throw;
		} catch(...) {
			ErrorInterpreter("Broadcast: Unknown Error", false);
			throw;
		}
	}
	template <typename T>
	int Send(T* buffer, int buffLen, const std::string& targetIP, int targetPort) {
		try {
			UpdateInterpreter("BEGIN Send1");
			std::string targetAddress = ConstructAddress(targetIP, targetPort);
			UpdateInterpreter("END Send1");
			return Send(buffer, buffLen, targetAddress);
		} catch(const std::exception& e) {
			std::string error = e.what();
			ErrorInterpreter("Send 1 Error: " + error, false);
			throw;
		} catch(...) {
			ErrorInterpreter("Send 1: Unknown Error", false);
			throw;
		}
		return 0;
	}
	template <typename T>
	int Send(T* buffer, int buffLen, const std::string& targetAddress) {
		try {
			UpdateInterpreter("BEGIN Send2");
			int currentConnections = m_numConnections.load(std::memory_order_relaxed);
			UpdateInterpreter("Sending Message To " + targetAddress + " - " + std::to_string(buffLen) + " Bytes");
			std::unique_lock lock(m_connectionsMutex);
			for(std::size_t i = 0; i < currentConnections; ++i) {
				if(GetSocketAddress(m_connections[i]) == targetAddress) {
					const char* sendBuff = reinterpret_cast<const char*>(buffer);
					int byteCount = send(m_connections[i], sendBuff, buffLen, 0);
					if(byteCount <= 0) {
						ErrorInterpreter("Error Sending Message: ", true);
					} else {
						UpdateInterpreter("Successfully Sent Message");
					}
					UpdateInterpreter("END Send2");
					return byteCount;
				}
			}
			lock.unlock;
			ErrorInterpreter("Unable To Find Connected Client With Address '" + targetAddress + "'", false);
			UpdateInterpreter("END Send2");
			return 0;
		} catch(const std::exception& e) {
			std::string error = e.what();
			ErrorInterpreter("Send 2 Error: " + error, false);
			throw;
		} catch(...) {
			ErrorInterpreter("Send 2: Unknown Error", false);
			throw;
		}
		return 0;
	}
	template <typename T>
	int Send(T* buffer, int buffLen) {
		try {
			UpdateInterpreter("BEGIN Send3");
			int currentConnections = m_numConnections.load(std::memory_order_relaxed);
			if(currentConnections == 1) {
				std::shared_lock lock(m_connectionsMutex);
				SOCKET target = m_connections[0];
				lock.unlock();
				UpdateInterpreter("END Send3");
				return Send(buffer, buffLen, &target);
			} else {
				ErrorInterpreter("Requires Only One Connected Client", false);
			}
			UpdateInterpreter("END Send3");
			return 0;
		} catch(const std::exception& e) {
			std::string error = e.what();
			ErrorInterpreter("Send 3 Error: " + error, false);
			throw;
		} catch(...) {
			ErrorInterpreter("Send 3: Unknown Error", false);
			throw;
		}
		return 0;
	}
	template <typename T>
	int Send(T* buffer, int buffLen, SOCKET* target) {
		try {
			UpdateInterpreter("BEGIN Send4");
			UpdateInterpreter("Sending Message To " + GetSocketAddress(*target) + " - " + std::to_string(buffLen) + " Bytes");
			const char* sendBuff = reinterpret_cast<const char*>(buffer);
			std::unique_lock lock(m_connectionsMutex);
			int byteCount = send(*target, sendBuff, buffLen, 0);
			lock.unlock();
			if(byteCount <= 0) {
				ErrorInterpreter("Error Sending Message: ", true);
			} else {
				UpdateInterpreter("Successfully Sent Message");
			}
			UpdateInterpreter("END Send4");
			return byteCount;
		} catch(const std::exception& e) {
			std::string error = e.what();
			ErrorInterpreter("Send 4 Error: " + error, false);
			throw;
		} catch(...) {
			ErrorInterpreter("Send 4: Unknown Error", false);
			throw;
		}
		return 0;
	}

private:
	struct MessageHandlerParams {
		TCPServerSocket* serverSocket;
		SOCKET clientSocket;
	};
	static DWORD WINAPI StaticAcceptConnection(LPVOID lpParam);
	void AcceptConnection();
	void RegisterClient(SOCKET socket);
	static DWORD WINAPI StaticMessageHandler(LPVOID lpParam);
	void MessageHandler(SOCKET acceptSocket);
	bool CloseClientSocket(SOCKET clientSocket);
	void OnClientDisconnect();
	void OnRead(unsigned char* message, int byteCount, SOCKET* sender);
	std::vector<SOCKET> m_connections;
	std::shared_mutex m_connectionsMutex;
	std::atomic<int> m_numConnections = 0;
	int m_listenBufferSize;
	int m_maxConnections;
	std::function<void()> m_onClientDisconnect;
	std::shared_mutex m_onClientDisconnectMutex;
	std::function<void(unsigned char* message, int byteCount, SOCKET* sender)> m_onRead;
	std::shared_mutex m_onReadMutex;
};