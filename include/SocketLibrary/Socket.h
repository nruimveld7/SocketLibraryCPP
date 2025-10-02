#pragma once

#include "SocketLibrary/WinSock2First.h"
#include <string>
#include <functional>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include "SocketLibrary/WorkerGroup.h"

namespace SocketLibrary {

  inline constexpr int INVALID_PORT = -1;

  class Socket {
  public:
    virtual ~Socket() noexcept;
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    Socket(Socket&& other) noexcept;
    Socket& operator=(Socket&& other) noexcept;
    void SetErrorHandler(std::function<void(const std::string& errorMessage)> errorHandler);
    void SetUpdateHandler(std::function<void(const std::string& updateMessage)> updateHandler);
    std::string GetName() const noexcept;
    bool SetName(const std::string& name);
    std::string GetServerIP() const noexcept;
    bool SetServerIP(const std::string& ip);
    int GetServerPort() const noexcept;
    bool SetServerPort(int port);
    bool SetServerPort(const std::string& port);
    int GetMessageLength() const noexcept;
    bool SetMessageLength(int messageLength);
    bool SetMessageLength(const std::string& messageLength);
    void SetTrafficUpdates(bool trafficUpdates) noexcept;
    virtual bool Open() = 0;
    virtual bool Close();
    bool GetActive() const noexcept;
    static bool CheckIP(const std::string& ip) noexcept;
    static bool CheckPort(int port) noexcept;
    static bool CheckPort(const std::string& port);
    bool operator==(const Socket& other) const noexcept {
      const SOCKET thisSocket = m_thisSocket.load(std::memory_order_acquire);
      const SOCKET otherSocket = other.m_thisSocket.load(std::memory_order_acquire);
      return thisSocket != INVALID_SOCKET && otherSocket != INVALID_SOCKET && thisSocket == otherSocket;
    }
    bool operator!=(const Socket& other) const noexcept {
      return !(*this == other);
    }

  protected:
    enum class Protocol {
      UDP,
      TCP
    };
    Socket();
    SOCKET GetSocket() const noexcept;
    bool ReinitializeSocket(Protocol protocol, bool shutdown);
    bool GetServiceAddress(Protocol protocol, sockaddr_in& outAddress);
    virtual bool Cleanup() = 0;
    bool Initialize(Protocol protocol);
    bool RegisterWSA();
    bool StartWorker(
      unsigned(__stdcall* workerFunction)(void*),
      void* context,
      unsigned stack = 0,
      unsigned initFlags = 0,
      unsigned* outID = nullptr
    ) noexcept;
    bool StopRequested() const noexcept;
    int ActiveWorkerCount() const noexcept;
    bool UnregisterWSA();
    bool CloseSocketSafe(SOCKET& socketToClose, bool shutDownSocket);
    bool CloseSocketSafe(std::atomic<SOCKET>& socketToClose, bool shutDownSocket);
    bool ShutDownSocket(SOCKET& socketToShutDown);
    bool IsRegistered() const noexcept;
    void SetRegistered(bool registered) noexcept;
    bool IsActive() const noexcept;
    void SetActive(bool active) noexcept;
    bool IsConfigured() const noexcept;
    void SetConfigured(bool configured) noexcept;
    bool IsClosing() const noexcept;
    void SetClosing(bool closing) noexcept;
    bool TrafficUpdatesEnabled() const noexcept;
    void TrafficUpdate(const std::string& trafficMessage);
    void ErrorInterpreter(const std::string& errorMessage, bool hasCode);
    void UpdateInterpreter(const std::string& updateMessage);
    static std::string DecodeSocketError(int errorCode);
    static std::string ConstructAddress(const std::string& ip, const std::string& port);
    static std::string ConstructAddress(const std::string& ip, int port);
    static std::string GetPeerAddress(const SOCKET& client);
    static std::string GetPeerIP(const SOCKET& socket);
    static int GetPeerPort(const SOCKET& socket) noexcept;
    static std::string GetLocalAddress(const SOCKET& client);
    static std::string GetLocalIP(const SOCKET& socket);
    static int GetLocalPort(const SOCKET& socket) noexcept;
    static std::string GetSocketAddress(const sockaddr_in& addr);
    static std::string GetSocketIP(const sockaddr_in& addr);
    static int GetSocketPort(const sockaddr_in& addr) noexcept;
    static bool ParseSocketAddress(const std::string& address, Protocol protocol, sockaddr_in& out);
    static bool ParseSocketAddress(const std::string& ip, int port, Protocol protocol, sockaddr_in& out);
    static bool ParseSocketAddress(const std::string& ip, const std::string& port, Protocol protocol, sockaddr_in& out);
    static bool GetHints(addrinfo& outHints, Protocol protocol, int family = AF_INET, int flags = 0) noexcept;
    static bool StringToInt(const std::string& intStr, int& outInt) noexcept;
    static void FallbackLog(const char* msg) noexcept;
    static bool IsMulticastIPv4(const in_addr& address) noexcept;
    static bool IsInitializedIPv4(const sockaddr_in& socketAddress) noexcept;
    static bool IsValidEndpointIPv4(const sockaddr_in& socketAddress) noexcept;
    static bool IsLimitedBroadcastIPv4(const in_addr& address) noexcept;
    std::atomic<SOCKET> m_thisSocket;
    std::string m_name;
    std::string m_serverIP;
    int m_serverPort;
    mutable std::shared_mutex m_configMutex;
    std::atomic<int> m_messageLength;
    std::atomic<bool> m_wsaRegistered;
    std::atomic<bool> m_active;
    std::atomic<bool> m_configured;
    std::atomic<bool> m_closeAttempt;
    std::atomic<bool> m_trafficUpdates;
    std::function<void(const std::string& errorMessage)> m_errorHandler;
    std::shared_mutex m_errorHandlerMutex;
    std::atomic<bool> m_errorHandlerFaulted;
    std::function<void(const std::string& updateMessage)> m_updateHandler;
    std::shared_mutex m_updateHandlerMutex;
    static int s_wsaRefCount;
    static std::mutex s_wsaMutex;
    static WSADATA s_wsaData;

  private:
    WorkerGroup m_workers;

  };
} //namespace SocketLibrary
