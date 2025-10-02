#pragma once

#include "SocketLibrary/WinSock2First.h"
#include <string>
#include <functional>
#include <shared_mutex>
#include <atomic>
#include <type_traits>
#include "SocketLibrary/Socket.h"

namespace SocketLibrary {
  class TCPClientSocket : public Socket {
  public:
    TCPClientSocket();
    ~TCPClientSocket() noexcept override;
    void SetOnDisconnect(std::function<void()> onDisconnect);
    void SetOnRead(std::function<void(unsigned char* message, int byteCount)> onRead);
    int GetConnectionDelay() const noexcept;
    bool SetConnectionDelay(int newDelay);
    bool SetConnectionDelay(const std::string& newDelay);
    bool IsConnected() const noexcept;
    bool IsCancelling() const noexcept;
    bool IsConnecting() const noexcept;
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
    static unsigned __stdcall StaticConnectionHandler(void* arg) noexcept;
    void ConnectionHandler();
    bool ConnectAttempt();
    void MessageHandler();
    int Send(const void* bytes, size_t byteCount);
    int SendAll(const char* buffer, int bufferSize);
    void SetConnected(bool connected) noexcept;
    void SetCancelling(bool cancelling) noexcept;
    void SetConnecting(bool connecting) noexcept;
    bool Cleanup() override;
    void OnDisconnect();
    void OnRead(unsigned char* message, int byteCount);
    std::atomic<int> m_connectionDelay;
    std::atomic<bool> m_connected;
    std::atomic<bool> m_cancelConnect;
    std::atomic<bool> m_connecting;
    std::function<void()> m_onDisconnect;
    std::shared_mutex m_onDisconnectMutex;
    std::function<void(unsigned char* message, int byteCount)> m_onRead;
    std::shared_mutex m_onReadMutex;
  };
} //namespace SocketLibrary
