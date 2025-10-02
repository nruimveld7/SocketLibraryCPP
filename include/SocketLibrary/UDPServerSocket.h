#pragma once

#include "SocketLibrary/WinSock2First.h"
#include <string>
#include <functional>
#include <shared_mutex>
#include <type_traits>
#include "SocketLibrary/Socket.h"

namespace SocketLibrary {
  class UDPServerSocket : public Socket {
  public:
    UDPServerSocket();
    ~UDPServerSocket() noexcept override;
    void SetOnRead(std::function<void(unsigned char* message, int byteCount, sockaddr_in sender)> onRead);
    bool Open();
    bool Close();

    template <typename T>
    int Broadcast(const T* buffer, size_t bufferSize) {
      static_assert(!std::is_void_v<T>, "T cannot be void");
      static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable");
      if(bufferSize > (std::numeric_limits<size_t>::max() / sizeof(T))) {
        ErrorInterpreter("Send error: payload too large for WinSock", false);
        return 0;
      }
      const size_t bytes = bufferSize * sizeof(T);
      return Broadcast(static_cast<const void*>(buffer), bytes);
    }

    template <typename T>
    int Broadcast(const T* buffer, size_t bufferSize, int port) {
      static_assert(!std::is_void_v<T>, "T cannot be void");
      static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable");
      if(bufferSize > (std::numeric_limits<size_t>::max() / sizeof(T))) {
        ErrorInterpreter("Send error: payload too large for WinSock", false);
        return 0;
      }
      const size_t bytes = bufferSize * sizeof(T);
      return Broadcast(static_cast<const void*>(buffer), bytes, port);
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
    int Send(const T* buffer, size_t bufferSize, sockaddr_in target) {
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
    static unsigned __stdcall StaticMessageHandler(void* arg) noexcept;
    void MessageHandler();
    int Broadcast(const void* bytes, size_t byteCount);
    int Broadcast(const void* bytes, size_t byteCount, int port);
    int Send(const void* bytes, size_t byteCount, const std::string& targetIP, const std::string& targetPort);
    int Send(const void* bytes, size_t byteCount, const std::string& targetIP, int targetPort);
    int Send(const void* bytes, size_t byteCount, const std::string& targetAddress);
    int Send(const void* bytes, size_t byteCount, const sockaddr_in& target);
    int Send(const void* bytes, size_t byteCount);
    int SendAll(sockaddr_in socket, const char* data, int total);
    bool Cleanup() override;
    void OnRead(unsigned char* message, int byteCount, sockaddr_in sender);
    sockaddr_in m_target;
    mutable std::shared_mutex m_targetMutex;
    std::function<void(unsigned char* message, int byteCount, sockaddr_in sender)> m_onRead;
    std::shared_mutex m_onReadMutex;
  };
} //namespace SocketLibrary
