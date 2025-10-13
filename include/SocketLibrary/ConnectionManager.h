#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include <shared_mutex>
#include "SocketLibrary/WinSock2First.h"

namespace SocketLibrary {
  class ConnectionManager {
  public:
    struct AddResult {
      enum class Code : uint8_t {
        Invalid,
        Added,
        Exists,
        Full
      } code;
      size_t count;
    };
    ConnectionManager() = default;
    ~ConnectionManager() = default;
    ConnectionManager(const ConnectionManager&) = delete;
    ConnectionManager& operator=(const ConnectionManager&) = delete;
    ConnectionManager(ConnectionManager&&) = delete;
    ConnectionManager& operator=(ConnectionManager&&) = delete;
    AddResult AddConnection(SOCKET socket, const std::string& address, size_t limit = 0);
    AddResult AddConnection(const std::string& address, SOCKET socket, size_t limit = 0);
    SOCKET FindSocket(const std::string& address) const noexcept;
    std::string FindAddress(SOCKET socket) const;
    void Snapshot(std::vector<SOCKET>& out) const;
    void Snapshot(std::vector<std::string>& out) const;
    void Snapshot(std::vector<SOCKET>& outSockets, std::vector<std::string>& outAddresses) const;
    void Snapshot(std::vector<std::string>& outAddresses, std::vector<SOCKET>& outSockets) const;
    size_t Count() const noexcept;
    bool RemoveConnection(SOCKET socket) noexcept;
    bool RemoveConnection(const std::string& address) noexcept;
    bool RemoveConnection(SOCKET socket, const std::string& address) noexcept;
    bool RemoveConnection(const std::string& address, SOCKET socket) noexcept;
    void Clear() noexcept;

  private:
    void Rehash() noexcept;
    std::unordered_map<SOCKET, std::string> m_socketToAddress;
    std::unordered_map<std::string, SOCKET> m_addressToSocket;
    size_t m_erasesSinceRehash{0};
    mutable std::shared_mutex m_mutex;
  };
} //namespace SocketLibrary
