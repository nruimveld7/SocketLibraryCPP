#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include "SocketLibrary/WinSock2First.h"

namespace SocketLibrary {
  class ConnectionManager {
  public:
    ConnectionManager() = default;
    ~ConnectionManager() = default;
    bool AddConnection(SOCKET socket, const std::string& address);
    bool AddConnection(const std::string& address, SOCKET socket);
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
  };
} //namespace SocketLibrary
