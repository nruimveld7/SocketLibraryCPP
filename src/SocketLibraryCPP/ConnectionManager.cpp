#include "pch.h"
#include "SocketLibrary/ConnectionManager.h"

namespace SocketLibrary {
  bool ConnectionManager::AddConnection(SOCKET socket, const std::string& address) {
    if(socket == INVALID_SOCKET || address.empty()) {
      return false;
    }
    if(m_socketToAddress.count(socket) || m_addressToSocket.count(address)) {
      return false;
    }
    m_socketToAddress.emplace(socket, address);
    m_addressToSocket.emplace(address, socket);
    return true;
  }

  bool ConnectionManager::AddConnection(const std::string& address, SOCKET socket) {
    return AddConnection(socket, address);
  }

  SOCKET ConnectionManager::FindSocket(const std::string& address) const noexcept {
    auto it = m_addressToSocket.find(address);
    return (it == m_addressToSocket.end()) ? INVALID_SOCKET : it->second;
  }

  std::string ConnectionManager::FindAddress(SOCKET socket) const {
    auto it = m_socketToAddress.find(socket);
    return (it == m_socketToAddress.end()) ? std::string() : it->second;
  }

  void ConnectionManager::Snapshot(std::vector<SOCKET>& out) const {
    out.clear();
    out.reserve(m_socketToAddress.size());
    for(const auto& [socket, address] : m_socketToAddress) {
      out.push_back(socket);
    }
  }

  void ConnectionManager::Snapshot(std::vector<std::string>& out) const {
    out.clear();
    out.reserve(m_socketToAddress.size());
    for(const auto& [socket, address] : m_socketToAddress) {
      out.push_back(address);
    }
  }

  void ConnectionManager::Snapshot(std::vector<SOCKET>& outSockets, std::vector<std::string>& outAddresses) const {
    outSockets.clear();
    outAddresses.clear();
    const auto n = m_socketToAddress.size();
    outSockets.reserve(n);
    outAddresses.reserve(n);
    for(const auto& [socket, address] : m_socketToAddress) {
      outSockets.push_back(socket);
      outAddresses.push_back(address);
    }
  }

  void ConnectionManager::Snapshot(std::vector<std::string>& outAddresses, std::vector<SOCKET>& outSockets) const {
    Snapshot(outSockets, outAddresses);
  }

  size_t ConnectionManager::Count() const noexcept {
    return m_socketToAddress.size();
  }

  bool ConnectionManager::RemoveConnection(SOCKET socket) noexcept {
    auto it = m_socketToAddress.find(socket);
    if(it == m_socketToAddress.end()) {
      return false;
    }
    if(!it->second.empty()) {
      m_addressToSocket.erase(it->second);
    }
    m_socketToAddress.erase(it);
    if(m_socketToAddress.empty()) {
      Rehash();
    } else if(++m_erasesSinceRehash >= 256) {
      Rehash();
    }
    return true;
  }

  bool ConnectionManager::RemoveConnection(const std::string& address) noexcept {
    auto it = m_addressToSocket.find(address);
    if(it == m_addressToSocket.end()) {
      return false;
    }
    if(it->second != INVALID_SOCKET) {
      m_socketToAddress.erase(it->second);
    }
    m_addressToSocket.erase(it);
    if(m_socketToAddress.empty()) {
      Rehash();
    } else if(++m_erasesSinceRehash >= 256) {
      Rehash();
    }
    return true;
  }

  bool ConnectionManager::RemoveConnection(SOCKET socket, const std::string& address) noexcept {
    if(RemoveConnection(socket)) {
      return true;
    }
    if(RemoveConnection(address)) {
      return true;
    }
    return false;
  }

  bool ConnectionManager::RemoveConnection(const std::string& address, SOCKET socket) noexcept {
    return RemoveConnection(socket, address);
  }

  void ConnectionManager::Clear() noexcept {
    m_socketToAddress.clear();
    m_addressToSocket.clear();
    Rehash();
  }

  void ConnectionManager::Rehash() noexcept {
    m_erasesSinceRehash = 0;
    const auto size = m_socketToAddress.size();
    const auto socketBuckets = m_socketToAddress.bucket_count();
    const auto addressBuckets = m_addressToSocket.bucket_count();
    if(size == 0) {
      m_socketToAddress.rehash(0);
      m_addressToSocket.rehash(0);
      return;
    }
    constexpr size_t minTrimSize = 1024;
    bool trimSockets = (socketBuckets > (size * 8) && socketBuckets > minTrimSize);
    bool trimAddresses = (addressBuckets > (size * 8) && addressBuckets > minTrimSize);
    if(trimSockets || trimAddresses) {
      m_socketToAddress.rehash(size);
      m_addressToSocket.rehash(size);
    }
  }
} // namespace SocketLibrary
