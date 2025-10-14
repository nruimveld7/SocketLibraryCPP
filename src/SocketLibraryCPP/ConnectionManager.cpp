#include "pch.h"
#include "SocketLibrary/ConnectionManager.h"

namespace SocketLibrary {
  ConnectionManager::AddResult ConnectionManager::AddConnection(SOCKET socket, const std::string& address, size_t limit) {
    AddResult addResult{};
    std::unique_lock lock(m_mutex);
    addResult.count = m_socketToAddress.size();
    if(socket == INVALID_SOCKET || address.empty()) {
      addResult.code = AddResult::Code::Invalid;
      return addResult;
    }
    if(m_socketToAddress.count(socket) || m_addressToSocket.count(address)) {
      addResult.code = AddResult::Code::Exists;
      return addResult;
    }
    if(limit != 0 && addResult.count >= limit) {
      addResult.code = AddResult::Code::Full;
      return addResult;
    }
    m_socketToAddress.emplace(socket, address);
    m_addressToSocket.emplace(address, socket);
    addResult.code = AddResult::Code::Added;
    addResult.count = m_socketToAddress.size();
    return addResult;
  }

  ConnectionManager::AddResult ConnectionManager::AddConnection(const std::string& address, SOCKET socket, size_t limit) {
    return AddConnection(socket, address, limit);
  }

  SOCKET ConnectionManager::FindSocket(const std::string& address) const noexcept {
    std::shared_lock lock(m_mutex);
    auto it = m_addressToSocket.find(address);
    return (it == m_addressToSocket.end()) ? INVALID_SOCKET : it->second;
  }

  std::string ConnectionManager::FindAddress(SOCKET socket) const {
    std::shared_lock lock(m_mutex);
    auto it = m_socketToAddress.find(socket);
    return (it == m_socketToAddress.end()) ? std::string() : it->second;
  }

  void ConnectionManager::Snapshot(std::vector<SOCKET>& out) const {
    out.clear();
    std::shared_lock lock(m_mutex);
    out.reserve(m_socketToAddress.size());
    for(const auto& [socket, address] : m_socketToAddress) {
      out.push_back(socket);
    }
  }

  void ConnectionManager::Snapshot(std::vector<std::string>& out) const {
    out.clear();
    std::shared_lock lock(m_mutex);
    out.reserve(m_socketToAddress.size());
    for(const auto& [socket, address] : m_socketToAddress) {
      out.push_back(address);
    }
  }

  void ConnectionManager::Snapshot(std::vector<SOCKET>& outSockets, std::vector<std::string>& outAddresses) const {
    outSockets.clear();
    outAddresses.clear();
    std::shared_lock lock(m_mutex);
    const auto size = m_socketToAddress.size();
    outSockets.reserve(size);
    outAddresses.reserve(size);
    for(const auto& [socket, address] : m_socketToAddress) {
      outSockets.push_back(socket);
      outAddresses.push_back(address);
    }
  }

  void ConnectionManager::Snapshot(std::vector<std::string>& outAddresses, std::vector<SOCKET>& outSockets) const {
    Snapshot(outSockets, outAddresses);
  }

  size_t ConnectionManager::Count() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_socketToAddress.size();
  }

  bool ConnectionManager::RemoveConnection(SOCKET socket) noexcept {
    bool rehash = false;
    {
      std::unique_lock lock(m_mutex);
      auto it = m_socketToAddress.find(socket);
      if(it == m_socketToAddress.end()) {
        return false;
      }
      if(!it->second.empty()) {
        m_addressToSocket.erase(it->second);
      }
      m_socketToAddress.erase(it);
      rehash = m_socketToAddress.empty() || ++m_erasesSinceRehash >= 256;
    }
    if(rehash) {
      Rehash();
    }
    return true;
  }

  bool ConnectionManager::RemoveConnection(const std::string& address) noexcept {
    bool rehash = false;
    {
      std::unique_lock lock(m_mutex);
      auto it = m_addressToSocket.find(address);
      if(it == m_addressToSocket.end()) {
        return false;
      }
      if(it->second != INVALID_SOCKET) {
        m_socketToAddress.erase(it->second);
      }
      m_addressToSocket.erase(it);
      rehash = m_socketToAddress.empty() || ++m_erasesSinceRehash >= 256;
    }
    if(rehash) {
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
    {
      std::unique_lock lock(m_mutex);
      m_socketToAddress.clear();
      m_addressToSocket.clear();
    }
    Rehash();
  }

  void ConnectionManager::Rehash() noexcept {
    std::unique_lock lock(m_mutex);
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
