#pragma once

#include "WinSock2First.h"
#include <mutex>
#include <atomic>
#include <vector>
#include <windows.h>

namespace SocketLibrary {
  class WorkerGroup {
  public:
    WorkerGroup() = default;
    ~WorkerGroup() noexcept;
    WorkerGroup(WorkerGroup&& other) noexcept;
    WorkerGroup& operator=(WorkerGroup&& other) noexcept;
    WorkerGroup(const WorkerGroup&) = delete;
    WorkerGroup& operator=(const WorkerGroup&) = delete;
    bool StartWorker(
      unsigned(__stdcall* workerFunction)(void*),
      void* context,
      unsigned stack = 0,
      unsigned initFlags = 0,
      unsigned* outID = nullptr) noexcept;
    void StopWorkers() noexcept;
    bool StopRequested() const noexcept;
    bool WaitForWorkers() noexcept;
    int ActiveWorkerCount() const noexcept;

  private:
    struct StartContext {
      WorkerGroup* group;
      unsigned(__stdcall* fn)(void*);
      void* context;
    };
    static unsigned __stdcall WorkerEntryPoint(void* params) noexcept;
    std::mutex m_workersMutex;
    std::vector<HANDLE> m_workers;
    std::atomic<int> m_activeWorkers{0};
    std::atomic<bool> m_stop{false};
  };
} //namespace SocketLibrary
