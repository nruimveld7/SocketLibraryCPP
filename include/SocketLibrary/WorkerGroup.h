#pragma once

#include <mutex>
#include <atomic>
#include <vector>
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>


class WorkerGroup {
public:
	WorkerGroup() = default;
	~WorkerGroup() noexcept;
  bool StartWorker(
    unsigned(__stdcall* workerFunction)(void*),
    void* context,
    unsigned stack = 0,
    unsigned initFlags = 0,
    unsigned* outID = nullptr) noexcept;
  void StopWorkers() noexcept;
  bool StopRequested() const noexcept;
  bool WaitForWorkers(DWORD timeoutMsPerChunk) noexcept;
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
