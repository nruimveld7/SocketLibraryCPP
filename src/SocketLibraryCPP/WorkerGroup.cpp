#include "SocketLibrary/WorkerGroup.h"
#include <process.h>
#include <new>
#include <algorithm>

WorkerGroup::~WorkerGroup() noexcept {
  StopWorkers();
  (void)WaitForWorkers(200);
}

bool WorkerGroup::StartWorker(
  unsigned(__stdcall* workerFunction)(void*),
  void* context,
  unsigned stack,
  unsigned initFlags,
  unsigned* outID) noexcept {
  if(!workerFunction) {
    return false;
  }
  if(m_stop.load(std::memory_order_acquire)) {
    return false;
  }
  // 1) Allocate raw memory without throwing
  auto* paramsMemory = static_cast<StartContext*>(::operator new(sizeof(StartContext), std::nothrow));
  if(!paramsMemory) {
    return false;
  }
  // 2) Construct StartContext in-place
  ::new (paramsMemory) StartContext{this, workerFunction, context};
  StartContext* params = paramsMemory;
  // 3) Create the thread
  unsigned threadID = 0;
  HANDLE threadHandle = (HANDLE)_beginthreadex(nullptr, stack, &WorkerGroup::WorkerEntryPoint, params, initFlags, &threadID);
  if(!threadHandle) {
    // 4) If thread creation failed, destroy + free the context
    params->~StartContext();
    ::operator delete(params);
    return false;
  }
  // 5) Track the handle
  {
    std::lock_guard lock(m_workersMutex);
    m_workers.push_back(threadHandle);
  }
  if(outID) {
    *outID = threadID;
  }
  return true;
}

void WorkerGroup::StopWorkers() noexcept {
  m_stop.store(true, std::memory_order_release);
}

bool WorkerGroup::StopRequested() const noexcept {
  return m_stop.load(std::memory_order_acquire);
}

bool WorkerGroup::WaitForWorkers(DWORD timeoutMsPerChunk) noexcept {
  std::vector<HANDLE> workers;
  {
    std::lock_guard lock(m_workersMutex);
    workers = std::move(m_workers);
    m_workers.clear();
  }
  if(workers.empty()) {
    return true;
  }
  bool allExited = true;
  size_t index = 0;
  while(true) {
    const size_t totalWorkers = workers.size();
    const size_t remainingWorkers = (index < totalWorkers ? totalWorkers - index : 0);
    if(remainingWorkers == 0) {
      break;
    }
    const size_t maximumObjects = static_cast<size_t>(MAXIMUM_WAIT_OBJECTS);
    const size_t chunkCount = remainingWorkers > maximumObjects ? maximumObjects : remainingWorkers;
    const DWORD result = ::WaitForMultipleObjects(
      static_cast<DWORD>(chunkCount),
      workers.data() + index,
      TRUE, // wait for all in this chunk
      timeoutMsPerChunk
    );
    if(result != WAIT_OBJECT_0) {
      allExited = false; // timed out or failed
    }
    index += chunkCount;
  }
  for(HANDLE worker : workers) {
    ::CloseHandle(worker);
  }
  return allExited && (m_activeWorkers.load(std::memory_order_acquire) == 0);
}

int WorkerGroup::ActiveWorkerCount() const noexcept {
  return m_activeWorkers.load(std::memory_order_acquire);
}

unsigned __stdcall WorkerGroup::WorkerEntryPoint(void* params) noexcept {
  std::unique_ptr<StartContext> startContext(static_cast<StartContext*>(params));
  WorkerGroup* workerGroup = startContext->group;
  workerGroup->m_activeWorkers.fetch_add(1, std::memory_order_acq_rel);
  struct Guard {
    WorkerGroup* workerGroup;
    ~Guard() noexcept {
      workerGroup->m_activeWorkers.fetch_sub(1, std::memory_order_acq_rel);
    }
  } guard{workerGroup};
  unsigned result = 0;
  try {
    result = startContext->fn(startContext->context);
  } catch(...) {
    result = 0;
  }
  return result;
}
