#include "pch.h"
#include "SocketLibrary/WorkerGroup.h"
#include <process.h>
#include <new>
#include <algorithm>

namespace SocketLibrary {
  WorkerGroup::~WorkerGroup() noexcept {
    StopWorkers();
  }

  WorkerGroup::WorkerGroup(WorkerGroup&& other) noexcept {
    std::lock_guard lock(other.m_workersMutex);
    m_workers = std::move(other.m_workers);
    m_activeWorkers.store(other.m_activeWorkers.exchange(0, std::memory_order_acq_rel), std::memory_order_release);
    m_stop.store(other.m_stop.exchange(false, std::memory_order_acq_rel), std::memory_order_release);
  }

  WorkerGroup& WorkerGroup::operator=(WorkerGroup&& other) noexcept {
    if(this != &other) {
      StopWorkers();
      std::scoped_lock locks(m_workersMutex, other.m_workersMutex);
      m_workers = std::move(other.m_workers);
      m_activeWorkers.store(other.m_activeWorkers.exchange(0, std::memory_order_acq_rel), std::memory_order_release);
      m_stop.store(other.m_stop.exchange(false, std::memory_order_acq_rel), std::memory_order_release);
    }
    return *this;
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
      m_workers.push_back(Worker{threadID, threadHandle});
    }
    if(outID) {
      *outID = threadID;
    }
    return true;
  }

  void WorkerGroup::StopWorkers() noexcept {
    m_stop.store(true, std::memory_order_release);
    WaitForWorkers();
  }

  bool WorkerGroup::StopRequested() const noexcept {
    return m_stop.load(std::memory_order_acquire);
  }

  bool WorkerGroup::IsWorker() const noexcept {
    const DWORD threadID = ::GetCurrentThreadId();
    std::lock_guard lock(m_workersMutex);
    for(const auto& worker : m_workers) {
      if(worker.threadID == threadID) {
        return true;
      }
    }
    return false;
  }

  bool WorkerGroup::WaitForWorkers() noexcept {
    const DWORD threadID = ::GetCurrentThreadId();
    const bool isWorker = IsWorker();
    std::vector<HANDLE> handles;
    {
      std::lock_guard lock(m_workersMutex);
      handles.reserve(m_workers.size());
      for(const auto& worker : m_workers) {
        if(isWorker && worker.threadID == threadID) {
          continue;
        }
        if(worker.handle) {
          handles.push_back(worker.handle);
        }
      }
      m_workers.clear();
    }
    WaitForHandles(handles);
    return m_activeWorkers.load(std::memory_order_acquire) == 0;
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

  void WorkerGroup::WaitForHandles(const std::vector<HANDLE>& handles) {
    if(handles.empty()) {
      return;
    }
    size_t index = 0;
    while(true) {
      const size_t totalHandles = handles.size();
      const size_t remainingHandles = (index < totalHandles ? totalHandles - index : 0);
      if(remainingHandles == 0) {
        break;
      }
      const size_t maximumObjects = static_cast<size_t>(MAXIMUM_WAIT_OBJECTS);
      const size_t chunkCount = remainingHandles > maximumObjects ? maximumObjects : remainingHandles;
      const DWORD result = ::WaitForMultipleObjects(
        static_cast<DWORD>(chunkCount),
        handles.data() + index,
        TRUE, // wait for all in this chunk
        INFINITE
      );
      if(result == WAIT_FAILED) {
        for(size_t i = 0; i < chunkCount; ++i) {
          HANDLE handle = handles[index + i];
          if(handle) {
            ::WaitForSingleObject(handle, INFINITE);
          }
        }
      }
      index += chunkCount;
    }
    for(HANDLE handle : handles) {
      if(handle) {
        ::CloseHandle(handle);
      }
    }
  }
} //namespace SocketLibrary
