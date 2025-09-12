#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
// Guarantees correct winsock include order
#include "SocketLibrary/WinSock2First.h"

// Pull windows.h and process.h becuase .cpps use them broadly
#include <windows.h>
#include <process.h>

// Common STL used across many .cpps (add/remove to taste)
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <functional>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <stdexcept>
#include <thread>
#include <chrono>
#include <limits>
#include <utility>
#include <sstream>
#include <cstdlib>
#include <algorithm>
#include <exception>
