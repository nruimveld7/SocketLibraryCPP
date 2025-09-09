#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
// Guarantees correct winsock include order
#include "SocketLibrary/WinSock2First.h"

// Pull Win32 only if your .cpps use it broadly (FormatMessage, HANDLE, etc.)
#include <windows.h>

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
#include <utility>
#include <sstream>
#include <cstdlib>
#include <algorithm>
#include <exception>