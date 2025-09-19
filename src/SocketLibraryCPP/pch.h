#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif

// Guarantees correct winsock include order
#include "SocketLibrary/WinSock2First.h"

// Common STL used across many .cpps
#include <windows.h>
#include <process.h>
#include <mstcpip.h>
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
