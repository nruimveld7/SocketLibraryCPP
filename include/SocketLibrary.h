// include/SocketLibrary.h
#pragma once

// Users may define these before including this header:
//   #define SOCKETLIBRARY_ENABLE_TCP  1   // or 0
//   #define SOCKETLIBRARY_ENABLE_UDP  1   // or 0
//
// Default: if neither is defined, enable both.
#if !defined(SOCKETLIBRARY_ENABLE_TCP) && !defined(SOCKETLIBRARY_ENABLE_UDP)
#  define SOCKETLIBRARY_ENABLE_TCP 1
#  define SOCKETLIBRARY_ENABLE_UDP 1
#endif

#if SOCKETLIBRARY_ENABLE_TCP
#  include "SocketLibrary/TCPServerSocket.h"
#  include "SocketLibrary/TCPClientSocket.h"
#endif

#if SOCKETLIBRARY_ENABLE_UDP
#  include "SocketLibrary/UDPServerSocket.h"
#  include "SocketLibrary/UDPClientSocket.h"
#endif
