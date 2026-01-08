// include/SocketLibrary/WinSock2First.h
#pragma once

#if defined(_WINSOCKAPI_) && !defined(_WINSOCK2API_)
#  error "winsock.h was included before winsock2.h. Include SocketLibrary.h (or WinSock2First.h) before windows.h."
#endif

#pragma push_macro("min")
#pragma push_macro("max")
#undef min
#undef max

#ifndef NOMINMAX
#  define NOMINMAX
#  define SOCKETLIBRARYCPP_DEFINED_NOMINMAX
#endif

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#  define SOCKETLIBRARYCPP_DEFINED_LEAN_AND_MEAN
#endif

#ifndef _WINSOCK2API_
#  include <winsock2.h>
#endif
#include <ws2tcpip.h>
#include <windows.h>

#ifdef SOCKETLIBRARYCPP_DEFINED_LEAN_AND_MEAN
#  undef WIN32_LEAN_AND_MEAN
#  undef SOCKETLIBRARYCPP_DEFINED_LEAN_AND_MEAN
#endif

#ifdef SOCKETLIBRARYCPP_DEFINED_NOMINMAX
#  undef NOMINMAX
#  undef SOCKETLIBRARYCPP_DEFINED_NOMINMAX
#endif

#undef min
#undef max

#pragma pop_macro("max")
#pragma pop_macro("min")
