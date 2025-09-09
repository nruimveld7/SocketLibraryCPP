// include/SocketLibrary/WinSock2First.h
#pragma once
#if defined(_WINSOCKAPI_) && !defined(_WINSOCK2API_)
#  error "winsock.h was included before winsock2.h. Include WinSock2First.h before windows.h."
#endif

#ifndef _WINSOCK2API_
#  include <winsock2.h>
#endif
#include <ws2tcpip.h>