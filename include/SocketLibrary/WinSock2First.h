// include/SocketLibrary/WinSock2First.h
#pragma once
#if defined(_WINSOCKAPI_) && !defined(_WINSOCK2API_)
  #error "winsock.h was included before winsock2.h. Include SocketLibrary.h before windows.h."
  #define SOCKETLIB_WINSOCK_ORDER_BAD 1
#endif

#ifndef SOCKETLIB_WINSOCK_ORDER_BAD
  #ifndef _WINSOCK2API_
    #include <winsock2.h>
  #endif
  #include <ws2tcpip.h>
#endif
