# SocketLibraryCPP

**Windows static C++ socket library** for MSVC, built on **WinSock2**.  
Delivers ready‑to‑use **TCP/UDP client & server** classes with simple async callbacks. The package includes headers and MSBuild wiring so Visual Studio projects get **auto include paths and linking** per platform/config—no manual project edits needed.

> This README is for the NuGet package page. For repository details and advanced usage, see the GitHub README in the root of the repo.

---

## Highlights
- **Out‑of‑the‑box sockets:** `TCPClientSocket`, `TCPServerSocket`, `UDPClientSocket`, `UDPServerSocket`
- **Asynchronous I/O with callbacks** (invoked off worker threads)
- **Zero external dependencies:** MSVC toolchain + WinSock2 only
- **Prebuilt x86/x64 static libs** (Debug/Release) with automatic MSBuild integration
- **Strict include‑order guard**: library headers ensure `winsock2.h` precedes any Windows headers

## Supported
- **Toolchain:** MSVC (Visual Studio)
- **OS:** Windows desktop/server (modern releases; earlier may work but aren’t in the test matrix)
- **Architectures:** x86, x64
- **Linking:** static `.lib` (no runtime DLL required)

## Install
Use the NuGet UI or Package Manager Console in your C++ project:
```powershell
Install-Package SocketLibraryCPP
```
The package automatically:
- Adds `include/` to **AdditionalIncludeDirectories**
- Selects the correct **.lib** for your current **Platform/Configuration**
- Injects the library into your **AdditionalDependencies**

No manual include/lib path editing is necessary.

## Quick start

### TCP server (echo example)
```cpp
#include <SocketLibrary/TCPServerSocket.h>
using namespace SocketLibrary;

int main() {
    TCPServerSocket server;
    server.SetIP("0.0.0.0");
    server.SetPort(5555);

    // Called when bytes arrive from a client.
    server.SetOnRead([&](unsigned char* data, int count, SOCKET client){
        server.Send(data, count, client); // echo back
    });

    // Optional: observe disconnects
    server.SetOnClientDisconnect([&](SOCKET client){
        // log / cleanup
    });

    if (!server.Open()) {
        // handle error (e.g., log via your handler)
        return 1;
    }
    // ... run until shutdown ...
    server.Close();
}
```

### TCP client (connect + send)
```cpp
#include <SocketLibrary/TCPClientSocket.h>
using namespace SocketLibrary;

int main() {
    TCPClientSocket client;
    client.SetIP("127.0.0.1");
    client.SetPort(5555);

    client.SetOnRead([](unsigned char* data, int count){
        // handle server response
    });
    client.SetOnDisconnect([](){
        // server closed or connection lost
    });

    if (!client.Open()) {
        // handle connection error
        return 1;
    }

    const char* hello = "hello";
    client.Send(hello, 5);
    // ...
    client.Close();
}
```

### UDP server (recv + reply, broadcast capable)
```cpp
#include <SocketLibrary/UDPServerSocket.h>
using namespace SocketLibrary;

int main() {
    UDPServerSocket udp;
    udp.SetIP("0.0.0.0");
    udp.SetPort(5555);

    udp.SetOnRead([&](unsigned char* data, int count, sockaddr_in from){
        // reply to sender
        udp.Send(data, count, from);
        // or: udp.Broadcast(data, count);
    });

    if (!udp.Open()) {
        return 1;
    }
    // ...
    udp.Close();
}
```

### UDP client (ephemeral bind + target caching)
```cpp
#include <SocketLibrary/UDPClientSocket.h>
using namespace SocketLibrary;

int main() {
    UDPClientSocket udp;
    if (!udp.Open()) return 1;

    // First send sets the target
    udp.Send("ping", 4, "192.168.1.10", 5555);
    // Subsequent sends can omit the target (uses the last one)
    udp.Send("again", 5);

    // Optionally receive via callback if configured
    udp.SetOnRead([](unsigned char* data, int count){
        // handle incoming datagrams
    });

    udp.Close();
}
```

> **Note:** Callback signatures and additional methods are documented in the public headers.

## Windows headers & include order
- If you need `<Windows.h>`, include it **after** the library headers or define `WIN32_LEAN_AND_MEAN` / `NOMINMAX` as appropriate.
- You **do not** need to include `WinSock2First.h` directly — our headers ensure correct include order and will fail fast if something pulls in `winsock.h` first.

## Troubleshooting
- **“winsock.h was included before winsock2.h”**  
  Include SocketLibrary headers before any Windows headers.
- **`std::min`/`std::max` macro conflicts**  
  Define `NOMINMAX` before including `<Windows.h>` (or set it project‑wide).
- **Link errors**  
  Ensure you’re building **Debug/Release × x86/x64** so the matching `.lib` exists.

## License
MIT (see `LICENSE` in the package).

## Source, issues, docs
GitHub: https://github.com/nruimveld7/SocketLibraryCPP
