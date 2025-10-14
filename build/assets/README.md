# SocketLibraryCPP

**Windows static C++ socket library** for MSVC, built on **WinSock2**.  
Ready-to-use **TCP/UDP client & server** classes with async callbacks, a clean state machine, and automatic MSBuild wiring via NuGet.

---

## Highlights
- **Drop-in sockets:** `TCPClientSocket`, `TCPServerSocket`, `UDPClientSocket`, `UDPServerSocket`
- **Async callbacks** on worker threads (`SetOnRead`, `SetOnClientDisconnect`, etc.)
- **Configurable TCP framing** via `SetMaxLength(...)`
- **Zero external dependencies:** MSVC + WinSock2 only
- **Prebuilt x86/x64 static libs** auto-linked for Debug/Release
- **Strict include-order guard** (`winsock2.h` always first)

---

## Supported
| Category | Supported |
|-----------|------------|
| **Toolchain** | MSVC (Visual Studio 2019–2022) |
| **OS** | Windows desktop/server (XP → 11) |
| **Architectures** | x86, x64 |
| **Linking** | Static `.lib` |

---

## Install
Use NuGet Package Manager or the console:
```powershell
Install-Package SocketLibraryCPP
```
The package automatically:
- Adds `include/` to your **AdditionalIncludeDirectories**
- Selects the matching `.lib` for platform/configuration
- Injects the library into your **AdditionalDependencies**

---

## Quick Start

### TCP Server (receive + echo, broadcast capable)
```cpp
#include <SocketLibrary/TCPServerSocket.h>
using namespace SocketLibrary;

int main() {
    TCPServerSocket server;
    server.SetErrorHandler([](const std::string& msg) {
        //Log error message
    });
    server.SetUpdateHandler([](const std::string& msg) {
        //Log update message
    });
    server.SetOnRead([&](unsigned char* data, size_t count, SOCKET client){
        server.Send(data, count, client); // Echo back
        //server.Broadcast(data, count);
    });
    server.SetOnClientDisconnect([](const std::string& addr) {
        //Handle client disconnect
    });
    server.SetServerIP("0.0.0.0");
    server.SetServerPort(55555);
    server.SetMaxLength(1000);
    if(!server.Open()) {
        return 1;
    }
    while(true) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    server.Close();
}
```

---

### TCP Client (connect + send)
```cpp
#include <string>
#include <SocketLibrary/TCPClientSocket.h>
using namespace SocketLibrary;

int main() {
    TCPClientSocket client;
    client.SetErrorHandler([](const std::string& msg) {
        //Log error message
    });
    client.SetUpdateHandler([](const std::string& msg) {
        //Log update message
    });
    client.SetOnRead([](unsigned char* data, size_t count) {
        //Handle message
    });
    client.SetOnDisconnect([]() {
        //Handle disconnect
    });
    client.SetServerIP("127.0.0.1");
    client.SetServerPort(55555);
    client.SetMaxLength(1000);
    if(!client.Open()) {
        return 1;
    }
    std::string msg = "hello";
    client.Send(msg.c_str(), msg.size());
    while(true) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    client.Close();
}
```

---

### UDP Server (bind + echo, broadcast capable)
```cpp
#include <SocketLibrary/UDPServerSocket.h>
using namespace SocketLibrary;

int main() {
    UDPServerSocket server;
    server.SetErrorHandler([](const std::string& msg) {
        //Log error message
    });
    server.SetUpdateHandler([](const std::string& msg) {
        //Log update message
    });
    server.SetOnRead([&](unsigned char* data, size_t count, sockaddr_in client){
        server.Send(data, count, client); // Echo back
        //server.Broadcast(data, count);
    });
    server.SetServerIP("0.0.0.0");
    server.SetServerPort(55555);
    if(!server.Open()) {
        return 1;
    }
    while(true) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    server.Close();
}
```

---

### UDP Client (ephemeral bind + target caching)
```cpp
#include <string>
#include <SocketLibrary/UDPClientSocket.h>
using namespace SocketLibrary;

int main() {
    UDPClientSocket client;
    client.SetErrorHandler([](const std::string& msg) {
        //Log error message
    });
    client.SetUpdateHandler([](const std::string& msg) {
        //Log update message
    });
    client.SetOnRead([](unsigned char* data, size_t count, sockaddr_in sender) {
        //Handle message
    });
    client.SetServerIP("127.0.0.1");
    client.SetServerPort(55555);
    if(!client.Open()) {
        return 1;
    }
    std::string msg = "hello";
    client.Send(msg.c_str(), msg.size()); // uses cached target
    //client.Send(msg.c_str(), msg.size(), "127.0.0.1", 55555);
    while(true) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    client.Close();
}
```

---

## State Model

```
Idle --Open()--> Opening --Startup OK--> Active
            \                 \
             \--Fail----------> Closing --> Idle

Active --Close()--> Closing --> Idle
Opening --Close()--> Closing --> Idle
```

- `Open()` transitions `Idle → Opening → Active` on success  
- `Close()` transitions any state to `Closing → Idle`  
- TCP clients track extra internal flags: `connecting`, `connected`, `cancelling`

---

## Logging & Callbacks
- **Updates:** `SetUpdateHandler(...)`  
- **Errors:** `SetErrorHandler(...)`  
- **Traffic logs:** enable with `SetTrafficUpdates(true)`  
All callbacks are executed on internal worker threads — synchronize UI access if needed.

---

## Include Order
You don’t need to include `WinSock2First.h` manually.  
Our headers enforce the correct order and will emit a compile-time error if `winsock.h` appears first.

---

## Troubleshooting
| Issue | Resolution |
|--------|-------------|
| *Include order error* | Include SocketLibrary headers before `<Windows.h>` |
| *Link errors* | Ensure platform/config (x86/x64, Debug/Release) matches the packaged libs |
| *Address in use* | TCP server uses `SO_EXCLUSIVEADDRUSE` — close any other binders |
| *Partial sends* | Indicates closed peer or fatal socket error; check your ErrorHandler |

---

## License
MIT (see `LICENSE` in the package).

## Source & Documentation
GitHub: [https://github.com/nruimveld7/SocketLibraryCPP](https://github.com/nruimveld7/SocketLibraryCPP)
