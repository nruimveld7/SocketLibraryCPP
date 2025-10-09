# SocketLibraryCPP

**Windows static C++ socket library** for MSVC, built on **WinSock2**.  
Ready‑to‑use **TCP/UDP client & server** classes with simple async callbacks, clean state machine, and automatic MSBuild wiring via NuGet.

---

## Highlights
- **Drop‑in sockets:** `TCPClientSocket`, `TCPServerSocket`, `UDPClientSocket`, `UDPServerSocket`
- **Async callbacks** on worker threads (`SetOnRead`, `SetOnClientDisconnect`, etc.)
- **Fixed‑length TCP framing** via `SetMessageLength(...)`
- **Zero external deps:** MSVC + WinSock2 only
- **Prebuilt x86/x64 static libs** with **auto include/lib** wiring for Debug/Release
- **Strict include‑order guard** to keep `winsock2.h` first


## Supported
- **Toolchain:** MSVC (Visual Studio)
- **OS:** Windows desktop/server
- **Architectures:** x86, x64
- **Linking:** static `.lib`

## Install
Use the NuGet UI or Package Manager Console in your C++ project:
```powershell
Install-Package SocketLibraryCPP
```
The package automatically:
- Adds `include/` to **AdditionalIncludeDirectories**
- Selects the correct **.lib** for your current **Platform/Configuration**
- Injects the library into your **AdditionalDependencies**

## Quick start

### TCP server (recv + echo, broadcast capable)
```cpp
#include <string>
#include <SocketLibrary/TCPServerSocket.h>
using namespace SocketLibrary;

int main() {
    TCPServerSocket server;
    //Optional: receive socket errors
    server.SetErrorHandler([&](const std::string& message)) {
        //Log error message
    }
    //Optional: receive socket logs
    server.SetUpdateHandler([&](const std::string& message)) {
        //Log update message
    }
    //Optional: accept replies from server
    server.SetServerIP("0.0.0.0");
    server.SetServerPort(55555);
    server.SetMessageLength(1000);
    //Called when bytes arrive from a client
    server.SetOnRead([&](unsigned char* data, size_t count, SOCKET client){
        server.Send(data, count, client); //Echo back
        //server.Broadcast(data, count);
    });
    //Optional: observe disconnects
    server.SetOnClientDisconnect([&](const std::string& clientAddress){
        //Log/cleanup
    });
    if(!server.Open()) {
        //Handle startup error
        return 1;
    }
    while(true) {
        //Run until shutdown
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    server.Close();
}
```

### TCP client (connect + send)
```cpp
#include <string>
#include <SocketLibrary/TCPClientSocket.h>
using namespace SocketLibrary;

int main() {
    TCPClientSocket client;
    client.SetErrorHandler([&](const std::string& message)) {
        //Log error message
    }
    client.SetUpdateHandler([&](const std::string& message)) {
        //Log update message
    }
    client.SetServerIP("127.0.0.1");
    client.SetServerPort(55555);
    server.SetMessageLength(1000);
    client.SetOnRead([](unsigned char* data, size_t count){
        //Handle server response
    });
    //Optional: observe disconnects
    client.SetOnDisconnect([](){
        //Server closed or connection lost
    });
    if(!client.Open()) {
        //Handle startup error
        return 1;
    }
    std::string message = "hello";
    client.Send(message.c_str(), message.size());
    while(true) {
        //Run until shutdown
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    client.Close();
}
```

### UDP server (recv + echo, broadcast capable)
```cpp
#include <string>
#include <SocketLibrary/UDPServerSocket.h>
using namespace SocketLibrary;

int main() {
    UDPServerSocket server;
    server.SetErrorHandler([&](const std::string& message)) {
        //Log error message
    }
    server.SetUpdateHandler([&](const std::string& message)) {
        //Log update message
    }
    server.SetServerIP("0.0.0.0");
    server.SetServerPort(55555);
    server.SetMessageLength(1000);
    //Called when bytes arrive from a client
    server.SetOnRead([&](unsigned char* data, size_t count, sockaddr_in client){
        server.Send(data, count, client); //Echo back
        //server.Broadcast(data, count);
    });
    if(!server.Open()) {
        //Handle startup error
        return 1;
    }
    while(true) {
        //Run until shutdown
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    server.Close();
}
```

### UDP client (ephemeral bind + target caching)
```cpp
#include <string>
#include <SocketLibrary/UDPClientSocket.h>
using namespace SocketLibrary;

int main() {
    UDPClientSocket client;
    client.SetErrorHandler([&](const std::string& message)) {
        //Log error message
    }
    client.SetUpdateHandler([&](const std::string& message)) {
        //Log update message
    }
    client.SetServerIP("127.0.0.1");
    client.SetServerPort(55555);
    client.SetMessageLength(1000);
    client.SetOnRead([](unsigned char* data, size_t count, sockaddr_in sender){
        //Handle incoming datagrams
    });
    if(!client.Open()) {
        //Handle startup error
        return 1;
    }
    std::string message = "hello";
    //Optional: Send with a provided address will set the server credentials
    //client.Send(message.c_str(), message.size(), "127.0.0.1", 55555);
    //Send with no provided address will use the previous server credentials
    client.Send("again", 5);
    
    while(true) {
        //Run until shutdown
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    client.Close();
}
```

---

## State model (concise)

The base socket has four states. TCP client also tracks `connected/connecting/cancelling` internally, but those are **not** part of the base state.

```
Idle --Open()--> Opening --Startup OK--> Active
            \                 \
             \--Startup Fail--> Closing --> Idle

Active --Close()--> Closing --> Idle
Opening --Close()--> Closing --> Idle
```

- `Open()` moves `Idle → Opening` and calls `Startup()`.
- On success, the object becomes `Active` (spawns workers).
- `Close()` from any state transitions to `Closing`, waits for workers to stop, performs `Cleanup()`, and returns to `Idle`.

---

## Logging & callbacks
- **Update** messages via `SetUpdateHandler(...)`
- **Errors** via `SetErrorHandler(...)` (exceptions inside handlers are caught)
- Optional: `SetTrafficUpdates(true)` for per‑send/recv logs


## Windows headers & include order
- If you need `<Windows.h>`, include it **after** the library headers or define `WIN32_LEAN_AND_MEAN` / `NOMINMAX` as appropriate.
- You **do not** need to include `WinSock2First.h` directly — our headers ensure correct include order and will fail fast if something pulls in `winsock.h` first.

## Troubleshooting
- **Include‑order error**: Ensure `winsock2.h` is included before any legacy `winsock.h` (the library enforces this).
- **Link errors**: Confirm Platform (x86/x64) and Configuration (Debug/Release) match your installed package libs.

## License
MIT (see `LICENSE` in the package).

## Source, issues, docs
GitHub: https://github.com/nruimveld7/SocketLibraryCPP
