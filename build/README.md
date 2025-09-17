# SocketLibraryCPP (NuGet)

Windows **static C++ socket library** for MSVC, built on **WinSock2**.  
Ships with headers + `.props/.targets` so Visual Studio projects get **auto include paths and linking** per platform/config.

## What you get
- TCP/UDP **client & server** classes
- Simple async callbacks (see **Callbacks** below)
- The library headers handle correct include order and will emit a compile‑time error if Windows headers are included first
- Prebuilt **x86/x64** static libraries (Debug/Release)
- No external runtime deps (MSVC + WinSock2 only)

## Supported
- **Toolchain:** MSVC (Visual Studio)
- **OS:** Windows (tested on the latest desktop & server releases; earlier versions may work but are not in the test matrix)
- **Architectures:** x86, x64

## Install
Use the NuGet UI or Package Manager Console in your C++ project:
```powershell
Install-Package SocketLibraryCPP
```
The package drops:
- Headers into your include path (`build/native/include`)
- Platform/config‑specific `.lib` into your linker inputs (`build/native/lib/<Platform>/<Config>`)

No manual include/lib path editing is needed.

## Quick start (minimal)
> Replace with your project's actual setup as needed. This uses the server type.
```cpp
#include "SocketLibrary.h"                 // brings in the library; includes are ordered safely
#include <Windows.h>                       // optional; include Windows AFTER the socket headers

int main() {
    TCPServerSocket server;

    // Open your server (adjust to your configuration/port as needed)
    server.Open();

    // Register callbacks (example signatures below)
    server.SetOnRead([](unsigned char* msg, int len, SOCKET* sender) {
        // handle inbound bytes
    });
    server.SetOnClientDisconnect([](){
        // handle disconnect
    });

    // ...
    return 0;
}
```

### Notes on Windows headers
- If you need `std::min` / `std::max`, **define `NOMINMAX`** before including `<Windows.h>`.
- You **do not** include `SocketLibrary/WinSock2First.h` directly; headers ensure WinSock2 is first.

## Callbacks
List the async callbacks your project exposes so consumers know what’s available. Examples:

| Type              | Method                    | Signature                                               | Fires when…                 |
|-------------------|---------------------------|---------------------------------------------------------|-----------------------------|
| `TCPServerSocket` | `SetOnRead`               | `(unsigned char* message, int byteCount, SOCKET* sender)` | Data is received            |
| `TCPServerSocket` | `SetOnClientDisconnect`   | `()`                                                    | A client disconnects        |
| *(add others, if any)* | *(e.g., `SetOnClientConnect`)* | *(your signature here)*                                 | *(describe trigger)*        |

> Tip: keep this table authoritative. If you add new callbacks or change signatures, update here.

## Configuration
The package’s MSBuild files (`SocketLibraryCPP.props` / `SocketLibraryCPP.targets`) automatically:
- add `include/` to **AdditionalIncludeDirectories**
- select the right **lib directory** for your current **Platform/Configuration**
- link **`SocketLibraryCPP.lib`**

You can override or inspect these in **Project → Properties → VC++ Directories / Linker**.

## Examples
**NuGet package does not include examples.** Example projects live in the GitHub repository and are meant for reference when working from source.

## Troubleshooting
- **“winsock.h was included before winsock2.h”**  
  Include the library headers first; they enforce the correct order and will fail fast if something brings in `winsock.h` too early.
- **`std::min`/`std::max` are macros**  
  Define `NOMINMAX` before `<Windows.h>` (or define it project‑wide).
- **Link errors**  
  Make sure you’re building one of the standard configs (**Debug/Release** × **x86/x64**) so the correct `.lib` exists.

## License
MIT (see `LICENSE` in the package).

## Source, issues, docs
GitHub: https://github.com/nruimveld7/SocketLibraryCPP
