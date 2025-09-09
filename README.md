# SocketLibraryCPP

Windows static socket library (MSVC) with public headers and MSBuild-based NuGet integration.  
Designed for Windows (WinSock2) consumers; cross‑platform is out of scope for now.

## Folder layout

```
SocketLibraryCPP/
  include/                   # public headers (what consumers include)
    SocketLibrary.h
    SocketLibrary/
      Socket.h
      WinSock2First.h
      ...

  build/native/              # NuGet MSBuild imports (props/targets) + staged headers/libs
    SocketLibraryCPP.props
    SocketLibraryCPP.targets

  lib/<Platform>/<Config>/   # built .lib staged here (not committed)
  intermediate/              # obj/temp (not committed)

  src/SocketLibraryCPP/      # .vcxproj for the static lib
  pkg/SocketLibraryCPP.nuspec
  README.md
  LICENSE
```

## Build (from source)

- Open `SocketLibraryCPP.sln` in Visual Studio.
- Select a configuration and platform (e.g., **x64/Release**).
- Build the solution.

**Outputs (by convention):**  
`lib/x64/Debug/SocketLibraryCPP.lib`, `lib/x64/Release/SocketLibraryCPP.lib`,  
`lib/Win32/Debug/SocketLibraryCPP.lib`, `lib/Win32/Release/SocketLibraryCPP.lib`.

> The `.vcxproj` can set `OutDir` and `IntDir` so outputs land under `lib/` and `intermediate/`.
> These directories are ignored by git and only staged into the NuGet package when packing.

## Consume (via NuGet PackageReference)

1. Publish the `.nupkg` to your private feed (see **Pack** below).  
2. In your consumer project, add your feed in **Tools → NuGet Package Manager → Package Sources**.  
3. Install:
   ```powershell
   Install-Package SocketLibraryCPP -Version <version>
   ```
4. In code:
   ```cpp
   #include "SocketLibrary.h"

   int main() {
       // minimal sanity compile — adjust to your API surface
       // SocketLibrary::Socket sock; // example: if you expose such a type
       return 0;
   }
   ```

The package’s `build/native/SocketLibraryCPP.props` adds `include/` to your `AdditionalIncludeDirectories`.  
`build/native/SocketLibraryCPP.targets` adds the correct `lib/<Platform>/<Config>/` to `AdditionalLibraryDirectories` and links `SocketLibraryCPP.lib` automatically.

## Pack (local test)

1. Build the library so `.lib` files exist under the `lib/<Platform>/<Config>/` folders.
2. From repo root, run:
   ```powershell
   nuget pack pkg/SocketLibraryCPP.nuspec -NoDefaultExcludes
   ```
   This produces `SocketLibraryCPP.<version>.nupkg` in the current directory.

> **Why `-NoDefaultExcludes`?** It ensures top‑level `README.md` and `LICENSE` are included when referenced by the `.nuspec`.

## Nuspec layout (summary)

- Public headers are packed under `build/native/include/`
- MSBuild imports live at `build/native/SocketLibraryCPP.props` and `.targets`
- Built libraries are packed under `build/native/lib/<Platform>/<Config>/`

A minimal nuspec metadata block looks like:

```xml
<metadata>
  <id>SocketLibraryCPP</id>
  <version>0.1.0</version>
  <authors>Noah Ruimveld</authors>
  <description>Windows static socket library with MSBuild integration via props/targets.</description>
  <license type="file">LICENSE</license>
  <repository type="git" url="https://github.com/nruin7/SocketLibraryCPP.git" />
  <packageTypes>
    <packageType name="Native" />
  </packageTypes>
</metadata>
```

## Verification checklist

- [ ] Fresh clone builds **Win32/x64 × Debug/Release** without committing outputs.
- [ ] `nuget pack` succeeds and includes headers, props/targets, and platform libs.
- [ ] A sample Console App installs the package and compiles with `#include "SocketLibrary.h"`.
- [ ] Link step succeeds (targets add `SocketLibraryCPP.lib` automatically).

## Contributing

Issues and PRs are welcome. Keep public API in `include/` stable; breaking changes should bump the minor/major version per semver.

## License

This project is licensed under the terms of the LICENSE file included in the repository.
