# ArgusEDR

A research-grade Endpoint Detection and Response (EDR) system for Windows, written in C/C++. Argus detects process injection by combining API hooking, memory scanning, and YARA signatures, and unifies those signals in a single correlation engine.

> **Status:** research prototype built for the Hakeriot program. Not intended for production use.

## How it works

```
 Monitored process                          Argus
┌──────────────────┐   named pipe   ┌───────────────────────────┐
│  Hook DLL        │ ─────────────▶ │  Correlator (Diamond FSM) │
│  (Detours)       │    events      │                           │
└──────────────────┘                │   ◀── YARA scan results   │
                                    │   ◀── PE-Sieve findings   │
                                    └─────────────┬─────────────┘
                                                  ▼
                                        Severity + alert output
```

1. **Hooks.** A DLL injected into target processes uses [Microsoft Detours](https://github.com/microsoft/Detours) to hook APIs commonly abused for injection and reports each call as an event.
2. **IPC.** Events travel over a named pipe to the correlator. On the receiving side, a thread-safe circular `EventQueue` (guarded by `CRITICAL_SECTION`, drop-oldest on overflow) buffers bursts so hooked processes are never blocked.
3. **Detection.** Suspicious memory is checked with [YARA](https://virustotal.github.io/yara/) rules and [PE-Sieve](https://github.com/hasherezade/pe-sieve) memory scans.
4. **Correlation.** The **Diamond FSM** merges all signals per process. Severity only escalates, never drops:

   `IDLE → LOW → MEDIUM → HIGH → CRITICAL`

## Components

| Component | Role |
|---|---|
| Hook DLL | Detours-based API hooking inside target processes |
| `injector.exe` | Injects the hook DLL into a target process |
| IPC layer | Named-pipe transport and `EventQueue` buffering |
| Correlator | Diamond FSM that combines signals into a severity level |
| YARA path | Signature matching on suspicious memory |
| `argus_pesieve` | PE-Sieve integration for memory scanning |

## Requirements

- Windows 10/11 (x64)
- MSVC (Visual Studio 2022 Build Tools or newer)
- CMake 3.20+
- [vcpkg](https://github.com/microsoft/vcpkg)

## Build

Clone with submodules so PE-Sieve is pulled in:

```powershell
git clone --recurse-submodules https://github.com/<your-user>/<repo>.git
cd <repo>
```

Configure and build:

```powershell
cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=<path-to-vcpkg>/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release
```

If the `pe-sieve` submodule is empty, the `argus_pesieve` DLL and its integration test are skipped. The hooks → IPC → correlator → YARA path still works, but PE-Sieve detection stays inactive. To enable it:

```powershell
git submodule update --init --recursive
```

## Usage

```powershell
# 1. Start the correlator
.\build\Release\<correlator>.exe

# 2. Inject the hook DLL into a target process
.\build\Release\injector.exe <pid>
```

Run these only inside a VM or another isolated test environment.

## Project layout

```
<fill in your top-level folders, e.g. src/, hooks/, correlator/, rules/, docs/>
```

## Roadmap

- [ ] Re-enable the PE-Sieve integration test and `argus_pesieve` DLL
- [ ] <next milestone>

## Acknowledgments

Built as part of the **Hakeriot** program by Lotem Goren and Nikol Kofman, under the guidance of Eli Shparaga.

Uses [Microsoft Detours](https://github.com/microsoft/Detours), [PE-Sieve](https://github.com/hasherezade/pe-sieve), and [YARA](https://virustotal.github.io/yara/).


