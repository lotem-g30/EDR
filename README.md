# ArgusEDR

A research-grade Endpoint Detection and Response (EDR) prototype for Windows, written in C/C++. Argus detects process injection by combining user-mode API hooking (Microsoft Detours), in-process memory scanning (PE-Sieve), and YARA signature matching, and correlates all three signals in a per-process state machine that can terminate the offending process.

> **Status:** research prototype built for the Hakeriot program. Not intended for production use. Run it only inside a VM or another isolated test environment.

## How it works

```
 Monitored process                                     argus_agent.exe
┌────────────────────────────────────┐
│ argus_hook.dll                     │   \\.\pipe\argus-events     ┌──────────────────────────┐
│  Detours hooks → EventQueue ───────┼──────────────────────────▶ │ IPC server               │
│                                    │                             │   │ trigger              │
│ argus_pesieve.dll                  │   \\.\pipe\argus-pesieve    │   ▼                      │
│  memory watcher + PE-Sieve scan ───┼──────────────────────────▶ │ Scanner + YARA (rules/)  │
└────────────────────────────────────┘                             │   │ findings             │
                                                                   │   ▼                      │
                                                                   │ Diamond FSM correlator   │
                                                                   │   → verdict / kill       │
                                                                   └──────────────────────────┘
```

1. **Hooks** – `argus_hook.dll` is injected into a target process and hooks six APIs with Detours: `VirtualAlloc`, `VirtualAllocEx`, `WriteProcessMemory`, `VirtualProtect`, `CreateRemoteThread`, and `CreateThread` (reported only when the thread starts in private, non-image memory). Each call becomes a JSON event.
2. **Queue and IPC** – Events go into a thread-safe circular `EventQueue` (4096 slots, `CRITICAL_SECTION`, drop-oldest on overflow) so the hooked process is never blocked, and a drain thread ships them over the `argus-events` named pipe.
3. **Scanning** – Every hooked event also triggers a memory and YARA scan of the target. In parallel, `argus_pesieve.dll` runs a 200 ms private-executable-memory watcher plus periodic PE-Sieve structural scans, and reports findings over the `argus-pesieve` pipe. It filters out Argus's own Detours relays so the EDR doesn't flag itself.
4. **Correlation** – The **Diamond FSM** tracks capability flags per PID. Severity only escalates, never drops:

| Severity | Condition |
|---|---|
| LOW | Memory allocated (`VirtualAlloc` / `VirtualAllocEx`) |
| MEDIUM | Bytes written into a tracked allocation, or memory made executable |
| HIGH | Written **and** made executable |
| CRITICAL | A remote thread (or a thread in private memory) is created, **or** a YARA rule matches |

PE-Sieve findings that fall in a region already captured by a hook event are deduplicated, so one injection isn't counted twice.

**Active response.** When a process reaches CRITICAL, the agent terminates it after a 500 ms grace period. This is on by default. To monitor without killing, set `ENABLE_ACTIVE_RESPONSE = false` in `src/agent/main.c`.

## Repository layout

```
src/
  hook_dll/         argus_hook.dll: Detours hooks, EventQueue, pipe client
  pesieve_dll/      argus_pesieve.dll: memory watcher, PE-Sieve scans, self-hook filtering
  agent/            argus_agent.exe: IPC servers, scanner, YARA, Diamond FSM correlator
  injector/         injector.exe: CreateRemoteThread + LoadLibraryA DLL injector
  test_*/           attack simulations and the false-positive check (see Tests)
  shellcode_runner/ in-process shellcode loader test
include/argus/      shared headers (event and finding types)
rules/              YARA rules (Elastic Security)
dashboard/          FastAPI + WebSocket live dashboard
tests/              end-to-end test (Python)
exercises/          standalone unit tests: EventQueue, FSM, PE-Sieve correlator feed
pe-sieve/           PE-Sieve (git submodule)
run_demo.ps1        demo runner (needs the agent already running)
run_test.ps1        standalone end-to-end run (starts its own agent)
start_dashboard.bat launches the dashboard at http://localhost:8080
```

## Requirements

- Windows 10/11 x64
- Visual Studio 2022 with the C++ workload (MSVC)
- CMake 3.20 or newer
- [vcpkg](https://github.com/microsoft/vcpkg). `vcpkg.json` pulls in `cjson`, `detours`, and `yara` automatically.
- Python 3.9+ (dashboard and end-to-end test only)

## Build

Clone with submodules so PE-Sieve is included:

```powershell
git clone --recurse-submodules https://github.com/lotem-g30/EDR.git
cd EDR
```

If `pe-sieve/` is empty after cloning, fetch it manually. It needs to be at the pinned commit, with its own submodules:

```powershell
git clone --recursive https://github.com/hasherezade/pe-sieve.git pe-sieve
git -C pe-sieve checkout f1dc39d
git -C pe-sieve submodule update --init --recursive
```

Configure and build (adjust the vcpkg path to your install):

```powershell
cmake -B build -S . -A x64 `
  -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake `
  -DVCPKG_TARGET_TRIPLET=x64-windows
cmake --build build --config Release
```

All binaries land in `build\bin\<Config>\`, and `rules\` is copied next to `argus_agent.exe` after every build.

`CMakePresets.json` is also provided (Ninja, `x64-debug` / `x64-release`), but it hardcodes `C:/vcpkg` and a specific MSVC path, so edit those first.

## Run

Use an **elevated** PowerShell (the injector needs `PROCESS_ALL_ACCESS`). Real-time antivirus will flag the EICAR test string that `test_target` writes to memory, so add the build folder to Defender exclusions or use a dedicated VM.

**Manual walkthrough**

```powershell
cd build\bin\Release

# 1. Start the agent (leave it running)
.\argus_agent.exe

# 2. In a second elevated shell: start the victim and note its PID
.\test_target.exe

# 3. Inject the monitoring DLLs
.\injector.exe <PID> argus_hook.dll
.\injector.exe <PID> argus_pesieve.dll

# 4. Press ENTER in test_target and watch the agent escalate
#    LOW → MEDIUM → HIGH → CRITICAL
```

`test_target` performs the full allocate → write → protect → thread chain, so every FSM flag fires in order.

**Dashboard**

```powershell
.\start_dashboard.bat
```

Opens http://localhost:8080. **RUN DEMO** restarts the agent, launches `test_target`, injects both DLLs, and streams severity changes live.

**Scripts**

```powershell
.\run_test.ps1     # starts its own agent, runs the demo, saves agent/target output to files
```

## Tests

| Test | What it checks |
|---|---|
| `tests/e2e_full_system_test.py` | Full pipeline: agent + `test_target` + injector must reach CRITICAL. Exit code 0 = pass. Run with `python tests\e2e_full_system_test.py --bin-dir build\bin\Release` |
| `test_target` | Allocate / write / protect / thread chain with an EICAR payload |
| `shellcode_runner` | In-process shellcode (RWX allocation + memcpy + new thread, no `WriteProcessMemory`) |
| `test_ProcessHollowing` | Classic x64 process hollowing into a suspended `notepad.exe` |
| `test_ModuleStomping`, `test_ModuleStomping2` | Module stomping at `user32.dll` / `amsi.dll` entry points |
| `test_FalsePositive` | Injects Argus into a running JIT process (PowerShell, node, Java); expected result is MEDIUM at most, never CRITICAL |
| `dummy_malware` | Self-patching process used to exercise PE-Sieve detection |
| `test_eq` | `EventQueue` unit test (ordering, empty pop, overflow drop-oldest) |

Manual test details are in [`tests/README.md`](tests/README.md).

## Limitations

- User-mode only. Hooks are installed per process via DLL injection, and Argus does not monitor anything it hasn't been injected into.
- The hooks sit on high-level Win32 APIs, so techniques that call NT syscalls directly bypass them.
- Detection depends on rule coverage. YARA scanning skips memory regions larger than 100 MB.

## Acknowledgments

Built as part of the **Hakeriot** program by Lotem Goren and Nikol Kofman, under the guidance of Eli Shparaga.

## Third-party components

| Component | License |
|---|---|
| [Microsoft Detours](https://github.com/microsoft/Detours) | MIT |
| [PE-Sieve](https://github.com/hasherezade/pe-sieve) | BSD-2-Clause |
| [YARA](https://virustotal.github.io/yara/) | BSD-3-Clause |
| [cJSON](https://github.com/DaveGamble/cJSON) | MIT |
| YARA rules in `rules/` (Elastic Security, [protections-artifacts](https://github.com/elastic/protections-artifacts)) | Elastic License v2 |
