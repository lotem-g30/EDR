/*
 * test_target.c
 * Minimal target process for Diamond FSM Correlator E2E testing.
 *
 * Executes the full "Trinity" injection sequence so every FSM capability
 * flag fires in order and the YARA scan catches the EICAR test string:
 *
 *   ALLOC   — VirtualAllocEx (PAGE_READWRITE)          → has_allocated    → LOW
 *   WRITE   — WriteProcessMemory (EICAR test string)   → has_written      → MEDIUM
 *   PROTECT — VirtualProtect   (PAGE_EXECUTE_READ)     → has_protected    → HIGH
 *             ↳ YARA scan triggers → Multi_EICAR_ac8f42d6 fires
 *               → correlator_feed_yara → has_yara → SEVERITY_CRITICAL
 *   THREAD  — CreateRemoteThread (self)                → has_remote_thread → CRITICAL
 *
 * !! WARNING !!
 * The EICAR payload string is the universal antivirus test signature.
 * Writing it to process memory WILL trigger Windows Defender and most
 * resident AV engines, which may kill this process before our EDR does.
 * Before running E2E tests, either:
 *   • Add the project build directory to Defender exclusions, OR
 *   • Disable real-time protection in a dedicated test VM.
 *
 * Manual workflow:
 *   1. Start argus_agent.exe
 *   2. Start test_target.exe  (note the printed PID)
 *   3. Run: injector.exe <PID> argus_hook.dll
 *   4. Press ENTER — Trinity executes
 *   5. Observe agent escalate LOW → MEDIUM → HIGH → CRITICAL
 *   6. Press ENTER again to free memory and exit
 *
 * Note: VirtualProtect (not VirtualProtectEx) is used intentionally —
 * argus_hook.dll hooks VirtualProtect directly via Detours.
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>

static DWORD WINAPI dummy_thread(LPVOID p) { (void)p; return 0; }

/*
 * Standard EICAR antivirus test string — matched by Multi_EICAR.yar rule
 * "Multi_EICAR_ac8f42d6" (ascii fullword condition).
 * The single backslash in the original string is escaped as \\ in C.
 */
#define EICAR_PAYLOAD \
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

int main(void)
{
    DWORD pid = GetCurrentProcessId();
    printf("\n  ArgusEDR  /  Trinity-EICAR test target\n");
    printf("  ----------------------------------------\n");
    printf("  PID    %lu\n", pid);
    printf("  Inject injector.exe %lu argus_hook.dll\n\n", pid);
    printf("  Press ENTER after injection...\n");
    getchar();

    /* ── ALLOC ── */
    LPVOID mem = VirtualAllocEx(
        GetCurrentProcess(), NULL,
        4096, MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);
    if (!mem) {
        fprintf(stderr, "  ERROR  VirtualAllocEx failed (%lu)\n", GetLastError());
        return 1;
    }
    Sleep(20000);

    /* ── WRITE ── */
    const char* payload = EICAR_PAYLOAD;
    SIZE_T written = 0;
    BOOL wpm_ok = WriteProcessMemory(
        GetCurrentProcess(), mem,
        payload, strlen(payload) + 1,
        &written);
    if (!wpm_ok) {
        fprintf(stderr, "  ERROR  WriteProcessMemory failed (%lu)\n", GetLastError());
        VirtualFree(mem, 0, MEM_RELEASE);
        return 1;
    }
    Sleep(20000);

    /* ── PROTECT ── */
    DWORD old_protect = 0;
    BOOL vp_ok = VirtualProtect(mem, 4096, PAGE_EXECUTE_READ, &old_protect);
    if (!vp_ok) {
        fprintf(stderr, "  ERROR  VirtualProtect failed (%lu)\n", GetLastError());
        VirtualFree(mem, 0, MEM_RELEASE);
        return 1;
    }
    Sleep(20000);

    /* ── THREAD ── */
    HANDLE hThread = CreateRemoteThread(
        GetCurrentProcess(), NULL, 0,
        dummy_thread, NULL, 0, NULL);
    if (!hThread) {
        fprintf(stderr, "  ERROR  CreateRemoteThread failed (%lu)\n", GetLastError());
        VirtualFree(mem, 0, MEM_RELEASE);
        return 1;
    }
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    printf("\n  Quad complete  ->  LOW / MEDIUM / HIGH / CRITICAL\n\n");
    printf("  Press ENTER to exit...\n");
    getchar();

    VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}
