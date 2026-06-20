/*
 * test_FalsePositive.c  (x64)
 * False-positive validation test for ArgusEDR.
 *
 * Finds a RUNNING OS process that naturally allocates and writes executable
 * memory as part of its normal operation (JIT runtimes are ideal: .NET CLR,
 * V8, JVM).  Both monitoring DLLs are injected into that SAME process so
 * the process's OWN API calls drive the correlator FSM -- no operations are
 * performed by this test binary.
 *
 * Why JIT processes?
 *   The .NET CLR calls VirtualAlloc(RWX) when JIT-compiling methods, which
 *   the hook captures and the FSM records as:
 *     has_allocated = true  (VirtualAlloc)
 *     has_protected = true  (exec permission)  ->  MEDIUM
 *   The CLR writes compiled code directly to those pages (NOT via
 *   WriteProcessMemory), so has_written stays false -> FSM stays at MEDIUM.
 *   CLR threads start inside clr.dll (MEM_IMAGE), not inside JIT pages
 *   (MEM_PRIVATE), so the CreateThread hook does not fire -> no CRITICAL.
 *
 * Candidate processes searched in order (first running match wins):
 *   powershell.exe, pwsh.exe, node.exe, java.exe, javaw.exe, python.exe
 * Fallback: spawns  powershell.exe  with a script that JIT-compiles .NET
 *   code in a loop so the hooks definitely fire during the window.
 *
 * Expected agent output:
 *   MEDIUM      (VirtualAlloc + exec permission from JIT)    <- expected
 *   PE-Sieve PRIVATE_EXECUTABLE corroboration               <- expected
 *   <silence>   no WPM, no CRT in private memory            <- expected
 *   CRITICAL    -> FALSE POSITIVE: EDR killed a legitimate process
 *
 * Workflow:
 *   1. Start argus_agent.exe
 *   2. Run test_FalsePositive.exe  ->  finds / spawns the target, prints PID
 *   3. Inject BOTH DLLs into the TARGET:
 *        injector.exe <target_pid>  argus_pesieve.dll
 *        injector.exe <target_pid>  argus_hook.dll
 *   4. Press ENTER -> 30-second monitoring window
 *   5. Check agent output:
 *        MEDIUM + silence  ->  PASS
 *        CRITICAL          ->  FALSE POSITIVE
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <processthreadsapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <TlHelp32.h>

#define MONITOR_SECONDS 30

/* Processes known to call VirtualAlloc(exec) during normal operation. */
static const char* JIT_CANDIDATES[] = {
    "powershell.exe",
    "pwsh.exe",
    "node.exe",
    "java.exe",
    "javaw.exe",
    "python.exe",
    NULL
};

/* Scans the running process list for the first match in JIT_CANDIDATES.
 * Returns the PID on success, 0 if none found. */
static DWORD find_jit_process(char* name_out, size_t name_len)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    DWORD found = 0;

    if (Process32FirstW(snap, &pe)) {
        do {
            char name_a[MAX_PATH] = {0};
            WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1,
                                name_a, sizeof(name_a), NULL, NULL);
            for (int i = 0; JIT_CANDIDATES[i]; i++) {
                if (_stricmp(name_a, JIT_CANDIDATES[i]) == 0) {
                    strncpy(name_out, name_a, name_len - 1);
                    found = pe.th32ProcessID;
                    goto done;
                }
            }
        } while (Process32NextW(snap, &pe));
    }
done:
    CloseHandle(snap);
    return found;
}

int main(void)
{
    printf("\n  ArgusEDR  /  False-Positive Validation Test  (x64)\n");
    printf("  ----------------------------------------\n\n");
    printf("  Strategy: inject BOTH EDR DLLs into one running OS process.\n");
    printf("  The process's own VirtualAlloc(exec) calls drive the FSM.\n");
    printf("  A correct EDR must reach MEDIUM but never CRITICAL.\n\n");

    /* ── Find a running JIT process ──────────────────────────────────────── */
    char     target_name[MAX_PATH] = {0};
    DWORD    target_pid  = 0;
    HANDLE   target_proc = NULL;
    BOOL     spawned     = FALSE;
    PROCESS_INFORMATION pi = {0};

    target_pid = find_jit_process(target_name, sizeof(target_name));

    if (target_pid != 0) {
        target_proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, target_pid);
        if (!target_proc) {
            printf("  [!]  Found %s (PID %lu) but OpenProcess failed (%lu).\n"
                   "       Try running as Administrator.\n\n",
                   target_name, (unsigned long)target_pid,
                   (unsigned long)GetLastError());
            return 1;
        }
        printf("  [FOUND]   Running JIT process: %-20s PID %lu\n\n",
               target_name, (unsigned long)target_pid);
    } else {
        /* Fallback: spawn powershell.exe running a .NET loop that JIT-compiles
         * new code every iteration, guaranteeing VirtualAlloc(exec) calls fire
         * inside the monitoring window after injection. */
        printf("  [INFO]    No JIT process found -- spawning powershell.exe.\n\n");

        char ps_cmd[512];
        snprintf(ps_cmd, sizeof(ps_cmd),
            "powershell.exe -NoProfile -Command \""
            "Write-Host 'ArgusEDR FP target ready'; "
            "1..9999 | ForEach-Object { "
              "[System.Text.Encoding]::UTF8.GetBytes('test') | Out-Null; "
              "Start-Sleep -Milliseconds 10 "
            "}\"");

        STARTUPINFOA si = { sizeof(si) };
        if (!CreateProcessA(NULL, ps_cmd, NULL, NULL, FALSE,
                            CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
            fprintf(stderr, "  ERROR  CreateProcess(powershell) failed (%lu)\n",
                    GetLastError());
            return 1;
        }
        Sleep(2000);    /* let CLR initialise and start JIT-compiling */

        target_pid  = GetProcessId(pi.hProcess);
        target_proc = pi.hProcess;
        spawned     = TRUE;
        strncpy(target_name, "powershell.exe", sizeof(target_name) - 1);
        printf("  [SPAWN]   powershell.exe spawned  PID %lu\n\n",
               (unsigned long)target_pid);
    }

    /* ── Injection instructions ───────────────────────────────────────────── */
    printf("  Target : %-24s PID %lu\n\n",
           target_name, (unsigned long)target_pid);

    printf("  Inject BOTH DLLs into the TARGET (same process):\n\n");
    printf("    injector.exe %-6lu argus_pesieve.dll\n", (unsigned long)target_pid);
    printf("    injector.exe %-6lu argus_hook.dll\n\n",  (unsigned long)target_pid);

    printf("  argus_pesieve.dll  scans the target's memory for RWX/PE anomalies.\n");
    printf("  argus_hook.dll     monitors the target's OWN API calls.\n\n");
    printf("  The target's .NET CLR will call VirtualAlloc(exec) for JIT pages.\n");
    printf("  Those calls drive the FSM without any action from this process.\n\n");

    printf("  Do both injections, then press ENTER to start the %d-second "
           "monitoring window...\n", MONITOR_SECONDS);
    getchar();

    /* ── Monitoring window ───────────────────────────────────────────────── */
    printf("\n  ---- Monitoring window (%d s) ----------------------------------\n\n",
           MONITOR_SECONDS);
    printf("  Watch argus_agent.exe output.\n\n");
    printf("  Expected events (from the target process's own operations):\n");
    printf("    MEDIUM   VirtualAlloc(exec) -- CLR JIT allocating code pages\n");
    printf("    PE-Sieve PRIVATE_EXECUTABLE -- fast watcher sees JIT pages\n");
    printf("    <silence after that>        -- no WPM, no CRT in private memory\n\n");
    printf("  CRITICAL at any point = false positive.\n\n");

    for (int rem = MONITOR_SECONDS; rem > 0; rem -= 5) {
        printf("  [%2d s remaining]  watching...\n", rem);
        fflush(stdout);
        Sleep(5000);
    }

    /* ── Result ──────────────────────────────────────────────────────────── */
    printf("\n  ----------------------------------------\n");
    printf("  Monitoring complete.  Target: %s  PID %lu\n\n",
           target_name, (unsigned long)target_pid);

    printf("  FSM progression for a correct EDR:\n");
    printf("    MEDIUM   (VirtualAlloc exec)  ->  detected but not dangerous\n");
    printf("    no HIGH  (no WriteProcessMemory from target on self via WPM)\n");
    printf("    no CRITICAL                   ->  PASS: no false positive\n\n");

    printf("  If CRITICAL appeared:\n");
    printf("    FAIL: EDR escalated a JIT allocation to a kill order.\n");
    printf("    Investigate: CreateThread start address was in MEM_PRIVATE?\n");
    printf("    Or YARA matched CLR/JIT bytes as malware pattern?\n\n");

    /* ── Cleanup ─────────────────────────────────────────────────────────── */
    if (spawned) {
        printf("  Terminating spawned powershell.exe (PID %lu)...\n",
               (unsigned long)target_pid);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    } else {
        CloseHandle(target_proc);
    }

    printf("  Done.\n\n");
    return 0;
}
