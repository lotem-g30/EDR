#include "hooks.h"
#include "detours.h"
#include "argus/mem_utils.h"
#include <stdio.h>
#include <intrin.h>

// Owns the global event queue; initialized by DllMain via eq_init(&g_queue)
EventQueue g_queue;

// ── Recursion guard ────────────────────────────────────────────────────────────
//
// Per-thread flag set while the hook body is executing.  Prevents re-entry
// when the IPC / queue layer itself triggers a hooked API (e.g. VirtualAlloc
// growing the event-queue backing buffer).

__declspec(thread) static bool g_is_in_hook = false;

// ── Caller whitelist ───────────────────────────────────────────────────────────
//
// Returns true when the return address belongs to argus_pesieve.dll.
// Must only be called while g_is_in_hook is already true so its own
// VirtualQuery / GetModuleFileNameA calls cannot re-enter the hook body.

static bool caller_is_pesieve(void* ret_addr)
{
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(ret_addr, &mbi, sizeof(mbi)) != sizeof(mbi))
        return false;
    if (mbi.Type != MEM_IMAGE || !mbi.AllocationBase)
        return false;
    char name[MAX_PATH];
    if (!GetModuleFileNameA((HMODULE)mbi.AllocationBase, name, sizeof(name)))
        return false;
    for (char* p = name; *p; p++)
        if (*p >= 'A' && *p <= 'Z') *p |= 0x20;
    return strstr(name, "argus_pesieve") != NULL;
}

// ── VirtualAlloc ───────────────────────────────────────────────────────────────
//
// Only report allocations that include execute permission.  Heap allocations
// (PAGE_READWRITE) are extremely common and produce noise without signal.

static LPVOID (WINAPI *Real_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD)
    = VirtualAlloc;

static LPVOID WINAPI Hook_VirtualAlloc(
    LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    void*  ret    = _ReturnAddress();
    LPVOID result = Real_VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);

    if (!g_is_in_hook) {
        g_is_in_hook = true;
        if (argus_is_exec_protect(flProtect) && !caller_is_pesieve(ret)) {
            char event[512];
            snprintf(event, sizeof(event),
                "{\"api\":\"VirtualAlloc\",\"pid\":%lu,\"target_pid\":%lu,"
                "\"address\":\"%p\",\"size\":%zu,\"protect\":%lu}",
                GetCurrentProcessId(), GetCurrentProcessId(),
                result, (size_t)dwSize, (unsigned long)flProtect);
            eq_push(&g_queue, event);
        }
        g_is_in_hook = false;
    }

    return result;
}

// ── VirtualAllocEx ─────────────────────────────────────────────────────────────

static LPVOID (WINAPI *Real_VirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD)
    = VirtualAllocEx;

static LPVOID WINAPI Hook_VirtualAllocEx(
    HANDLE hProcess, LPVOID lpAddress,
    SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    void*  ret    = _ReturnAddress();
    LPVOID result = Real_VirtualAllocEx(
        hProcess, lpAddress, dwSize, flAllocationType, flProtect);

    if (!g_is_in_hook) {
        g_is_in_hook = true;
        if (!caller_is_pesieve(ret)) {
            char event[512];
            snprintf(event, sizeof(event),
                "{\"api\":\"VirtualAllocEx\",\"pid\":%lu,\"target_pid\":%lu,"
                "\"address\":\"%p\",\"size\":%zu,\"protect\":%lu}",
                GetCurrentProcessId(), GetProcessId(hProcess),
                result, (size_t)dwSize, (unsigned long)flProtect);
            eq_push(&g_queue, event);
        }
        g_is_in_hook = false;
    }

    return result;
}

// ── WriteProcessMemory ─────────────────────────────────────────────────────────

static BOOL (WINAPI *Real_WriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *)
    = WriteProcessMemory;

static BOOL WINAPI Hook_WriteProcessMemory(
    HANDLE hProcess, LPVOID lpBaseAddress,
    LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten)
{
    void* ret    = _ReturnAddress();
    BOOL  result = Real_WriteProcessMemory(
        hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);

    if (!g_is_in_hook) {
        g_is_in_hook = true;
        if (!caller_is_pesieve(ret)) {
            char event[512];
            snprintf(event, sizeof(event),
                "{\"api\":\"WriteProcessMemory\",\"pid\":%lu,\"target_pid\":%lu,"
                "\"address\":\"%p\",\"size\":%zu}",
                GetCurrentProcessId(), GetProcessId(hProcess),
                lpBaseAddress, (size_t)nSize);
            eq_push(&g_queue, event);
        }
        g_is_in_hook = false;
    }

    return result;
}

// ── CreateThread ───────────────────────────────────────────────────────────────
//
// Only report threads whose start address lies in private (non-module) memory.
// This filters out legitimate DLL thread spawns — including argus_pesieve.dll's
// own scan thread, which starts inside the DLL's image pages (MEM_IMAGE).
// Shellcode threads start in anonymous RWX allocations (MEM_PRIVATE).

static HANDLE (WINAPI *Real_CreateThread)(
    LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD)
    = CreateThread;

static HANDLE WINAPI Hook_CreateThread(
    LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter,
    DWORD dwCreationFlags, LPDWORD lpThreadId)
{
    void*  ret    = _ReturnAddress();
    HANDLE result = Real_CreateThread(
        lpThreadAttributes, dwStackSize, lpStartAddress,
        lpParameter, dwCreationFlags, lpThreadId);

    if (!g_is_in_hook) {
        g_is_in_hook = true;
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(lpStartAddress, &mbi, sizeof(mbi)) == sizeof(mbi) &&
            mbi.Type == MEM_PRIVATE && !caller_is_pesieve(ret)) {
            char event[512];
            snprintf(event, sizeof(event),
                "{\"api\":\"CreateThread\",\"pid\":%lu,\"target_pid\":%lu,"
                "\"start_address\":\"%p\"}",
                GetCurrentProcessId(), GetCurrentProcessId(),
                (void *)lpStartAddress);
            eq_push(&g_queue, event);
        }
        g_is_in_hook = false;
    }

    return result;
}

// ── CreateRemoteThread ─────────────────────────────────────────────────────────

static HANDLE (WINAPI *Real_CreateRemoteThread)(
    HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD)
    = CreateRemoteThread;

static HANDLE WINAPI Hook_CreateRemoteThread(
    HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
{
    void*  ret    = _ReturnAddress();
    HANDLE result = Real_CreateRemoteThread(
        hProcess, lpThreadAttributes, dwStackSize,
        lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);

    if (!g_is_in_hook) {
        g_is_in_hook = true;
        if (!caller_is_pesieve(ret)) {
            char event[512];
            snprintf(event, sizeof(event),
                "{\"api\":\"CreateRemoteThread\",\"pid\":%lu,\"target_pid\":%lu,"
                "\"start_address\":\"%p\"}",
                GetCurrentProcessId(), GetProcessId(hProcess),
                (void *)lpStartAddress);
            eq_push(&g_queue, event);
        }
        g_is_in_hook = false;
    }

    return result;
}

// ── VirtualProtect ─────────────────────────────────────────────────────────────

static BOOL (WINAPI *Real_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD)
    = VirtualProtect;

static BOOL WINAPI Hook_VirtualProtect(
    LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
    void* ret    = _ReturnAddress();
    BOOL  result = Real_VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);

    if (!g_is_in_hook) {
        g_is_in_hook = true;
        if (!caller_is_pesieve(ret)) {
            char event[512];
            snprintf(event, sizeof(event),
                "{\"api\":\"VirtualProtect\",\"pid\":%lu,\"target_pid\":%lu,"
                "\"address\":\"%p\",\"size\":%zu,\"protect\":%lu}",
                GetCurrentProcessId(), GetCurrentProcessId(),
                lpAddress, (size_t)dwSize, (unsigned long)flNewProtect);
            eq_push(&g_queue, event);
        }
        g_is_in_hook = false;
    }

    return result;
}

// ── Transaction helpers ────────────────────────────────────────────────────────

void hooks_install(void) {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach((PVOID *)&Real_VirtualAlloc,       Hook_VirtualAlloc);
    DetourAttach((PVOID *)&Real_VirtualAllocEx,     Hook_VirtualAllocEx);
    DetourAttach((PVOID *)&Real_WriteProcessMemory, Hook_WriteProcessMemory);
    DetourAttach((PVOID *)&Real_CreateThread,       Hook_CreateThread);
    DetourAttach((PVOID *)&Real_CreateRemoteThread, Hook_CreateRemoteThread);
    DetourAttach((PVOID *)&Real_VirtualProtect,     Hook_VirtualProtect);
    DetourTransactionCommit();
}

void hooks_uninstall(void) {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach((PVOID *)&Real_VirtualAlloc,       Hook_VirtualAlloc);
    DetourDetach((PVOID *)&Real_VirtualAllocEx,     Hook_VirtualAllocEx);
    DetourDetach((PVOID *)&Real_WriteProcessMemory, Hook_WriteProcessMemory);
    DetourDetach((PVOID *)&Real_CreateThread,       Hook_CreateThread);
    DetourDetach((PVOID *)&Real_CreateRemoteThread, Hook_CreateRemoteThread);
    DetourDetach((PVOID *)&Real_VirtualProtect,     Hook_VirtualProtect);
    DetourTransactionCommit();
}
