#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Returns true if 'protect' grants any execute permission.
 * Strips modifier flags (PAGE_GUARD, PAGE_NOCACHE, PAGE_WRITECOMBINE) before
 * testing so callers do not need to mask beforehand.
 * Compatible with both C and C++; used by hook_dll and pesieve_dll. */
static inline int argus_is_exec_protect(DWORD protect)
{
    DWORD p = protect & ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE);
    return (p & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                 PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

#ifdef __cplusplus
}
#endif
