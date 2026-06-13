#pragma once
#include <windows.h>

// Returns true if the PE-Sieve JSON_DETAILS2 scan report contains at least
// one patched byte sequence that cannot be confirmed as one of our own Detours
// hooks redirecting into argus_hook.dll.
//
// When true the caller should emit FINDING_CODE_CAVE.  When false all detected
// patches are either confirmed-ours or UNCERTAIN, so CODE_CAVE is suppressed.
//
// Requires hook_dll_base to be the load address of argus_hook.dll (as returned
// by GetModuleHandleA).  Pass 0 when the module is not loaded — the function
// will suppress the finding in that case.
bool has_foreign_patches(const char* json, ULONGLONG hook_dll_base);
