#include "patch_filter.h"
#include "ownership.h"
#include <stdlib.h>
#include <string.h>

// ── JSON helpers ──────────────────────────────────────────────────────────────
//
// PE-Sieve at JSON_DETAILS2 level emits per-patch records inside
// "patches_list" arrays.  Each record with "is_hook":1 has a "hook_target"
// object describing where the patched JMP redirects:
//
//   "patches_list" : [
//     { "rva":"...", "size":5, "is_hook":1, "func_name":"VirtualAllocEx",
//       "hook_target" : {
//         "module_name" : "argus_hook.dll",   // present when target is named
//         "module"      : "7ffc1234abcd",     // bare hex (no "0x")
//         "rva"         : "0",
//         "status"      : 0
//       }
//     }, ...
//   ]
//
// Detours quirk: when argus_hook.dll is >2 GB away from the patched DLL,
// Detours inserts a near-trampoline relay stub (MEM_PRIVATE PAGE_EXECUTE_READ)
// close to the patched function.  PE-Sieve then reports hook_target.module as
// the relay address, not argus_hook.dll's base.  follow_jmp_chain resolves
// these multi-hop stubs so they are correctly identified as ours.

// Parse a bare hex string (leading '"' and spaces are ignored).
static ULONGLONG parse_hex_str(const char* s)
{
    while (s && (*s == '"' || *s == ' ')) s++;
    if (!s || !*s) return 0ULL;
    char* end;
    ULONGLONG v = strtoull(s, &end, 16);
    return (end == s) ? 0ULL : v;
}

// Walk forward from 'after_open' (the character after the opening '{') and
// return the position just past the matching closing '}'.
// PE-Sieve JSON values do not contain literal '{' or '}', so plain depth
// counting is safe.
static const char* find_obj_end(const char* after_open)
{
    int depth = 1;
    for (const char* p = after_open; *p; p++) {
        if      (*p == '{') ++depth;
        else if (*p == '}') { if (--depth == 0) return p + 1; }
    }
    return NULL; // malformed
}

// ── Patch classification ──────────────────────────────────────────────────────

bool has_foreign_patches(const char* json, ULONGLONG hook_dll_base)
{
    if (!json || !json[0] || hook_dll_base == 0) return false;

    ULONGLONG hook_dll_end = hook_dll_base;
    {
        MEMORY_BASIC_INFORMATION mbi;
        while (VirtualQuery((LPCVOID)(uintptr_t)hook_dll_end, &mbi, sizeof(mbi)) == sizeof(mbi)
               && mbi.Type == MEM_IMAGE
               && (ULONGLONG)mbi.AllocationBase == hook_dll_base)
            hook_dll_end += mbi.RegionSize;
    }
    if (hook_dll_end == hook_dll_base)
        hook_dll_end = hook_dll_base + (1ULL << 20);

    auto in_hook_dll = [&](ULONGLONG addr) -> bool {
        return addr != 0 && addr >= hook_dll_base && addr < hook_dll_end;
    };

    const char* p = json;

    while ((p = strstr(p, "\"patches_list\"")) != NULL) {
        p += 14;
        const char* arr = strchr(p, '[');
        if (!arr) break;
        p = arr + 1;

        const char* scope_end = strstr(p, "\"patches_list\"");
        const char* cursor    = p;

        while (1) {
            const char* patch_obj = strchr(cursor, '{');
            if (!patch_obj || (scope_end && patch_obj >= scope_end)) break;

            const char* patch_end = find_obj_end(patch_obj + 1);
            const char* obj_lim   = patch_end ? patch_end
                                    : (scope_end ? scope_end : NULL);

            // ── is_hook ───────────────────────────────────────────────────────
            // Absent or 0 → UNCERTAIN → skip (PE-Sieve may fail to classify a
            // Detours E9 JMP as HOOK_INLINE in rare edge cases).
            const char* ih = strstr(patch_obj + 1, "\"is_hook\"");
            if (!ih || (obj_lim && ih >= obj_lim)) {
                cursor = patch_end ? patch_end : (patch_obj + 1);
                continue;
            }
            const char* v = ih + 9;
            while (*v == ' ' || *v == ':' || *v == '\n' || *v == '\r') v++;
            if (*v == '0') {
                cursor = patch_end ? patch_end : (patch_obj + 1);
                continue;
            }

            // ── hook_target block ─────────────────────────────────────────────
            const char* ht = strstr(patch_obj + 1, "\"hook_target\"");
            if (!ht || (obj_lim && ht >= obj_lim)) {
                cursor = patch_end ? patch_end : (patch_obj + 1);
                continue;
            }
            const char* ht_brace = strchr(ht + 13, '{');
            if (!ht_brace) {
                cursor = patch_end ? patch_end : (patch_obj + 1);
                continue;
            }
            const char* ht_end = find_obj_end(ht_brace + 1);
            const char* ht_lim = ht_end ? ht_end : obj_lim;

            // ── Parse hook_target fields ──────────────────────────────────────
            // full_va = module + rva == hookTargetVA in PE-Sieve.
            // When hookTargetModule == 0, rva holds hookTargetVA directly.

            const char* mn_val     = NULL;
            const char* mn_val_end = NULL;
            {
                const char* mn = strstr(ht_brace + 1, "\"module_name\"");
                if (mn && (!ht_lim || mn < ht_lim)) {
                    const char* mq = strchr(mn + 13, '"');
                    if (mq && (!ht_lim || mq < ht_lim)) {
                        const char* mend = strchr(mq + 1, '"');
                        if (mend && (!ht_lim || mend < ht_lim)) {
                            mn_val     = mq + 1;
                            mn_val_end = mend;
                        }
                    }
                }
            }

            ULONGLONG target = 0;
            {
                const char* scan = ht_brace + 1;
                while ((scan = strstr(scan, "\"module\"")) != NULL) {
                    if (ht_lim && scan >= ht_lim) break;
                    const char* after = scan + 8;
                    while (*after == ' ' || *after == '\t') after++;
                    if (*after != ':') { scan++; continue; }
                    const char* q = strchr(scan + 8, '"');
                    if (q && (!ht_lim || q < ht_lim))
                        target = parse_hex_str(q + 1);
                    break;
                }
            }

            ULONGLONG hook_rva = 0;
            {
                const char* rk = strstr(ht_brace + 1, "\"rva\"");
                if (rk && (!ht_lim || rk < ht_lim)) {
                    const char* after = rk + 5;
                    while (*after == ' ' || *after == '\t') after++;
                    if (*after == ':') {
                        const char* q = strchr(rk + 5, '"');
                        if (q && (!ht_lim || q < ht_lim))
                            hook_rva = parse_hex_str(q + 1);
                    }
                }
            }

            ULONGLONG full_va = target + hook_rva;

            // ── Decision logic ────────────────────────────────────────────────

            if (mn_val && mn_val_end) {
                // module_name present: check whether it names argus_hook.dll.
                bool is_argus = false;
                for (const char* s = mn_val; s + 9 < mn_val_end; s++) {
                    if (s[0] == 'a' && memcmp(s, "argus_hook", 10) == 0) {
                        is_argus = true; break;
                    }
                }
                if (is_argus) {
                    if (full_va != 0 && !in_hook_dll(full_va))
                        remember_region_containing(full_va);
                    cursor = patch_end ? patch_end : (patch_obj + 1);
                    continue; // OURS via module_name
                }
                // Named foreign module.  Try JMP chain in case the relay stub
                // lies within that module's mapped range.
                if (full_va != 0) {
                    ULONGLONG resolved = follow_jmp_chain(full_va);
                    if (in_hook_dll(resolved) && resolved != full_va) {
                        remember_region_containing(full_va);
                        cursor = patch_end ? patch_end : (patch_obj + 1);
                        continue; // relay inside foreign module's range → OURS
                    }
                }
                return true; // module_name confirms a different DLL → FOREIGN
            }

            // No module_name: rely on address range and JMP chain.
            if (in_hook_dll(full_va) || in_hook_dll(target)) {
                cursor = patch_end ? patch_end : (patch_obj + 1);
                continue; // OURS (direct address match)
            }
            if (full_va != 0) {
                ULONGLONG resolved = follow_jmp_chain(full_va);
                if (in_hook_dll(resolved) && resolved != full_va) {
                    remember_region_containing(full_va);
                    cursor = patch_end ? patch_end : (patch_obj + 1);
                    continue; // OURS via relay stub
                }
                if (resolved == 0 || resolved == full_va) {
                    // Chain unrecognised or unreachable → UNCERTAIN → skip.
                    cursor = patch_end ? patch_end : (patch_obj + 1);
                    continue;
                }
                return true; // resolved elsewhere → FOREIGN
            }
            // full_va == 0 → UNCERTAIN → skip.
            cursor = patch_end ? patch_end : (patch_obj + 1);
        }

        if (!scope_end) break;
        p = scope_end;
    }

    return false; // all patches confirmed ours (or no patches found)
}
