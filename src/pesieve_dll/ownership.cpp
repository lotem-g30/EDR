#include "ownership.h"
#include "argus/mem_utils.h"
#include <string.h>

OwnershipContext g_owned = {};

// ── Internal helpers ──────────────────────────────────────────────────────────

static AddressRange module_range(const char* module_name)
{
    AddressRange out = {0, 0};
    HMODULE mod = GetModuleHandleA(module_name);
    if (!mod) return out;

    ULONGLONG base = (ULONGLONG)(uintptr_t)mod;
    ULONGLONG end  = base;
    MEMORY_BASIC_INFORMATION mbi = {};

    while (VirtualQuery((LPCVOID)(uintptr_t)end, &mbi, sizeof(mbi)) == sizeof(mbi)
           && mbi.Type == MEM_IMAGE
           && (ULONGLONG)(uintptr_t)mbi.AllocationBase == base) {
        ULONGLONG next = (ULONGLONG)(uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (next <= end) break;
        end = next;
    }

    if (end == base) end = base + (1ULL << 20); // conservative 1 MB fallback
    out.begin = base;
    out.end   = end;
    return out;
}

static bool ranges_overlap(ULONGLONG base, ULONGLONG size, const AddressRange& r)
{
    if (base == 0 || r.begin == 0 || r.end <= r.begin) return false;
    ULONGLONG span = (size == 0) ? 1 : size;
    ULONGLONG end  = base + span;
    if (end < base) end = ~0ULL; // overflow guard
    return base < r.end && end > r.begin;
}

static bool address_in_range(ULONGLONG address, const AddressRange& range)
{
    return address != 0 && range.begin != 0 &&
           address >= range.begin && address < range.end;
}

// ── Public API ────────────────────────────────────────────────────────────────

void refresh_owned_ranges(void)
{
    g_owned.hook_dll    = module_range("argus_hook.dll");
    g_owned.pesieve_dll = module_range("argus_pesieve.dll");
    g_owned.detours_relays.clear();
}

void remember_region_containing(ULONGLONG address)
{
    if (address == 0) return;

    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery((LPCVOID)(uintptr_t)address, &mbi, sizeof(mbi)) != sizeof(mbi))
        return;
    if (mbi.State != MEM_COMMIT) return;

    AddressRange r = {
        (ULONGLONG)(uintptr_t)mbi.BaseAddress,
        (ULONGLONG)(uintptr_t)mbi.BaseAddress + mbi.RegionSize
    };

    for (const AddressRange& existing : g_owned.detours_relays) {
        if (existing.begin == r.begin && existing.end == r.end)
            return;
    }
    g_owned.detours_relays.push_back(r);
}

bool is_argus_owned_region(ULONGLONG base, ULONGLONG size)
{
    if (base == 0) return false;

    if (ranges_overlap(base, size, g_owned.hook_dll))    return true;
    if (ranges_overlap(base, size, g_owned.pesieve_dll)) return true;

    for (const AddressRange& relay : g_owned.detours_relays) {
        if (ranges_overlap(base, size, relay)) return true;
    }
    return false;
}

ULONGLONG follow_jmp_chain(ULONGLONG start)
{
    ULONGLONG addr = start;
    for (int depth = 0; depth < 3; depth++) {
        if (addr == 0) return 0;
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery((LPCVOID)(uintptr_t)addr, &mbi, sizeof(mbi)) != sizeof(mbi))
            return 0;
        if (mbi.State != MEM_COMMIT) return 0;
        if (!argus_is_exec_protect(mbi.Protect)) return 0;

        const unsigned char* p = (const unsigned char*)(uintptr_t)addr;
        if (p[0] == 0xE9) {                          // E9 rel32: near relative JMP
            INT32 rel; memcpy(&rel, p + 1, 4);
            addr = addr + 5 + (LONGLONG)rel;
        } else if (p[0] == 0xFF && p[1] == 0x25) {   // FF 25 rel32: JMP [RIP+rel32]
            INT32 rel; memcpy(&rel, p + 2, 4);
            ULONGLONG ptr_addr = addr + 6 + (LONGLONG)rel;
            MEMORY_BASIC_INFORMATION mbi2;
            if (VirtualQuery((LPCVOID)(uintptr_t)ptr_addr, &mbi2, sizeof(mbi2)) != sizeof(mbi2))
                return 0;
            if (mbi2.State != MEM_COMMIT) return 0;
            memcpy(&addr, (const void*)(uintptr_t)ptr_addr, sizeof(addr));
        } else {
            break; // unrecognised instruction — stop here
        }
    }
    return addr;
}

bool region_contains_argus_relay(const MEMORY_BASIC_INFORMATION& mbi)
{
    if (g_owned.hook_dll.begin == 0 || mbi.State != MEM_COMMIT)
        return false;

    SIZE_T limit = mbi.RegionSize < 4096 ? mbi.RegionSize : 4096;
    const unsigned char* bytes = (const unsigned char*)(uintptr_t)mbi.BaseAddress;

    for (SIZE_T offset = 0; offset + 6 <= limit; ++offset) {
        const unsigned char* p = bytes + offset;
        if (p[0] != 0xE9 && !(p[0] == 0xFF && p[1] == 0x25))
            continue;

        ULONGLONG start =
            (ULONGLONG)(uintptr_t)mbi.BaseAddress + (ULONGLONG)offset;
        ULONGLONG resolved = follow_jmp_chain(start);

        if (resolved != 0 && resolved != start &&
            address_in_range(resolved, g_owned.hook_dll)) {
            remember_region_containing(start);
            return true;
        }
    }
    return false;
}
