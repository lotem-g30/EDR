#pragma once
#include <windows.h>
#include <vector>

// ── Address range ─────────────────────────────────────────────────────────────

struct AddressRange {
    ULONGLONG begin;
    ULONGLONG end; // exclusive
};

// ── Ownership context ─────────────────────────────────────────────────────────
//
// Tracks the address ranges that belong to Argus infrastructure so that
// emit_finding_at and walk_private_executable can suppress self-generated
// findings before they reach the agent.

struct OwnershipContext {
    AddressRange             hook_dll;
    AddressRange             pesieve_dll;
    std::vector<AddressRange> detours_relays;
};

extern OwnershipContext g_owned;

// Rebuilds hook_dll and pesieve_dll ranges from the currently loaded modules.
// Call once per scan cycle before any ownership checks.
void refresh_owned_ranges(void);

// Records the VirtualQuery region that contains 'address' as a known Detours
// relay page.  Called when a relay stub whose JMP chain resolves to
// argus_hook.dll is first discovered.
void remember_region_containing(ULONGLONG address);

// Returns true if [base, base+size) overlaps any Argus-owned range.
// base == 0 is treated as an aggregate (unaddressed) finding — returns false.
bool is_argus_owned_region(ULONGLONG base, ULONGLONG size);

// Follows at most 3 hops of E9 (rel32) or FF25 (RIP-relative indirect) JMP
// instructions from 'start'.  Returns the resolved address after following, or
// 0 on failure (unmapped, non-executable, or too many hops).
// Used to trace Detours near-trampoline relay stubs back to argus_hook.dll.
ULONGLONG follow_jmp_chain(ULONGLONG start);

// Returns true if the committed MEM_PRIVATE region described by 'mbi' contains
// a Detours relay stub whose JMP chain resolves into argus_hook.dll.
// Side-effect: calls remember_region_containing for confirmed relay pages.
bool region_contains_argus_relay(const MEMORY_BASIC_INFORMATION& mbi);
