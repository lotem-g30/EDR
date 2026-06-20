#pragma once
#include <windows.h>
#include <stdbool.h>
#include "argus/events.h"

#define CORRELATOR_MAX_REGIONS 16

// Active-response kill-switch.
// TRUE  — agent calls TerminateProcess immediately when a PID reaches CRITICAL.
// FALSE — monitoring only; prints a disabled notice and leaves the process alive.
// Flip this in main() before starting the event loop.
extern bool ENABLE_ACTIVE_RESPONSE;

typedef struct {
    ULONGLONG base_address;
    ULONGLONG size;
    char      source_api[32];
} TrackedRegion;

// Initialize the correlator. Call once from main() before any threads start.
void correlator_init(void);

// Tear down the correlator. Call once from main() at shutdown.
void correlator_destroy(void);

// Feed a PE-Sieve finding. base_address is the region base from the JSON
// "region":{"base_address":"0x..."} field.
// Implements deduplication against previously hook-tracked regions before
// escalating severity.
// Returns true if the finding was NOT deduped (caller should trigger a YARA scan).
// Returns false if the address was already covered by a hook event (YARA already ran).
bool correlator_feed_pesieve(DWORD pid, const char* finding_type_str,
                             ULONGLONG base_address);

// Feed a hook event from the argus-events pipe.
// api_name: e.g. "VirtualProtect", "CreateRemoteThread", "VirtualAllocEx".
// protect_flags: flNewProtect for VirtualProtect; 0 for all other APIs.
// address/size: the affected memory region (0 if not applicable).
// For VirtualAllocEx, WriteProcessMemory, and VirtualProtect, the region is
// recorded in the per-PID tracking table for later deduplication.
void correlator_feed_hook_event(DWORD pid, const char* api_name,
                                DWORD protect_flags,
                                ULONGLONG address, ULONGLONG size);

// Feed a YARA match. Escalates the PID's severity to CRITICAL immediately.
void correlator_feed_yara(DWORD pid, const char* rule_name);
