#include "correlator.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#define MAX_TRACKED_PIDS  512
#define MAX_CHAIN_STEPS   8
#define CRITICAL_GRACE_MS 500

static const char* s_sev[] = { "LOW", "MEDIUM", "HIGH", "CRITICAL" };

/* One link in the evidence chain — added for every severity increase. */
typedef struct {
    Severity sev;
    char     label[96];   /* display form of the finding that pushed severity to `sev` */
} ChainStep;

typedef struct {
    DWORD  pid;
    HANDLE process_handle;
} KillContext;

typedef struct {
    DWORD         pid;
    Severity      severity;
    bool          active;
    int           region_count;
    TrackedRegion regions[CORRELATOR_MAX_REGIONS];
    /* Diamond / Capabilities FSM flags */
    bool          has_allocated;
    bool          has_written;
    bool          has_protected;
    bool          has_remote_thread;
    bool          has_yara;
    bool          is_dead;
    /* Diagnostic fields — populated before calling evaluate_state_and_severity(). */
    char          last_context[256];    /* "Source: Finding" for the current event   */
    char          justification[512];   /* human-readable detection rationale        */
    /* Ordered evidence chain: one step per severity level reached. */
    ChainStep     chain[MAX_CHAIN_STEPS];
    int           chain_count;
} PidEntry;

static PidEntry          s_table[MAX_TRACKED_PIDS];
static CRITICAL_SECTION  s_lock;

/* Kill-switch — TRUE enables immediate TerminateProcess on CRITICAL.
 * Default: TRUE. Set to FALSE in main() for monitoring-only / debug sessions. */
bool ENABLE_ACTIVE_RESPONSE = true;

void correlator_init(void) {
    memset(s_table, 0, sizeof(s_table));
    InitializeCriticalSection(&s_lock);
}

void correlator_destroy(void) {
    DeleteCriticalSection(&s_lock);
}

/* Must be called with s_lock held. */
static PidEntry* find_or_create(DWORD pid) {
    PidEntry* free_slot = NULL;
    for (int i = 0; i < MAX_TRACKED_PIDS; i++) {
        if (s_table[i].active && s_table[i].pid == pid)
            return &s_table[i];
        if (!s_table[i].active && !free_slot)
            free_slot = &s_table[i];
    }
    if (free_slot) {
        memset(free_slot, 0, sizeof(*free_slot));
        free_slot->pid      = pid;
        free_slot->severity = (Severity)-1;  /* sentinel: no verdict yet */
        free_slot->active   = true;
    }
    return free_slot;
}

/* ── Formatting helpers ───────────────────────────────────────────────────── */

/* Split "Source: Finding detail" into separate strings. */
static void parse_context(const char* ctx,
                           char* source,  size_t src_len,
                           char* finding, size_t fnd_len) {
    const char* sep = strstr(ctx, ": ");
    if (sep) {
        size_t n = (size_t)(sep - ctx);
        if (n >= src_len) n = src_len - 1;
        memcpy(source, ctx, n);
        source[n] = '\0';
        strncpy(finding, sep + 2, fnd_len - 1);
        finding[fnd_len - 1] = '\0';
    } else {
        strncpy(source,  ctx, src_len - 1); source[src_len - 1]  = '\0';
        strncpy(finding, ctx, fnd_len - 1); finding[fnd_len - 1] = '\0';
    }
}

/* Strip the "FINDING_" prefix from PE-Sieve type strings. */
static const char* strip_prefix(const char* s) {
    return (strncmp(s, "FINDING_", 8) == 0) ? s + 8 : s;
}

/* Build a human-readable evidence chain string:
 * "VirtualAllocEx (LOW) + WriteProcessMemory (MEDIUM) + ... (CRITICAL)" */
static void build_chain_str(const PidEntry* e, char* buf, size_t buf_len) {
    int pos = 0;
    buf[0] = '\0';
    for (int i = 0; i < e->chain_count && pos < (int)buf_len - 1; i++) {
        int n = snprintf(buf + pos, buf_len - pos,
                         "%s%s (%s)",
                         i > 0 ? " + " : "",
                         e->chain[i].label,
                         s_sev[e->chain[i].sev]);
        if (n <= 0) break;
        pos += n;
    }
}

/*
 * Attempt to terminate `pid` and log the precise outcome.
 * Called immediately when a PID transitions to CRITICAL and ENABLE_ACTIVE_RESPONSE
 * is TRUE — no deferred execution, no buffering.
 */
static void active_response_kill_handle(HANDLE process_handle, DWORD pid) {
    printf("  [!!!] CRITICAL THREAT DETECTED: Terminating process PID %lu...\n",
           (unsigned long)pid);

    if (!process_handle || process_handle == INVALID_HANDLE_VALUE) {
        printf("  [ERR] Invalid process handle for PID %lu.\n",
               (unsigned long)pid);
        return;
    }

    if (ENABLE_ACTIVE_RESPONSE) {
        SetLastError(ERROR_SUCCESS);
        BOOL ok = TerminateProcess(process_handle, 1);
        DWORD err = ok ? ERROR_SUCCESS : GetLastError();

        if (ok)
            printf("  [OK]  Success: Process %lu terminated.\n",
                   (unsigned long)pid);
        else
            printf("  [ERR] Error: Failed to terminate process %lu. "
                   "Error Code: %lu\n",
                   (unsigned long)pid, (unsigned long)err);
    } else {
        printf("  [!]  KILL-SWITCH: Disabled, skipping termination.\n");
    }
    fflush(stdout);
}

static DWORD WINAPI delayed_kill_thread(LPVOID param) {
    KillContext* ctx = (KillContext*)param;
    if (!ctx)
        return 1;

    Sleep(CRITICAL_GRACE_MS);

    active_response_kill_handle(ctx->process_handle, ctx->pid);

    CloseHandle(ctx->process_handle);
    free(ctx);
    return 0;
}

static void schedule_delayed_kill(DWORD pid) {
    HANDLE process_handle = OpenProcess(
        PROCESS_TERMINATE | SYNCHRONIZE,
        FALSE,
        pid
    );

    if (!process_handle) {
        printf("  [ERR] OpenProcess(PROCESS_TERMINATE) failed for PID %lu. "
               "Error Code: %lu\n",
               (unsigned long)pid,
               (unsigned long)GetLastError());
        fflush(stdout);
        return;
    }

    KillContext* ctx = (KillContext*)malloc(sizeof(KillContext));
    if (!ctx) {
        printf("  [ERR] Failed to allocate delayed-kill context.\n");
        fflush(stdout);
        CloseHandle(process_handle);
        return;
    }

    ctx->pid = pid;
    ctx->process_handle = process_handle;

    HANDLE thread = CreateThread(
        NULL,
        0,
        delayed_kill_thread,
        ctx,
        0,
        NULL
    );

    if (!thread) {
        printf("  [ERR] Failed to create delayed-kill thread. "
               "Error Code: %lu\n",
               (unsigned long)GetLastError());
        fflush(stdout);
        CloseHandle(process_handle);
        free(ctx);
        return;
    }

    CloseHandle(thread);
}

/*
 * Format and print a structured alert block.
 * Records the current finding into e->chain[], then emits:
 *   - For LOW / MEDIUM / HIGH: a compact block with optional Chain line.
 *   - For CRITICAL:            a boxed block with full Evidence chain and
 *                              active-response section ([!!!]/[!]/[+]/[-]).
 */
static void emit_verdict(PidEntry* e, Severity new_sev) {
    char source[64]   = {0};
    char finding[192] = {0};
    parse_context(e->last_context, source, sizeof(source), finding, sizeof(finding));
    const char* fd = strip_prefix(finding);   /* display form — no "FINDING_" prefix */

    /* Record this verdict as the next link in the evidence chain. */
    if (e->chain_count < MAX_CHAIN_STEPS) {
        ChainStep* step = &e->chain[e->chain_count++];
        step->sev = new_sev;
        strncpy(step->label, fd, sizeof(step->label) - 1);
        step->label[sizeof(step->label) - 1] = '\0';
    }

    const char* just = e->justification[0] ? e->justification : "n/a";

    if (new_sev == SEVERITY_CRITICAL) {
        /* Build evidence chain string (now includes the CRITICAL step). */
        char chain_str[512] = {0};
        build_chain_str(e, chain_str, sizeof(chain_str));

        printf("\n  ==================================================\n");
        printf("  [SOURCE: %-10s] | [SEVERITY: CRITICAL]  pid %lu\n",
               source, (unsigned long)e->pid);
        printf("  ==================================================\n");
        printf("  Finding:       %s\n",        fd);
        printf("  Justification: %s\n",        just);
        printf("  Evidence:      %s\n",        chain_str);
        printf("  --------------------------------------------------\n");

        /* Delay termination briefly so asynchronous detectors such as
         * PE-Sieve can contribute late evidence. The waiting happens in a
         * separate thread, so s_lock is not blocked. */
        if (ENABLE_ACTIVE_RESPONSE) {
            printf("  [!]  KILL-SWITCH: Process termination scheduled in %lu ms "
                   "to collect late evidence.\n",
                   (unsigned long)CRITICAL_GRACE_MS);
            schedule_delayed_kill(e->pid);
        } else {
            printf("  [!]  KILL-SWITCH: Disabled, skipping termination.\n");
        }

        printf("  ==================================================\n\n");

    } else {
        /* LOW / MEDIUM / HIGH — compact block. */
        printf("\n  [SOURCE: %-10s] | [SEVERITY: %s]  pid %lu\n",
               source, s_sev[new_sev], (unsigned long)e->pid);
        printf("  Finding:       %s\n", fd);
        printf("  Justification: %s\n", just);

        /* Show the running chain only when there are 2+ steps (i.e., this is an
         * escalation, not the opening event). */
        if (e->chain_count >= 2) {
            char chain_str[512] = {0};
            build_chain_str(e, chain_str, sizeof(chain_str));
            printf("  Chain:         %s\n", chain_str);
        }
        printf("\n");
    }
    /* Emit a JSON verdict line for the dashboard parser. */
    printf("{\"type\":\"PROCESS_VERDICT\",\"pid\":%lu,\"severity\":\"%s\",\"trigger\":\"%s\"}\n",
           (unsigned long)e->pid, s_sev[new_sev], fd);
    fflush(stdout);
}

/*
 * Derives severity from accumulated FSM flags and emits a verdict when
 * severity increases (highest-wins ladder).
 * Must be called with s_lock held.
 */
static void evaluate_state_and_severity(PidEntry* e) {
    if (e->is_dead) return;

    Severity derived;
    if      (e->has_remote_thread || e->has_yara)  derived = SEVERITY_CRITICAL;
    else if (e->has_written && e->has_protected)    derived = SEVERITY_HIGH;
    else if (e->has_written || e->has_protected)    derived = SEVERITY_MEDIUM;
    else if (e->has_allocated)                      derived = SEVERITY_LOW;
    else return;

    if (derived > e->severity) {
        emit_verdict(e, derived);
        e->severity = derived;
    }
}

/* ── Feed functions ───────────────────────────────────────────────────────── */

void correlator_feed_pesieve(DWORD pid, const char* finding_type_str,
                              ULONGLONG base_address)
{
    bool is_structural =
        finding_type_str &&
        (strcmp(finding_type_str, "FINDING_PE_IMPLANT")      == 0 ||
         strcmp(finding_type_str, "FINDING_PE_HOLLOWING")    == 0 ||
         strcmp(finding_type_str, "FINDING_REFLECTIVE_LOAD") == 0);

    bool is_local_mod =
        finding_type_str &&
        (strcmp(finding_type_str, "FINDING_CODE_CAVE")    == 0 ||
         strcmp(finding_type_str, "FINDING_MODULE_STOMP") == 0);

    bool  deduped     = false;
    char  dup_api[32] = {0};

    EnterCriticalSection(&s_lock);
    PidEntry* e = find_or_create(pid);
    if (e) {
        bool already_critical = (e->severity == SEVERITY_CRITICAL);

        snprintf(e->last_context, sizeof(e->last_context),
                 "PE-Sieve: %s", finding_type_str ? finding_type_str : "unknown");

        const char* ft = finding_type_str ? finding_type_str : "";

        if (strcmp(ft, "FINDING_CODE_CAVE") == 0) {
            snprintf(e->justification, sizeof(e->justification),
                "0x%llx: executable bytes in module section don't match the "
                "on-disk image — code injected into existing module space.",
                (unsigned long long)base_address);

        } else if (strcmp(ft, "FINDING_MODULE_STOMP") == 0) {
            snprintf(e->justification, sizeof(e->justification),
                "0x%llx: module section overwritten in-memory; diverges from "
                "on-disk PE — injected code hidden inside a legitimate module.",
                (unsigned long long)base_address);

        } else if (strcmp(ft, "FINDING_PE_HOLLOWING") == 0) {
            snprintf(e->justification, sizeof(e->justification),
                "0x%llx: original module code evacuated and replaced by a "
                "foreign PE — host process shell now executes attacker code.",
                (unsigned long long)base_address);

        } else if (strcmp(ft, "FINDING_PE_IMPLANT") == 0) {
            snprintf(e->justification, sizeof(e->justification),
                "0x%llx: PE image resident in memory with no backing file on "
                "disk — reflective DLL injection bypassing the Windows loader.",
                (unsigned long long)base_address);

        } else if (strcmp(ft, "FINDING_REFLECTIVE_LOAD") == 0) {
            snprintf(e->justification, sizeof(e->justification),
                "0x%llx: PE loaded without a file mapping, sidestepping the "
                "Windows loader to suppress module-load telemetry.",
                (unsigned long long)base_address);

        } else {
            snprintf(e->justification, sizeof(e->justification),
                "0x%llx: MEM_PRIVATE + executable — committed anonymous region "
                "with no file backing; classic in-process shellcode signature.",
                (unsigned long long)base_address);
        }

        /* The PID has already reached CRITICAL, so severity cannot increase.
         * Still print and publish this PE-Sieve finding as late evidence during
         * the termination grace period. */
        if (already_critical) {
            const char* display_finding =
                strip_prefix(finding_type_str ? finding_type_str : "unknown");

            printf("\n");
            printf("  [SOURCE: %-10s] | [SEVERITY: CRITICAL]  pid %lu\n",
                   "PE-Sieve", (unsigned long)pid);
            printf("  Finding:       %s\n", display_finding);
            printf("  Justification: %s\n", e->justification);
            printf("  Late evidence: received during termination grace period\n\n");

            printf("{\"type\":\"PROCESS_EVIDENCE\","
                   "\"pid\":%lu,"
                   "\"severity\":\"CRITICAL\","
                   "\"source\":\"PE-Sieve\","
                   "\"finding\":\"%s\"}\n",
                   (unsigned long)pid,
                   display_finding);
            fflush(stdout);

            LeaveCriticalSection(&s_lock);
            return;
        }

        if (is_structural) {
            e->has_written   = true;
            e->has_protected = true;
            evaluate_state_and_severity(e);
        } else if (is_local_mod && base_address != 0) {
            for (int i = 0; i < e->region_count; i++) {
                TrackedRegion* r = &e->regions[i];
                if (base_address >= r->base_address &&
                    base_address <  r->base_address + r->size &&
                    (strcmp(r->source_api, "VirtualProtect")     == 0 ||
                     strcmp(r->source_api, "WriteProcessMemory") == 0)) {
                    deduped = true;
                    strncpy(dup_api, r->source_api, sizeof(dup_api) - 1);
                    break;
                }
            }
            if (!deduped) {
                e->has_protected = true;
                evaluate_state_and_severity(e);
            }
        } else {
            e->has_protected = true;
            evaluate_state_and_severity(e);
        }
    }
    LeaveCriticalSection(&s_lock);

    if (deduped)
        printf("  dedup     pid %-6lu  %s @ 0x%llx (covered by %s hook)\n",
               (unsigned long)pid, finding_type_str,
               (unsigned long long)base_address, dup_api);
}

void correlator_feed_hook_event(DWORD pid, const char* api_name,
                                 DWORD protect_flags,
                                 ULONGLONG address, ULONGLONG size)
{
    if (!api_name) return;

    bool is_exec = (protect_flags & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                     PAGE_EXECUTE_READWRITE |
                                     PAGE_EXECUTE_WRITECOPY)) != 0;

    EnterCriticalSection(&s_lock);
    PidEntry* e = find_or_create(pid);
    if (e) {
        /* Record region for later PE-Sieve deduplication. */
        bool track =
            address != 0 && size != 0 &&
            (strcmp(api_name, "VirtualAlloc")       == 0 ||
             strcmp(api_name, "VirtualAllocEx")     == 0 ||
             strcmp(api_name, "WriteProcessMemory") == 0 ||
             strcmp(api_name, "VirtualProtect")     == 0);

        if (track && e->region_count < CORRELATOR_MAX_REGIONS) {
            TrackedRegion* r = &e->regions[e->region_count++];
            r->base_address  = address;
            r->size          = size;
            strncpy(r->source_api, api_name, sizeof(r->source_api) - 1);
        }

        if (strcmp(api_name, "VirtualProtect")   == 0 ||
            strcmp(api_name, "VirtualProtectEx") == 0) {
            snprintf(e->last_context, sizeof(e->last_context),
                     "Hook: %s(protect=0x%lx)", api_name, (unsigned long)protect_flags);
        } else {
            snprintf(e->last_context, sizeof(e->last_context), "Hook: %s", api_name);
        }

        if (strcmp(api_name, "VirtualAlloc")   == 0 ||
            strcmp(api_name, "VirtualAllocEx") == 0) {
            if (is_exec)
                snprintf(e->justification, sizeof(e->justification),
                    "0x%llx (%llu B): PAGE_EXECUTE_READWRITE in one call — "
                    "no separate VirtualProtect needed; classic shellcode staging.",
                    (unsigned long long)address, (unsigned long long)size);
            else
                snprintf(e->justification, sizeof(e->justification),
                    "0x%llx (%llu B): RW memory allocation — "
                    "step 1 of: allocate -> write payload -> set executable -> execute.",
                    (unsigned long long)address, (unsigned long long)size);

        } else if (strcmp(api_name, "WriteProcessMemory") == 0) {
            snprintf(e->justification, sizeof(e->justification),
                "0x%llx (%llu B): arbitrary bytes written into a tracked allocation — "
                "write stage of the injection chain confirmed.",
                (unsigned long long)address, (unsigned long long)size);

        } else if (strcmp(api_name, "VirtualProtect")   == 0 ||
                   strcmp(api_name, "VirtualProtectEx") == 0) {
            if (is_exec)
                snprintf(e->justification, sizeof(e->justification),
                    "0x%llx: protection changed to executable (flags=0x%lx) — "
                    "separating write and protect avoids RWX-allocation heuristics.",
                    (unsigned long long)address, (unsigned long)protect_flags);
            else
                snprintf(e->justification, sizeof(e->justification),
                    "0x%llx: memory protection changed (new flags=0x%lx).",
                    (unsigned long long)address, (unsigned long)protect_flags);

        } else if (strcmp(api_name, "CreateRemoteThread") == 0) {
            snprintf(e->justification, sizeof(e->justification),
                "Thread created in remote process with start address in MEM_PRIVATE "
                "(non-image) memory — cross-process shellcode execution.");

        } else if (strcmp(api_name, "CreateThread") == 0) {
            snprintf(e->justification, sizeof(e->justification),
                "Thread started in MEM_PRIVATE (non-image) executable memory — "
                "legitimate code always originates from a loaded module's image pages.");

        } else {
            snprintf(e->justification, sizeof(e->justification),
                "API '%s' intercepted on pid %lu.", api_name, (unsigned long)pid);
        }

        if (strcmp(api_name, "VirtualAllocEx") == 0 ||
            strcmp(api_name, "VirtualAlloc")   == 0) {
            e->has_allocated = true;
            if (is_exec) e->has_protected = true;
        } else if (strcmp(api_name, "WriteProcessMemory") == 0) {
            if (e->has_allocated) e->has_written = true;
        } else if (strcmp(api_name, "VirtualProtect")   == 0 ||
                   strcmp(api_name, "VirtualProtectEx") == 0) {
            if (is_exec) e->has_protected = true;
        } else if (strcmp(api_name, "CreateRemoteThread") == 0 ||
                   strcmp(api_name, "CreateThread")       == 0) {
            e->has_remote_thread = true;
        }

        evaluate_state_and_severity(e);
    }
    LeaveCriticalSection(&s_lock);
}

void correlator_feed_yara(DWORD pid, const char* rule_name) {
    EnterCriticalSection(&s_lock);
    PidEntry* e = find_or_create(pid);
    if (e) {
        const char* rn = (rule_name && rule_name[0]) ? rule_name : "unknown";
        snprintf(e->last_context, sizeof(e->last_context), "YARA: %s", rn);
        snprintf(e->justification, sizeof(e->justification),
            "Rule '%s' matched bytes in executable memory — "
            "pattern-based detection confirmed known-malicious content in the process.",
            rn);
        e->has_yara = true;
        evaluate_state_and_severity(e);
    }
    LeaveCriticalSection(&s_lock);
}
