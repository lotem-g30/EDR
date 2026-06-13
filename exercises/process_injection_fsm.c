/*
 * process_injection_fsm.c
 * Argus EDR — Diamond/Capabilities FSM Correlator for Process Injection Detection.
 *
 * CRITICAL RULE: Termination REQUIRES a YARA confirmation.
 * Behavioral flags alone are NEVER sufficient to kill a process.
 *
 * Kill conditions (exactly two, both require has_yara):
 *   1. Full injection chain:  ALLOC + WRITE + PROTECT + YARA
 *   2. YARA match alone:      YARA (independent of behavioral flags)
 */

#include <windows.h>
#include <stdbool.h>
#include <stdio.h>

/* ------------------------------------------------------------------ */
/* Types                                                               */
/* ------------------------------------------------------------------ */

typedef enum {
    EVENT_HOOK_ALLOC_NORMAL,   /* VirtualAllocEx, normal protection bits   */
    EVENT_HOOK_ALLOC_RWX,      /* VirtualAllocEx with RWX — alloc+protect  */
    EVENT_HOOK_WRITE,          /* WriteProcessMemory                        */
    EVENT_HOOK_PROTECT,        /* VirtualProtect with exec bit set          */
    EVENT_PESIEVE_PRIVATE_EXEC,/* PE-Sieve detected private executable page */
    EVENT_YARA_MATCH,          /* YARA rule fired on this process           */
    EVENT_HOOK_REMOTETHREAD    /* CreateRemoteThread — stopped upstream     */
} EventType;

typedef struct {
    DWORD pid;
    bool  has_allocated;  /* process allocated memory in a remote target   */
    bool  has_written;    /* process wrote into that allocation             */
    bool  has_protected;  /* allocation became executable (3 paths, below) */
    bool  has_yara;       /* YARA rule matched on this process              */
    bool  is_dead;        /* already killed — ignore all future events      */
} ProcessContext;

/* ------------------------------------------------------------------ */
/* Internal helpers                                                    */
/* ------------------------------------------------------------------ */

static void KillProcess(ProcessContext* ctx, const char* reason)
{
    printf("[KILL] PID %lu — %s\n", (unsigned long)ctx->pid, reason);
    ctx->is_dead = true;
    /*
     * Production: obtain a handle here and call TerminateProcess.
     * HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, ctx->pid);
     * if (h) { TerminateProcess(h, 1); CloseHandle(h); }
     */
}

/* ------------------------------------------------------------------ */
/* FSM                                                                 */
/* ------------------------------------------------------------------ */

void ProcessFsmEvent(ProcessContext* ctx, EventType event)
{
    if (ctx->is_dead)
        return;

    /* ---- State Update -------------------------------------------- */
    switch (event) {

        case EVENT_HOOK_ALLOC_NORMAL:
            ctx->has_allocated = true;
            break;

        /*
         * RWX allocation grants both the ALLOC and PROTECT flags in
         * one shot — no need for a separate VirtualProtect call.
         */
        case EVENT_HOOK_ALLOC_RWX:
            ctx->has_allocated = true;
            ctx->has_protected = true;
            break;

        /*
         * A write only counts as part of an injection if memory was
         * previously allocated.  Writes into pre-existing sections are
         * not meaningful on their own.
         */
        case EVENT_HOOK_WRITE:
            if (ctx->has_allocated)
                ctx->has_written = true;
            break;

        /* Path 2 to PROTECT: explicit VirtualProtect with exec bit. */
        case EVENT_HOOK_PROTECT:
            ctx->has_protected = true;
            break;

        /* Path 1 to PROTECT: PE-Sieve found a private executable page. */
        case EVENT_PESIEVE_PRIVATE_EXEC:
            ctx->has_protected = true;
            break;

        case EVENT_YARA_MATCH:
            ctx->has_yara = true;
            break;

        /*
         * RemoteThread events are intentionally ignored here.
         * If YARA already fired, the kill below will have handled the
         * process before the thread is created.  No further action needed.
         */
        case EVENT_HOOK_REMOTETHREAD:
            break;
    }

    /* ---- Kill Logic Evaluation ------------------------------------ */
    /*
     * Both conditions below require has_yara — behavioral evidence alone
     * NEVER justifies termination.
     */

    /* Condition 1: complete injection chain confirmed by YARA. */
    bool full_chain = ctx->has_allocated
                   && ctx->has_written
                   && ctx->has_protected
                   && ctx->has_yara;

    /* Condition 2: YARA match is independently sufficient. */
    bool yara_confirmed = ctx->has_yara;

    if (full_chain)
        KillProcess(ctx, "full injection chain (ALLOC + WRITE + PROTECT + YARA)");
    else if (yara_confirmed)
        KillProcess(ctx, "YARA match — standalone confirmation");
}

/* ------------------------------------------------------------------ */
/* Test driver                                                         */
/* ------------------------------------------------------------------ */

static void print_ctx(const ProcessContext* ctx)
{
    printf("  alloc=%-5s write=%-5s protect=%-5s yara=%-5s dead=%s\n",
           ctx->has_allocated  ? "true" : "false",
           ctx->has_written    ? "true" : "false",
           ctx->has_protected  ? "true" : "false",
           ctx->has_yara       ? "true" : "false",
           ctx->is_dead        ? "true" : "false");
}

int main(void)
{
    /* --- Scenario A: full behavioral chain, then YARA confirms --- */
    printf("=== Scenario A: ALLOC_NORMAL -> WRITE -> PROTECT -> YARA ===\n");
    {
        ProcessContext ctx = { .pid = 1001 };
        ProcessFsmEvent(&ctx, EVENT_HOOK_ALLOC_NORMAL); print_ctx(&ctx);
        ProcessFsmEvent(&ctx, EVENT_HOOK_WRITE);        print_ctx(&ctx);
        ProcessFsmEvent(&ctx, EVENT_HOOK_PROTECT);      print_ctx(&ctx);
        ProcessFsmEvent(&ctx, EVENT_YARA_MATCH);        print_ctx(&ctx);
        /* Expected: KILL via full_chain */
    }

    /* --- Scenario B: RWX shortcut then write, no YARA yet --- */
    printf("\n=== Scenario B: ALLOC_RWX -> WRITE (no YARA — must NOT kill) ===\n");
    {
        ProcessContext ctx = { .pid = 1002 };
        ProcessFsmEvent(&ctx, EVENT_HOOK_ALLOC_RWX); print_ctx(&ctx);
        ProcessFsmEvent(&ctx, EVENT_HOOK_WRITE);     print_ctx(&ctx);
        /* Expected: no kill — YARA required */
    }

    /* --- Scenario C: PE-Sieve provides the PROTECT flag, YARA fires --- */
    printf("\n=== Scenario C: ALLOC_NORMAL -> WRITE -> PESIEVE -> YARA ===\n");
    {
        ProcessContext ctx = { .pid = 1003 };
        ProcessFsmEvent(&ctx, EVENT_HOOK_ALLOC_NORMAL);    print_ctx(&ctx);
        ProcessFsmEvent(&ctx, EVENT_HOOK_WRITE);           print_ctx(&ctx);
        ProcessFsmEvent(&ctx, EVENT_PESIEVE_PRIVATE_EXEC); print_ctx(&ctx);
        ProcessFsmEvent(&ctx, EVENT_YARA_MATCH);           print_ctx(&ctx);
        /* Expected: KILL via full_chain */
    }

    /* --- Scenario D: YARA fires without any prior behavior (cold scan) --- */
    printf("\n=== Scenario D: YARA only (no behavioral flags) ===\n");
    {
        ProcessContext ctx = { .pid = 1004 };
        ProcessFsmEvent(&ctx, EVENT_YARA_MATCH); print_ctx(&ctx);
        /* Expected: KILL via yara_confirmed */
    }

    /* --- Scenario E: events after death are silently ignored --- */
    printf("\n=== Scenario E: post-death events ignored ===\n");
    {
        ProcessContext ctx = { .pid = 1005 };
        ProcessFsmEvent(&ctx, EVENT_YARA_MATCH);           print_ctx(&ctx); /* kills */
        ProcessFsmEvent(&ctx, EVENT_HOOK_ALLOC_NORMAL);    print_ctx(&ctx); /* no-op */
        ProcessFsmEvent(&ctx, EVENT_HOOK_REMOTETHREAD);    print_ctx(&ctx); /* no-op */
        /* Expected: is_dead stays true, no second KILL line */
    }

    /* --- Scenario F: RemoteThread alone, no YARA --- */
    printf("\n=== Scenario F: REMOTETHREAD only (ignored, no kill) ===\n");
    {
        ProcessContext ctx = { .pid = 1006 };
        ProcessFsmEvent(&ctx, EVENT_HOOK_REMOTETHREAD); print_ctx(&ctx);
        /* Expected: all flags false, no kill */
    }

    return 0;
}
