#include <windows.h>
#include <pe_sieve_api.h>
#include <vector>
#include <set>
#include "argus/events.h"
#include "argus/mem_utils.h"
#include "ownership.h"
#include "patch_filter.h"
#include "ipc.h"

// The lightweight VirtualQuery watcher runs continuously. The expensive
// structural PE-Sieve scan runs periodically.
#define SCAN_CYCLE_MS  (2 * 60 * 1000)  // structural scan every 2 minutes
#define FAST_WATCH_MS  200               // realtime memory watcher interval

// Tracks bases of private-executable regions already reported in this session.
// A base is removed once the region is no longer private+executable, allowing a
// later reappearance at the same address to be reported again.
static std::set<ULONGLONG> g_reported_private_exec;

// ── Private executable region walker ─────────────────────────────────────────
//
// Walks all MEM_PRIVATE committed regions with any execute permission and emits
// FINDING_PRIVATE_EXECUTABLE for each one not identified as an Argus relay stub.
// De-duplicates across watcher passes: the same still-present region is only
// reported once until it disappears and re-appears.
static void walk_private_executable(HANDLE pipe,
                                    DWORD self_pid,
                                    const char* process_name,
                                    const char* session_id,
                                    const char* scan_id)
{
    unsigned char* addr = NULL;
    MEMORY_BASIC_INFORMATION mbi = {};
    std::set<ULONGLONG> currently_executable;

    while (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        unsigned char* next = (unsigned char*)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;

        if (mbi.State != MEM_COMMIT ||
            mbi.Type  != MEM_PRIVATE ||
            !argus_is_exec_protect(mbi.Protect))
            continue;

        const ULONGLONG base = (ULONGLONG)(uintptr_t)mbi.BaseAddress;
        const ULONGLONG size = (ULONGLONG)mbi.RegionSize;

        currently_executable.insert(base);

        if (is_argus_owned_region(base, size))
            continue;

        if (region_contains_argus_relay(mbi)) {
            printf("[PESIEVE WALK] suppressed Argus relay base=0x%llx\n",
                   (unsigned long long)base);
            fflush(stdout);
            continue;
        }

        if (g_reported_private_exec.count(base))
            continue;

        printf("[PESIEVE WALK] NEW candidate base=0x%llx size=%llu protect=0x%lx\n",
               (unsigned long long)base,
               (unsigned long long)size,
               (unsigned long)mbi.Protect);
        fflush(stdout);

        const bool sent = emit_finding_at(
            pipe, self_pid, process_name, session_id, scan_id,
            FINDING_PRIVATE_EXECUTABLE,
            base, size, mbi.Protect,
            "New private executable memory region");

        if (sent)
            g_reported_private_exec.insert(base);
    }

    // Retire regions that disappeared or lost execute permission.
    for (auto it = g_reported_private_exec.begin();
         it != g_reported_private_exec.end();) {
        if (!currently_executable.count(*it))
            it = g_reported_private_exec.erase(it);
        else
            ++it;
    }
}

// ── Fast memory watcher ───────────────────────────────────────────────────────

struct FastWatcherContext {
    DWORD self_pid;
    char  process_name[ARGUS_MAX_NAME];
    char  session_id[ARGUS_MAX_UUID];
};

// Runs independently from PESieve_scan_ex so the expensive structural scan
// cannot block detection of a newly-created private executable region.
static DWORD WINAPI fast_memory_watcher(LPVOID param)
{
    FastWatcherContext* ctx = static_cast<FastWatcherContext*>(param);
    if (!ctx) return 1;

    HANDLE pipe = INVALID_HANDLE_VALUE;

    printf("[PESIEVE FAST] continuous watcher started; interval=%lu ms\n",
           (unsigned long)FAST_WATCH_MS);
    fflush(stdout);

    while (true) {
        if (pipe == INVALID_HANDLE_VALUE) {
            pipe = connect_to_pipe();
            if (pipe == INVALID_HANDLE_VALUE) {
                printf("[PESIEVE FAST] pipe unavailable; retrying\n");
                fflush(stdout);
                Sleep(500);
                continue;
            }
            printf("[PESIEVE FAST] connected to argus-pesieve pipe\n");
            fflush(stdout);
        }

        char scan_id[ARGUS_MAX_UUID] = {};
        gen_uuid(scan_id, sizeof(scan_id));

        refresh_owned_ranges();

        walk_private_executable(
            pipe, ctx->self_pid, ctx->process_name, ctx->session_id, scan_id);

        Sleep(FAST_WATCH_MS);
    }

    if (pipe != INVALID_HANDLE_VALUE) CloseHandle(pipe);
    return 0;
}

// ── Structural PE-Sieve scan ──────────────────────────────────────────────────

static void run_structural_scan(DWORD self_pid,
                                const char* process_name,
                                const char* session_id)
{
    char scan_id[ARGUS_MAX_UUID];
    gen_uuid(scan_id, sizeof(scan_id));

    HMODULE hook_dll      = GetModuleHandleA("argus_hook.dll");
    ULONGLONG hook_dll_base = (ULONGLONG)(uintptr_t)hook_dll;

    char ignored_buf[256] = "argus_pesieve.dll";
    if (hook_dll)
        strncat(ignored_buf, ";argus_hook.dll",
                sizeof(ignored_buf) - strlen(ignored_buf) - 1);

    pesieve::t_params params = {};
    params.pid            = self_pid;
    params.out_filter     = pesieve::OUT_NO_DIR;
    params.quiet          = true;
    params.json_lvl       = pesieve::JSON_DETAILS2;
    params.results_filter = pesieve::SHOW_SUSPICIOUS;
    params.shellcode      = pesieve::SHELLC_PATTERNS_OR_STATS;
    params.modules_ignored.buffer = ignored_buf;
    params.modules_ignored.length = (ULONG)strlen(ignored_buf);

    size_t buf_capacity = 32768;
    std::vector<char> json_buf(buf_capacity, '\0');
    size_t needed = 0;

    pesieve::t_report report = PESieve_scan_ex(
        &params, pesieve::REPORT_SCANNED,
        json_buf.data(), buf_capacity, &needed);

    if (needed > buf_capacity) {
        buf_capacity = needed + 1;
        json_buf.assign(buf_capacity, '\0');
        report = PESieve_scan_ex(
            &params, pesieve::REPORT_SCANNED,
            json_buf.data(), buf_capacity, &needed);
    }

    printf("[PESIEVE REPORT] replaced=%lu implanted_pe=%lu implanted_shc=%lu "
           "patched=%lu iat_hooked=%lu needed=%llu\n",
           (unsigned long)report.replaced,
           (unsigned long)report.implanted_pe,
           (unsigned long)report.implanted_shc,
           (unsigned long)report.patched,
           (unsigned long)report.iat_hooked,
           (unsigned long long)needed);
    fflush(stdout);

    HANDLE pipe = connect_to_pipe();
    if (pipe == INVALID_HANDLE_VALUE) return;

    if (report.replaced > 0)
        emit_finding(pipe, self_pid, process_name, session_id, scan_id,
                     FINDING_PE_HOLLOWING, "PE hollowing detected");

    if (report.implanted_pe > 0)
        emit_finding(pipe, self_pid, process_name, session_id, scan_id,
                     FINDING_PE_IMPLANT, "PE implant detected");

    if (report.patched > 0 &&
        has_foreign_patches(json_buf.data(), hook_dll_base))
        emit_finding(pipe, self_pid, process_name, session_id, scan_id,
                     FINDING_CODE_CAVE, "Code cave/modification detected");

    if (report.iat_hooked > 0)
        emit_finding(pipe, self_pid, process_name, session_id, scan_id,
                     FINDING_MODULE_STOMP, "IAT hook detected");

    CloseHandle(pipe);
}

// ── Scan coordinator thread ───────────────────────────────────────────────────

static DWORD WINAPI scan_thread(LPVOID /*param*/)
{
    const DWORD self_pid = GetCurrentProcessId();

    char session_id[ARGUS_MAX_UUID] = {};
    gen_uuid(session_id, sizeof(session_id));

    char process_name[ARGUS_MAX_NAME] = "unknown";
    char path[MAX_PATH] = {};
    DWORD sz = MAX_PATH;
    if (QueryFullProcessImageNameA(GetCurrentProcess(), 0, path, &sz)) {
        const char* slash = strrchr(path, '\\');
        strncpy(process_name, slash ? slash + 1 : path, sizeof(process_name) - 1);
        process_name[sizeof(process_name) - 1] = '\0';
    }

    // The context outlives this thread because scan_thread runs for the process
    // lifetime.  The fast watcher is continuous and independent of the periodic
    // structural scan.
    FastWatcherContext watcher_ctx = {};
    watcher_ctx.self_pid = self_pid;
    strncpy(watcher_ctx.process_name, process_name,
            sizeof(watcher_ctx.process_name) - 1);
    watcher_ctx.process_name[sizeof(watcher_ctx.process_name) - 1] = '\0';
    strncpy(watcher_ctx.session_id, session_id,
            sizeof(watcher_ctx.session_id) - 1);
    watcher_ctx.session_id[sizeof(watcher_ctx.session_id) - 1] = '\0';

    HANDLE watcher = CreateThread(NULL, 0, fast_memory_watcher,
                                  &watcher_ctx, 0, NULL);
    if (watcher) {
        CloseHandle(watcher);
    } else {
        printf("[PESIEVE FAST] failed to create watcher thread, error=%lu\n",
               (unsigned long)GetLastError());
        fflush(stdout);
    }

    while (true) {
        run_structural_scan(self_pid, process_name, session_id);
        Sleep(SCAN_CYCLE_MS);
    }

    return 0;
}

// ── DLL entry point ───────────────────────────────────────────────────────────

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID /*lpvReserved*/)
{
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        HANDLE t = CreateThread(NULL, 0, scan_thread, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }
    return TRUE;
}
