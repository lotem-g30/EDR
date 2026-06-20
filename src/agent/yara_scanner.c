#include "yara_scanner.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

// Skip regions larger than 100 MB to avoid huge heap allocations.
#define MAX_REGION_SIZE (100ULL * 1024 * 1024)

static void get_timestamp(char* buf, size_t len) {
    time_t t = time(NULL);
    struct tm tm_info;
    gmtime_s(&tm_info, &t);
    strftime(buf, len, "%Y-%m-%dT%H:%M:%SZ", &tm_info);
}

#ifdef YARA_AVAILABLE

// ── Lifecycle ─────────────────────────────────────────────────────────────────

void yara_global_init(void) {
    yr_initialize();
}

void yara_global_finalize(void) {
    yr_finalize();
}

// ── Rule loading ──────────────────────────────────────────────────────────────

static void yara_compiler_error_cb(int error_level,
                                   const char* file_name,
                                   int line_number,
                                   const YR_RULE* rule,
                                   const char* message,
                                   void* user_data)
{
    (void)rule; (void)user_data;
    const char* level = (error_level == YARA_ERROR_LEVEL_ERROR) ? "error" : "warning";
    fprintf(stderr, "[YARA] %s:%d: %s: %s\n",
            file_name ? file_name : "?", line_number, level, message);
}

// Validate a single rule file in an isolated compiler.
// Returns 0 if the file compiled cleanly, -1 otherwise.
static int yara_validate_file(const char* full_path, const char* display_name) {
    YR_COMPILER* val = NULL;
    if (yr_compiler_create(&val) != ERROR_SUCCESS)
        return -1;
    yr_compiler_set_callback(val, yara_compiler_error_cb, NULL);
    FILE* fp = fopen(full_path, "r");
    if (!fp) {
        yr_compiler_destroy(val);
        return -1;
    }
    int errs = yr_compiler_add_file(val, fp, NULL, display_name);
    fclose(fp);
    yr_compiler_destroy(val);
    return (errs == 0) ? 0 : -1;
}

int yara_load_rules(const char* path, YR_RULES** rules_out) {
    *rules_out = NULL;

    YR_COMPILER* compiler = NULL;
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        fprintf(stderr, "[YARA] yr_compiler_create failed\n");
        return -1;
    }
    yr_compiler_set_callback(compiler, yara_compiler_error_cb, NULL);

    DWORD attrs = GetFileAttributesA(path);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "[YARA] Path not found: %s\n", path);
        yr_compiler_destroy(compiler);
        return -1;
    }

    int files_added = 0;

    if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
        char pattern[MAX_PATH];
        snprintf(pattern, sizeof(pattern), "%s\\*.yar", path);

        WIN32_FIND_DATAA fd;
        HANDLE hFind = FindFirstFileA(pattern, &fd);
        if (hFind == INVALID_HANDLE_VALUE) {
            fprintf(stderr, "[YARA] No *.yar files found in: %s\n", path);
            yr_compiler_destroy(compiler);
            return -1;
        }

        do {
            char full_path[MAX_PATH];
            snprintf(full_path, sizeof(full_path), "%s\\%s", path, fd.cFileName);

            // Validate in an isolated compiler first so errors never
            // contaminate the shared compiler's state.
            if (yara_validate_file(full_path, fd.cFileName) != 0) {
                fprintf(stderr, "[YARA] Skipping %s (see errors above)\n",
                        fd.cFileName);
                continue;
            }

            FILE* fp = fopen(full_path, "r");
            if (!fp) {
                fprintf(stderr, "[YARA] Cannot open rule file: %s\n", full_path);
                continue;
            }
            yr_compiler_add_file(compiler, fp, NULL, fd.cFileName);
            fclose(fp);
            files_added++;
        } while (FindNextFileA(hFind, &fd));

        FindClose(hFind);
    } else {
        if (yara_validate_file(path, path) != 0) {
            fprintf(stderr, "[YARA] Rule file has errors: %s\n", path);
            yr_compiler_destroy(compiler);
            return -1;
        }
        FILE* fp = fopen(path, "r");
        if (!fp) {
            fprintf(stderr, "[YARA] Cannot open rule file: %s\n", path);
            yr_compiler_destroy(compiler);
            return -1;
        }
        yr_compiler_add_file(compiler, fp, NULL, path);
        fclose(fp);
        files_added = 1;
    }

    if (files_added == 0) {
        fprintf(stderr, "[YARA] No rule files compiled successfully\n");
        yr_compiler_destroy(compiler);
        return -1;
    }

    if (yr_compiler_get_rules(compiler, rules_out) != ERROR_SUCCESS) {
        fprintf(stderr, "[YARA] yr_compiler_get_rules failed\n");
        yr_compiler_destroy(compiler);
        return -1;
    }

    yr_compiler_destroy(compiler);
    printf("[YARA] Compiled %d rule file(s) from: %s\n", files_added, path);
    return 0;
}

// ── YARA match callback ───────────────────────────────────────────────────────

typedef struct {
    DWORD         pid;
    const char*   process_name;
    const char*   session_id;
    const char*   scan_id;
    ScanFinding*  out_findings;
    size_t*       out_count;
    size_t        max_findings;
    MemoryRegion  current_region;
} YaraCallbackCtx;

static int yara_callback(YR_SCAN_CONTEXT* context,
                         int              message,
                         void*            message_data,
                         void*            user_data)
{
    if (message != CALLBACK_MSG_RULE_MATCHING)
        return CALLBACK_CONTINUE;

    YaraCallbackCtx* ctx = (YaraCallbackCtx*)user_data;
    if (*ctx->out_count >= ctx->max_findings)
        return CALLBACK_ABORT;

    YR_RULE*     rule = (YR_RULE*)message_data;
    ScanFinding* f    = &ctx->out_findings[*ctx->out_count];
    memset(f, 0, sizeof(*f));

    get_timestamp(f->ts, sizeof(f->ts));
    strncpy(f->session_id,    ctx->session_id,    ARGUS_MAX_UUID - 1);
    strncpy(f->scan_id,       ctx->scan_id,       ARGUS_MAX_UUID - 1);
    strncpy(f->process_name,  ctx->process_name,  ARGUS_MAX_NAME - 1);
    f->pid          = ctx->pid;
    f->finding_type = FINDING_YARA_MATCH;
    f->severity     = SEVERITY_HIGH;
    f->region       = ctx->current_region;

    strncpy(f->detail.yara_rule, rule->identifier,
            sizeof(f->detail.yara_rule) - 1);
    strncpy(f->detail.reason, "YARA rule matched memory region",
            sizeof(f->detail.reason) - 1);

    (*ctx->out_count)++;
    return CALLBACK_CONTINUE;
}

// ── Memory region scanner ─────────────────────────────────────────────────────

int yara_scan_process(HANDLE      hProcess,
                      DWORD       pid,
                      const char* process_name,
                      const char* session_id,
                      const char* scan_id,
                      YR_RULES*   rules,
                      ScanFinding* out_findings,
                      size_t*     out_count,
                      size_t      max_findings)
{
    YaraCallbackCtx ctx = {0};
    ctx.pid          = pid;
    ctx.process_name = process_name;
    ctx.session_id   = session_id;
    ctx.scan_id      = scan_id;
    ctx.out_findings = out_findings;
    ctx.out_count    = out_count;
    ctx.max_findings = max_findings;

    MEMORY_BASIC_INFORMATION mbi;
    unsigned char* address = NULL;

    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        address += mbi.RegionSize;

        // Only scan committed pages
        if (mbi.State != MEM_COMMIT)
            continue;

        // Strip modifier bits (PAGE_GUARD, PAGE_NOCACHE, PAGE_WRITECOMBINE)
        // to get the base protection before checking readability
        DWORD base_protect = mbi.Protect &
            ~(DWORD)(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE);

        if (base_protect == PAGE_NOACCESS)
            continue;
        if (mbi.Protect & PAGE_GUARD)
            continue;

        // Only scan pages with execute permission.  Shellcode must be
        // runnable before it is operationally relevant, and restricting
        // YARA to executable pages makes the FSM escalation ladder strictly
        // ordered: WriteProcessMemory fires MEDIUM (RW page, no YARA match)
        // and VirtualProtect fires HIGH, then the triggered scan finds the
        // EICAR payload in the now-executable page and fires CRITICAL.
        if (!(base_protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                              PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
            continue;

        // Skip oversized regions to cap memory usage
        if (mbi.RegionSize > MAX_REGION_SIZE) {
            printf("[YARA] Skipping large region 0x%p (%zu MB)\n",
                   mbi.BaseAddress, mbi.RegionSize / (1024 * 1024));
            continue;
        }

        BYTE* buf = (BYTE*)malloc(mbi.RegionSize);
        if (!buf)
            continue;

        SIZE_T bytes_read = 0;
        if (!ReadProcessMemory(hProcess, mbi.BaseAddress,
                               buf, mbi.RegionSize, &bytes_read)) {
            fprintf(stderr,
                "[YARA] ReadProcessMemory failed at 0x%p (err=%lu) — skipping\n",
                mbi.BaseAddress, GetLastError());
            free(buf);
            continue;
        }

        ctx.current_region.base_address = (uint64_t)(uintptr_t)mbi.BaseAddress;
        ctx.current_region.size         = mbi.RegionSize;
        ctx.current_region.protect      = mbi.Protect;
        ctx.current_region.type         = mbi.Type;
        ctx.current_region.state        = mbi.State;

        yr_rules_scan_mem(rules, buf, bytes_read, 0, yara_callback, &ctx, 0);
        free(buf);
    }

    return 0;
}

#endif // YARA_AVAILABLE
