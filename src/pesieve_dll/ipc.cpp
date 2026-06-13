#include "ipc.h"
#include "ownership.h"
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <rpc.h>

#pragma comment(lib, "rpcrt4.lib")

// ── Timestamp / UUID ──────────────────────────────────────────────────────────

void get_timestamp(char* buf, size_t len)
{
    time_t t = time(NULL);
    struct tm tm_info;
    gmtime_s(&tm_info, &t);
    strftime(buf, len, "%Y-%m-%dT%H:%M:%SZ", &tm_info);
}

void gen_uuid(char* buf, size_t len)
{
    UUID uuid;
    UuidCreate(&uuid);
    unsigned char* str = NULL;
    UuidToStringA(&uuid, &str);
    if (str) {
        strncpy(buf, (char*)str, len - 1);
        buf[len - 1] = '\0';
        RpcStringFreeA(&str);
    }
}

// ── Pipe connection ───────────────────────────────────────────────────────────

HANDLE connect_to_pipe(void)
{
    DWORD start = GetTickCount();
    while (1) {
        WaitNamedPipeW(L"\\\\.\\pipe\\argus-pesieve", 1000);
        HANDLE h = CreateFileW(
            L"\\\\.\\pipe\\argus-pesieve",
            GENERIC_WRITE, 0, NULL,
            OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE)
            return h;
        if (GetTickCount() - start >= 3000)
            return INVALID_HANDLE_VALUE;
        Sleep(100);
    }
}

// ── Finding serialization ─────────────────────────────────────────────────────

static const char* s_finding_type[] = {
    "FINDING_PRIVATE_EXECUTABLE",
    "FINDING_PE_HOLLOWING",
    "FINDING_PE_IMPLANT",
    "FINDING_REFLECTIVE_LOAD",
    "FINDING_CODE_CAVE",
    "FINDING_MODULE_STOMP",
    "FINDING_YARA_MATCH",
    "FINDING_ANOMALOUS_THREAD",
};

static const char* s_severity[] = {
    "LOW", "MEDIUM", "HIGH", "CRITICAL",
};

static void serialize_finding(const ScanFinding* f, char* buf, size_t buf_size)
{
    const char* ftype = (f->finding_type < 8) ? s_finding_type[f->finding_type] : "UNKNOWN";
    const char* sev   = (f->severity    < 4) ? s_severity[f->severity]          : "UNKNOWN";

    snprintf(buf, buf_size,
        "{"
        "\"ts\":\"%s\","
        "\"session_id\":\"%s\","
        "\"scan_id\":\"%s\","
        "\"pid\":%lu,"
        "\"process_name\":\"%s\","
        "\"finding_type\":\"%s\","
        "\"severity\":\"%s\","
        "\"region\":{"
          "\"base_address\":\"0x%llx\","
          "\"size\":%llu,"
          "\"protect\":%lu,"
          "\"type\":%lu,"
          "\"state\":%lu"
        "},"
        "\"detail\":{"
          "\"reason\":\"%s\","
          "\"yara_rule\":\"%s\","
          "\"pe_anomaly\":\"%s\""
        "}"
        "}",
        f->ts, f->session_id, f->scan_id,
        (unsigned long)f->pid, f->process_name,
        ftype, sev,
        (unsigned long long)f->region.base_address,
        (unsigned long long)f->region.size,
        (unsigned long)f->region.protect,
        (unsigned long)f->region.type,
        (unsigned long)f->region.state,
        f->detail.reason,
        f->detail.yara_rule,
        f->detail.pe_anomaly
    );
}

// ── Emission ──────────────────────────────────────────────────────────────────

bool emit_finding_at(HANDLE pipe,
                     DWORD self_pid,
                     const char* process_name,
                     const char* session_id,
                     const char* scan_id,
                     FindingType ft,
                     ULONGLONG base_address,
                     ULONGLONG region_size,
                     DWORD protect,
                     const char* anomaly)
{
    // Suppress findings whose address falls within a known Argus-owned range.
    if (is_argus_owned_region(base_address, region_size))
        return false;

    ScanFinding f;
    memset(&f, 0, sizeof(f));
    get_timestamp(f.ts, sizeof(f.ts));
    strncpy(f.session_id,   session_id,   ARGUS_MAX_UUID - 1);
    strncpy(f.scan_id,      scan_id,      ARGUS_MAX_UUID - 1);
    strncpy(f.process_name, process_name, ARGUS_MAX_NAME - 1);
    f.pid                 = self_pid;
    f.finding_type        = ft;
    f.severity            = SEVERITY_HIGH;
    f.region.base_address = base_address;
    f.region.size         = region_size;
    f.region.protect      = protect;
    f.region.type         = (protect != 0) ? MEM_PRIVATE : 0;
    f.region.state        = MEM_COMMIT;
    strncpy(f.detail.pe_anomaly, anomaly, sizeof(f.detail.pe_anomaly) - 1);
    strncpy(f.detail.reason,     anomaly, sizeof(f.detail.reason)     - 1);

    char buf[4096];
    serialize_finding(&f, buf, sizeof(buf) - 2);
    size_t len = strlen(buf);
    buf[len]     = '\n';
    buf[len + 1] = '\0';

    DWORD written = 0;
    BOOL ok = WriteFile(pipe, buf, (DWORD)(len + 1), &written, NULL);

    if (!ok || written != (DWORD)(len + 1)) {
        printf(
            "[PESIEVE PIPE] WriteFile failed ok=%d written=%lu "
            "expected=%llu error=%lu\n",
            ok ? 1 : 0,
            (unsigned long)written,
            (unsigned long long)(len + 1),
            ok ? 0UL : (unsigned long)GetLastError()
        );
        fflush(stdout);
    } else {
        printf(
            "[PESIEVE PIPE] finding sent base=0x%llx bytes=%lu\n",
            (unsigned long long)base_address,
            (unsigned long)written
        );
        fflush(stdout);
    }

    return ok && written == (DWORD)(len + 1);
}

void emit_finding(HANDLE pipe,
                  DWORD self_pid,
                  const char* process_name,
                  const char* session_id,
                  const char* scan_id,
                  FindingType ft,
                  const char* anomaly)
{
    emit_finding_at(pipe, self_pid, process_name, session_id, scan_id,
                    ft, 0, 0, 0, anomaly);
}
