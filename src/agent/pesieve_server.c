#include "pesieve_server.h"
#include "correlator.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define PESIEVE_PIPE_MAX_INSTANCES 4

struct ArgusPesieveServer {
    HANDLE       accept_thread;
    volatile bool running;
};

// Lightweight JSON helpers (no cJSON dep required for the flat pesieve JSON).

static bool ps_json_get_str(const char* line, const char* key,
                            char* out, size_t out_len) {
    char search[128];
    snprintf(search, sizeof(search), "\"%s\":\"", key);
    const char* p = strstr(line, search);
    if (!p) return false;
    p += strlen(search);
    const char* end = strchr(p, '"');
    if (!end) return false;
    size_t n = (size_t)(end - p);
    if (n >= out_len) n = out_len - 1;
    memcpy(out, p, n);
    out[n] = '\0';
    return true;
}

static bool ps_json_get_uint(const char* line, const char* key, DWORD* out) {
    char search[128];
    snprintf(search, sizeof(search), "\"%s\":", key);
    const char* p = strstr(line, search);
    if (!p) return false;
    p += strlen(search);
    while (*p == ' ') p++;
    if (*p < '0' || *p > '9') return false;
    *out = (DWORD)strtoul(p, NULL, 10);
    return true;
}

// Reads NDJSON ScanFinding lines and routes each one to the correlator.
static DWORD WINAPI pesieve_reader_thread(LPVOID param) {
    HANDLE pipe = (HANDLE)param;

    char  accum[65536];
    int   accum_pos = 0;
    char  read_buf[4096];
    DWORD bytes_read;

    while (1) {
        BOOL ok = ReadFile(pipe, read_buf, sizeof(read_buf) - 1, &bytes_read, NULL);
        if (!ok || bytes_read == 0) break;

        if (accum_pos + (int)bytes_read >= (int)sizeof(accum)) {
            accum_pos = 0;
            continue;
        }
        memcpy(accum + accum_pos, read_buf, bytes_read);
        accum_pos += bytes_read;

        char* start = accum;
        char* nl;
        while ((nl = (char*)memchr(start, '\n',
                      accum_pos - (int)(start - accum))) != NULL) {
            *nl = '\0';
            if (*start != '\0') {
                // Route finding to the correlator.
                DWORD pid = 0;
                char  finding_type[64] = {0};
                if (ps_json_get_uint(start, "pid", &pid) &&
                    ps_json_get_str(start, "finding_type",
                                    finding_type, sizeof(finding_type)) &&
                    pid != 0) {
                    // Parse region.base_address ("0x..." hex string).
                    ULONGLONG base_addr = 0;
                    char base_addr_str[64] = {0};
                    if (ps_json_get_str(start, "base_address",
                                        base_addr_str, sizeof(base_addr_str)))
                        base_addr = strtoull(base_addr_str, NULL, 16);
                    correlator_feed_pesieve(pid, finding_type, base_addr);

                    /* Re-emit raw JSON so the dashboard parser picks it up
                     * as a SCAN_FINDING (same format as internal scanner). */
                    printf("%s\n", start);
                    fflush(stdout);
                }
            }
            start = nl + 1;
        }

        int remaining = accum_pos - (int)(start - accum);
        memmove(accum, start, remaining);
        accum_pos = remaining;
    }

    CloseHandle(pipe);
    return 0;
}

static DWORD WINAPI pesieve_accept_thread(LPVOID param) {
    ArgusPesieveServer* s = (ArgusPesieveServer*)param;

    /* NULL DACL — allow any integrity level (incl. medium) to connect. */
    SECURITY_DESCRIPTOR sd;
    SECURITY_ATTRIBUTES sa;
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
    sa.nLength              = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle       = FALSE;

    while (s->running) {
        HANDLE pipe = CreateNamedPipeW(
            L"\\\\.\\pipe\\argus-pesieve",
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PESIEVE_PIPE_MAX_INSTANCES,
            4096, 65536,
            0, &sa);
        if (pipe == INVALID_HANDLE_VALUE) {
            Sleep(100);
            continue;
        }

        BOOL connected = ConnectNamedPipe(pipe, NULL);
        if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
            CloseHandle(pipe);
            continue;
        }

        printf("  PE-Sieve DLL connected\n");
        fflush(stdout);

        HANDLE t = CreateThread(NULL, 0, pesieve_reader_thread, pipe, 0, NULL);
        if (t) CloseHandle(t);
    }

    return 0;
}

ArgusPesieveServer* pesieve_server_create(void) {
    ArgusPesieveServer* s =
        (ArgusPesieveServer*)calloc(1, sizeof(ArgusPesieveServer));
    if (!s) return NULL;

    s->running = true;
    s->accept_thread = CreateThread(NULL, 0, pesieve_accept_thread, s, 0, NULL);
    if (!s->accept_thread) {
        free(s);
        return NULL;
    }
    return s;
}

void pesieve_server_destroy(ArgusPesieveServer* s) {
    if (!s) return;
    s->running = false;
    WaitForSingleObject(s->accept_thread, 3000);
    CloseHandle(s->accept_thread);
    free(s);
}
