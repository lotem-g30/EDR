#include "ipc_server.h"
#include "correlator.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// APIs that additionally trigger a full memory + YARA scan of the target.
static const char* TRIGGER_APIS[] = {
    "VirtualAlloc",
    "VirtualAllocEx",
    "CreateThread",
    "CreateRemoteThread",
    "WriteProcessMemory",
    "VirtualProtect",
    NULL
};

// ── Trigger queue ─────────────────────────────────────────────────────────────

#define TRIGGER_QUEUE_CAP 256

typedef struct {
    ScanTrigger      buf[TRIGGER_QUEUE_CAP];
    uint32_t         head;
    uint32_t         tail;
    CRITICAL_SECTION lock;
    HANDLE           sem;   // semaphore: count == number of queued items
} TriggerQueue;

static void tq_init(TriggerQueue* q) {
    memset(q->buf, 0, sizeof(q->buf));
    q->head = q->tail = 0;
    InitializeCriticalSection(&q->lock);
    q->sem = CreateSemaphore(NULL, 0, TRIGGER_QUEUE_CAP, NULL);
}

static void tq_destroy(TriggerQueue* q) {
    CloseHandle(q->sem);
    DeleteCriticalSection(&q->lock);
}

static void tq_push(TriggerQueue* q, DWORD pid) {
    EnterCriticalSection(&q->lock);
    uint32_t next = (q->head + 1) % TRIGGER_QUEUE_CAP;
    if (next != q->tail) {
        q->buf[q->head].pid = pid;
        q->head = next;
        ReleaseSemaphore(q->sem, 1, NULL);
    }
    // silently drop if full
    LeaveCriticalSection(&q->lock);
}

static bool tq_pop(TriggerQueue* q, DWORD timeout_ms, ScanTrigger* out) {
    if (WaitForSingleObject(q->sem, timeout_ms) != WAIT_OBJECT_0)
        return false;
    EnterCriticalSection(&q->lock);
    *out = q->buf[q->tail];
    q->tail = (q->tail + 1) % TRIGGER_QUEUE_CAP;
    LeaveCriticalSection(&q->lock);
    return true;
}

// ── Server struct ─────────────────────────────────────────────────────────────

struct ArgusIpcServer {
    char         session_id[ARGUS_MAX_UUID];
    HANDLE       accept_thread;
    volatile bool running;
    TriggerQueue  triggers;
};

// ── Per-client reader ─────────────────────────────────────────────────────────

typedef struct {
    HANDLE           pipe;
    char             session_id[ARGUS_MAX_UUID];
    ArgusIpcServer*  server;
} ClientContext;

static bool is_trigger_api(const char* name) {
    for (int i = 0; TRIGGER_APIS[i]; i++)
        if (strcmp(name, TRIGGER_APIS[i]) == 0) return true;
    return false;
}

// Extract the value of a JSON string field: "key":"value" → value
static bool json_get_string(const char* line, const char* key,
                            char* out, size_t out_size) {
    char search[128];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char* pos = strstr(line, search);
    if (!pos) return false;
    const char* colon = strchr(pos + strlen(search), ':');
    if (!colon) return false;
    const char* q1 = strchr(colon + 1, '"');
    if (!q1) return false;
    const char* q2 = strchr(q1 + 1, '"');
    if (!q2) return false;
    size_t len = (size_t)(q2 - q1 - 1);
    if (len >= out_size) len = out_size - 1;
    memcpy(out, q1 + 1, len);
    out[len] = '\0';
    return true;
}

// Extract the value of a JSON number field: "key":12345 → 12345
static bool json_get_uint(const char* line, const char* key, DWORD* out) {
    char search[128];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char* pos = strstr(line, search);
    if (!pos) return false;
    const char* colon = strchr(pos + strlen(search), ':');
    if (!colon) return false;
    const char* p = colon + 1;
    while (*p == ' ' || *p == '\t') p++;
    if (*p < '0' || *p > '9') return false;
    *out = (DWORD)strtoul(p, NULL, 10);
    return true;
}

static DWORD WINAPI client_reader_thread(LPVOID param) {
    ClientContext* ctx = (ClientContext*)param;
    HANDLE pipe = ctx->pipe;

    char  accum[16384];
    int   accum_pos = 0;
    char  read_buf[4096];
    DWORD bytes_read;

    while (1) {
        BOOL ok = ReadFile(pipe, read_buf, sizeof(read_buf) - 1, &bytes_read, NULL);
        if (!ok || bytes_read == 0) break;

        if (accum_pos + (int)bytes_read >= (int)sizeof(accum)) {
            accum_pos = 0;  // overflow: reset accumulator
            continue;
        }
        memcpy(accum + accum_pos, read_buf, bytes_read);
        accum_pos += bytes_read;

        char* start = accum;
        char* nl;
        while ((nl = (char*)memchr(start, '\n',
                accum_pos - (int)(start - accum))) != NULL) {
            *nl = '\0';

            // drop notice
            char type_val[64] = {0};
            if (json_get_string(start, "type", type_val, sizeof(type_val)) &&
                strcmp(type_val, "drop_notice") == 0) {
                DWORD dropped = 0;
                json_get_uint(start, "dropped", &dropped);
                printf("  warn      %lu hook event(s) dropped\n", (unsigned long)dropped);
                start = nl + 1;
                continue;
            }

            // normal API event
            char api[128] = {0};
            if (json_get_string(start, "api", api, sizeof(api))) {
                DWORD target_pid = 0;
                json_get_uint(start, "target_pid", &target_pid);

                if (target_pid != 0) {
                    DWORD protect = 0;
                    if (strcmp(api, "VirtualProtect")  == 0 ||
                        strcmp(api, "VirtualAlloc")    == 0 ||
                        strcmp(api, "VirtualAllocEx")  == 0)
                        json_get_uint(start, "protect", &protect);

                    ULONGLONG addr = 0;
                    ULONGLONG sz   = 0;
                    char addr_str[64] = {0};
                    if (json_get_string(start, "address", addr_str, sizeof(addr_str)))
                        addr = strtoull(addr_str, NULL, 16);
                    DWORD sz_dw = 0;
                    if (json_get_uint(start, "size", &sz_dw))
                        sz = (ULONGLONG)sz_dw;

                    correlator_feed_hook_event(target_pid, api, protect, addr, sz);

                    if (is_trigger_api(api))
                        tq_push(&ctx->server->triggers, target_pid);

                    /* Emit structured line so the dashboard parser can pick up hook events. */
                    printf("[IPC] event: %s\n", start);
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
    free(ctx);
    return 0;
}

// ── Accept loop ───────────────────────────────────────────────────────────────

static DWORD WINAPI accept_loop_thread(LPVOID param) {
    ArgusIpcServer* s = (ArgusIpcServer*)param;

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
            L"\\\\.\\pipe\\argus-events",
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            IPC_SERVER_MAX_INSTANCES,
            4096, 16384,
            0, &sa
        );
        if (pipe == INVALID_HANDLE_VALUE) {
            Sleep(100);
            continue;
        }

        BOOL connected = ConnectNamedPipe(pipe, NULL);
        if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
            CloseHandle(pipe);
            continue;
        }

        printf("  hook DLL connected\n");
        fflush(stdout);

        ClientContext* ctx = (ClientContext*)calloc(1, sizeof(ClientContext));
        ctx->pipe   = pipe;
        ctx->server = s;
        strncpy(ctx->session_id, s->session_id, ARGUS_MAX_UUID - 1);

        HANDLE t = CreateThread(NULL, 0, client_reader_thread, ctx, 0, NULL);
        if (t) CloseHandle(t);  // detach; thread frees ctx on exit
    }

    return 0;
}

// ── Public API ────────────────────────────────────────────────────────────────

ArgusIpcServer* ipc_server_create(const char* session_id) {
    ArgusIpcServer* s = (ArgusIpcServer*)calloc(1, sizeof(ArgusIpcServer));
    if (!s) return NULL;

    strncpy(s->session_id, session_id, ARGUS_MAX_UUID - 1);
    s->running = true;
    tq_init(&s->triggers);

    s->accept_thread = CreateThread(NULL, 0, accept_loop_thread, s, 0, NULL);
    return s;
}

void ipc_server_destroy(ArgusIpcServer* s) {
    s->running = false;
    WaitForSingleObject(s->accept_thread, 3000);
    CloseHandle(s->accept_thread);
    tq_destroy(&s->triggers);
    free(s);
}

bool ipc_server_dequeue_trigger(ArgusIpcServer* s, DWORD timeout_ms, ScanTrigger* out) {
    return tq_pop(&s->triggers, timeout_ms, out);
}

void ipc_server_push_trigger(ArgusIpcServer* s, DWORD pid) {
    tq_push(&s->triggers, pid);
}
