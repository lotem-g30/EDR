#include "ipc_client.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

struct ArgusIpcClient {
    EventQueue*   queue;
    HANDLE        pipe;
    HANDLE        thread;
    HANDLE        stop_event;
    volatile bool connected;
    uint64_t      last_seen_drops;
};

static DWORD WINAPI drain_thread(LPVOID param);

static HANDLE connect_to_pipe(DWORD retry_ms) {
    DWORD start = GetTickCount();
    while (1) {
        WaitNamedPipeW(PIPE_NAME, 1000);
        HANDLE h = CreateFileW(
            PIPE_NAME,
            GENERIC_WRITE,
            0, NULL,
            OPEN_EXISTING,
            0, NULL
        );
        if (h != INVALID_HANDLE_VALUE)
            return h;
        if (GetTickCount() - start >= retry_ms)
            return INVALID_HANDLE_VALUE;
        Sleep(100);
    }
}

ArgusIpcClient* ipc_client_create(EventQueue* queue, DWORD retry_ms) {
    ArgusIpcClient* c = (ArgusIpcClient*)calloc(1, sizeof(ArgusIpcClient));
    if (!c) return NULL;

    c->queue      = queue;
    c->stop_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    c->pipe       = connect_to_pipe(retry_ms);
    c->connected  = (c->pipe != INVALID_HANDLE_VALUE);

    c->thread = CreateThread(NULL, 0, drain_thread, c, 0, NULL);
    return c;
}

void ipc_client_destroy(ArgusIpcClient* c) {
    SetEvent(c->stop_event);
    WaitForSingleObject(c->thread, INFINITE);
    if (c->pipe != INVALID_HANDLE_VALUE)
        CloseHandle(c->pipe);
    CloseHandle(c->stop_event);
    CloseHandle(c->thread);
    free(c);
}

bool ipc_client_connected(ArgusIpcClient* c) {
    return c->connected;
}

static void write_line(ArgusIpcClient* c, const char* msg, size_t len) {
    if (c->pipe == INVALID_HANDLE_VALUE) return;
    DWORD written;
    BOOL ok = WriteFile(c->pipe, msg, (DWORD)len, &written, NULL);
    if (!ok && GetLastError() == ERROR_BROKEN_PIPE) {
        CloseHandle(c->pipe);
        c->connected = false;
        c->pipe = connect_to_pipe(5000);
        c->connected = (c->pipe != INVALID_HANDLE_VALUE);
        if (c->connected)
            WriteFile(c->pipe, msg, (DWORD)len, &written, NULL);
    }
}

static DWORD WINAPI drain_thread(LPVOID param) {
    ArgusIpcClient* c = (ArgusIpcClient*)param;

    // +2: room for '\n' appended to the event and a null terminator
    char event[EQ_MAX_EVENT_LEN + 2];

    while (1) {
        if (WaitForSingleObject(c->stop_event, 1) == WAIT_OBJECT_0)
            break;

        // emit drop notice before next event if drops occurred
        uint64_t current_drops = eq_dropped(c->queue);
        if (current_drops > c->last_seen_drops) {
            char notice[128];
            int nlen = sprintf(notice,
                "{\"type\":\"drop_notice\",\"dropped\":%llu}\n",
                (unsigned long long)(current_drops - c->last_seen_drops));
            write_line(c, notice, (size_t)nlen);
            c->last_seen_drops = current_drops;
        }

        if (eq_pop(c->queue, event, EQ_MAX_EVENT_LEN)) {
            size_t len = strlen(event);
            event[len]     = '\n';
            event[len + 1] = '\0';
            write_line(c, event, len + 1);
        }
    }

    // drain remaining events before exit
    while (eq_pop(c->queue, event, EQ_MAX_EVENT_LEN)) {
        size_t len = strlen(event);
        event[len] = '\n';
        if (c->pipe != INVALID_HANDLE_VALUE) {
            DWORD written;
            WriteFile(c->pipe, event, (DWORD)(len + 1), &written, NULL);
        }
    }

    return 0;
}
