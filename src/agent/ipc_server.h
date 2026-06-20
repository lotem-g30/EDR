#pragma once
#include <windows.h>
#include <stdbool.h>
#include "argus/events.h"

#define IPC_SERVER_MAX_INSTANCES 64

typedef struct {
    DWORD pid;
} ScanTrigger;

typedef struct ArgusIpcServer ArgusIpcServer;

ArgusIpcServer* ipc_server_create(const char* session_id);
void            ipc_server_destroy(ArgusIpcServer* s);

// Blocks up to timeout_ms waiting for the next trigger.
// Returns true and fills *out on success; false on timeout.
bool ipc_server_dequeue_trigger(ArgusIpcServer* s, DWORD timeout_ms, ScanTrigger* out);

// Enqueue a scan trigger for pid (same queue that hook events use).
// Silently dropped if the queue is full.
void ipc_server_push_trigger(ArgusIpcServer* s, DWORD pid);
