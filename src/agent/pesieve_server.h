#pragma once
#include <windows.h>
#include <stdbool.h>
#include "ipc_server.h"

typedef struct ArgusPesieveServer ArgusPesieveServer;

// Creates a named-pipe server on \\.\pipe\argus-pesieve that reads
// NDJSON ScanFinding lines emitted by argus_pesieve.dll, routes them to
// the correlator, and enqueues a YARA scan trigger for findings whose
// address was not already covered by a hook event.
ArgusPesieveServer* pesieve_server_create(ArgusIpcServer* ipc);
void                pesieve_server_destroy(ArgusPesieveServer* s);
