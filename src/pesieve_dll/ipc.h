#pragma once
#include <windows.h>
#include "argus/events.h"

// Fills buf with the current UTC time formatted as "YYYY-MM-DDTHH:MM:SSZ".
void get_timestamp(char* buf, size_t len);

// Fills buf with a freshly generated UUID string (no braces).
void gen_uuid(char* buf, size_t len);

// Connects to the argus-pesieve named pipe, retrying for up to 3 seconds.
// Returns INVALID_HANDLE_VALUE if the pipe is not available within that window.
HANDLE connect_to_pipe(void);

// Serialises and sends one finding through 'pipe'.
// base_address, region_size, and protect may be 0 for aggregate PE-Sieve
// findings where no specific region address is available.
// Addresses that fall within Argus-owned ranges are silently suppressed.
// Returns true on a successful WriteFile.
bool emit_finding_at(HANDLE pipe,
                     DWORD self_pid,
                     const char* process_name,
                     const char* session_id,
                     const char* scan_id,
                     FindingType ft,
                     ULONGLONG base_address,
                     ULONGLONG region_size,
                     DWORD protect,
                     const char* anomaly);

// Convenience wrapper for PE-Sieve aggregate findings (no specific region).
void emit_finding(HANDLE pipe,
                  DWORD self_pid,
                  const char* process_name,
                  const char* session_id,
                  const char* scan_id,
                  FindingType ft,
                  const char* anomaly);
