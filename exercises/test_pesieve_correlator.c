/*
 * test_pesieve_correlator.c  —  Integration tests for correlator_feed_pesieve()
 *
 * Verifies that the PE-Sieve feeding path correctly escalates severity, emits
 * PROCESS_VERDICT JSON, and deduplicates localized findings that were already
 * captured by a prior hook event.
 *
 * Build (from project root):
 *   cl /std:c17 exercises\test_pesieve_correlator.c src\agent\correlator.c ^
 *      /Fe:test_pesieve_correlator.exe /I src\agent /I include
 *   test_pesieve_correlator.exe
 */

#include <fcntl.h>
#include <io.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "correlator.h"

// ── stdout capture ─────────────────────────────────────────────────────────────
//
// Redirects fd 1 (stdout) to the write end of an anonymous pipe so that
// printf output from the correlator can be read back into a buffer.
// Restoring fd 1 is done by dup-ing a saved copy back over it.

#define CAPTURE_BUF_SIZE 8192

typedef struct {
    int saved_fd;    // dup of original fd 1
    int pipe_rd;     // read end of the capture pipe
    int pipe_wr;     // write end of the capture pipe
} StdoutCapture;

static void capture_begin(StdoutCapture* cap) {
    int pfd[2];
    _pipe(pfd, CAPTURE_BUF_SIZE, _O_TEXT);
    cap->pipe_rd = pfd[0];
    cap->pipe_wr = pfd[1];

    fflush(stdout);
    cap->saved_fd = _dup(_fileno(stdout));
    _dup2(cap->pipe_wr, _fileno(stdout));
    setvbuf(stdout, NULL, _IONBF, 0);  // ensure writes go through immediately
}

// Returns the number of bytes read into buf (null-terminated).
static int capture_end(StdoutCapture* cap, char* buf, int buf_size) {
    fflush(stdout);
    _dup2(cap->saved_fd, _fileno(stdout));
    _close(cap->saved_fd);
    _close(cap->pipe_wr);  // EOF so _read returns

    int n = _read(cap->pipe_rd, buf, buf_size - 1);
    if (n < 0) n = 0;
    buf[n] = '\0';
    _close(cap->pipe_rd);
    return n;
}

// ── Minimal test harness ───────────────────────────────────────────────────────

static int g_failures = 0;

static void check(int condition, const char* msg) {
    if (!condition) {
        fprintf(stderr, "  [FAIL] %s\n", msg);
        g_failures++;
    }
}

// ── Individual tests ───────────────────────────────────────────────────────────

// 1. Primary requirement: FINDING_PE_IMPLANT → PROCESS_VERDICT with HIGH.
static void test_pe_implant_escalates_to_high(void) {
    printf("  [TEST] FINDING_PE_IMPLANT escalates to HIGH ... ");

    correlator_init();

    StdoutCapture cap;
    capture_begin(&cap);
    correlator_feed_pesieve(1337, "FINDING_PE_IMPLANT", 0x00007FF700000000ULL);
    char buf[CAPTURE_BUF_SIZE];
    capture_end(&cap, buf, sizeof(buf));

    correlator_destroy();

    check(strstr(buf, "PROCESS_VERDICT")       != NULL, "output must contain PROCESS_VERDICT");
    check(strstr(buf, "\"pid\":1337")           != NULL, "output must contain \"pid\":1337");
    check(strstr(buf, "\"severity\":\"HIGH\"")  != NULL, "output must contain \"severity\":\"HIGH\"");
    check(strstr(buf, "PE-Sieve")              != NULL, "trigger must reference PE-Sieve");

    printf(g_failures == 0 ? "PASS\n" : "FAIL\n");
    printf("    captured: %s\n", buf);
}

// 2. FINDING_PE_HOLLOWING is also structural → must escalate to HIGH.
static void test_pe_hollowing_escalates_to_high(void) {
    printf("  [TEST] FINDING_PE_HOLLOWING escalates to HIGH ... ");

    correlator_init();

    StdoutCapture cap;
    capture_begin(&cap);
    correlator_feed_pesieve(2001, "FINDING_PE_HOLLOWING", 0x0000000140000000ULL);
    char buf[CAPTURE_BUF_SIZE];
    capture_end(&cap, buf, sizeof(buf));

    correlator_destroy();

    int before = g_failures;
    check(strstr(buf, "PROCESS_VERDICT")      != NULL, "HOLLOWING: must contain PROCESS_VERDICT");
    check(strstr(buf, "\"pid\":2001")          != NULL, "HOLLOWING: must contain pid 2001");
    check(strstr(buf, "\"severity\":\"HIGH\"") != NULL, "HOLLOWING: severity must be HIGH");
    printf(g_failures == before ? "PASS\n" : "FAIL\n");
}

// 3. FINDING_REFLECTIVE_LOAD is structural → must escalate to HIGH.
static void test_reflective_load_escalates_to_high(void) {
    printf("  [TEST] FINDING_REFLECTIVE_LOAD escalates to HIGH ... ");

    correlator_init();

    StdoutCapture cap;
    capture_begin(&cap);
    correlator_feed_pesieve(3000, "FINDING_REFLECTIVE_LOAD", 0x0000000140001000ULL);
    char buf[CAPTURE_BUF_SIZE];
    capture_end(&cap, buf, sizeof(buf));

    correlator_destroy();

    int before = g_failures;
    check(strstr(buf, "PROCESS_VERDICT")      != NULL, "REFLECTIVE: must contain PROCESS_VERDICT");
    check(strstr(buf, "\"pid\":3000")          != NULL, "REFLECTIVE: must contain pid 3000");
    check(strstr(buf, "\"severity\":\"HIGH\"") != NULL, "REFLECTIVE: severity must be HIGH");
    printf(g_failures == before ? "PASS\n" : "FAIL\n");
}

// 4. FINDING_CODE_CAVE with no prior hook → not deduplicated → escalates to MEDIUM.
static void test_code_cave_no_prior_hook_escalates_to_medium(void) {
    printf("  [TEST] FINDING_CODE_CAVE (no prior hook) escalates to MEDIUM ... ");

    correlator_init();

    StdoutCapture cap;
    capture_begin(&cap);
    correlator_feed_pesieve(4242, "FINDING_CODE_CAVE", 0x00007FF800001000ULL);
    char buf[CAPTURE_BUF_SIZE];
    capture_end(&cap, buf, sizeof(buf));

    correlator_destroy();

    int before = g_failures;
    check(strstr(buf, "PROCESS_VERDICT")        != NULL, "CODE_CAVE: must contain PROCESS_VERDICT");
    check(strstr(buf, "\"pid\":4242")            != NULL, "CODE_CAVE: must contain pid 4242");
    check(strstr(buf, "\"severity\":\"MEDIUM\"") != NULL, "CODE_CAVE: severity must be MEDIUM");
    printf(g_failures == before ? "PASS\n" : "FAIL\n");
}

// 5. FINDING_CODE_CAVE at an address previously touched by VirtualProtect
//    → deduplication fires: no PROCESS_VERDICT, [CORRELATOR] Deduplicated logged.
static void test_code_cave_deduped_by_vprotect_hook(void) {
    printf("  [TEST] FINDING_CODE_CAVE after VirtualProtect hook is deduplicated ... ");

    correlator_init();

    // Feed the VirtualProtect hook event BEFORE the capture so its own output
    // (if any) does not enter the capture buffer.  With protect_flags=0 there
    // is no exec bit, so the hook itself emits no verdict — only records region.
    correlator_feed_hook_event(5555, "VirtualProtect", 0,
                               0x00007FF800001000ULL, 0x1000ULL);

    StdoutCapture cap;
    capture_begin(&cap);
    // PE-Sieve reports CODE_CAVE at the same address — should be suppressed.
    correlator_feed_pesieve(5555, "FINDING_CODE_CAVE", 0x00007FF800001000ULL);
    char buf[CAPTURE_BUF_SIZE];
    capture_end(&cap, buf, sizeof(buf));

    correlator_destroy();

    int before = g_failures;
    check(strstr(buf, "PROCESS_VERDICT") == NULL, "deduped: must NOT emit PROCESS_VERDICT");
    check(strstr(buf, "Deduplicated")    != NULL, "deduped: must log Deduplicated notice");
    check(strstr(buf, "VirtualProtect")  != NULL, "deduped: notice must name the prior hook");
    printf(g_failures == before ? "PASS\n" : "FAIL\n");
    printf("    captured: %s\n", buf);
}

// 6. FINDING_CODE_CAVE at an address touched by WriteProcessMemory
//    → deduplication fires for that hook type as well.
static void test_code_cave_deduped_by_write_hook(void) {
    printf("  [TEST] FINDING_CODE_CAVE after WriteProcessMemory hook is deduplicated ... ");

    correlator_init();

    correlator_feed_hook_event(6100, "WriteProcessMemory", 0,
                               0x00007FFA00002000ULL, 0x500ULL);

    StdoutCapture cap;
    capture_begin(&cap);
    // Address falls within [0x7FFA00002000, 0x7FFA00002500).
    correlator_feed_pesieve(6100, "FINDING_CODE_CAVE", 0x00007FFA00002100ULL);
    char buf[CAPTURE_BUF_SIZE];
    capture_end(&cap, buf, sizeof(buf));

    correlator_destroy();

    int before = g_failures;
    check(strstr(buf, "PROCESS_VERDICT")   == NULL, "WPM dedup: must NOT emit PROCESS_VERDICT");
    check(strstr(buf, "Deduplicated")      != NULL, "WPM dedup: must log Deduplicated notice");
    check(strstr(buf, "WriteProcessMemory")!= NULL, "WPM dedup: notice must name WriteProcessMemory");
    printf(g_failures == before ? "PASS\n" : "FAIL\n");
}

// 7. Structural findings (PE_IMPLANT) are NEVER deduplicated even if a hook
//    event already recorded the same region.
static void test_structural_finding_not_deduped_by_prior_hook(void) {
    printf("  [TEST] Structural FINDING_PE_IMPLANT is NOT deduplicated by prior hook ... ");

    correlator_init();

    // Record a WriteProcessMemory covering the same address.
    // This also escalates pid 6666 to MEDIUM (emit happens before capture).
    correlator_feed_hook_event(6666, "WriteProcessMemory", 0,
                               0x00007FF900000000ULL, 0x2000ULL);

    StdoutCapture cap;
    capture_begin(&cap);
    // Structural finding — must escalate to HIGH regardless.
    correlator_feed_pesieve(6666, "FINDING_PE_IMPLANT", 0x00007FF900000000ULL);
    char buf[CAPTURE_BUF_SIZE];
    capture_end(&cap, buf, sizeof(buf));

    correlator_destroy();

    int before = g_failures;
    check(strstr(buf, "PROCESS_VERDICT")      != NULL, "structural: must emit PROCESS_VERDICT");
    check(strstr(buf, "\"pid\":6666")          != NULL, "structural: must contain pid 6666");
    check(strstr(buf, "\"severity\":\"HIGH\"") != NULL, "structural: severity must be HIGH (not deduped)");
    check(strstr(buf, "Deduplicated")         == NULL, "structural: must NOT log Deduplicated");
    printf(g_failures == before ? "PASS\n" : "FAIL\n");
}

// ── Entry point ────────────────────────────────────────────────────────────────

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== PE-Sieve Correlator Integration Tests ===\n\n");

    test_pe_implant_escalates_to_high();
    test_pe_hollowing_escalates_to_high();
    test_reflective_load_escalates_to_high();
    test_code_cave_no_prior_hook_escalates_to_medium();
    test_code_cave_deduped_by_vprotect_hook();
    test_code_cave_deduped_by_write_hook();
    test_structural_finding_not_deduped_by_prior_hook();

    printf("\n");
    if (g_failures == 0) {
        printf("All tests passed.\n");
        return 0;
    }
    fprintf(stderr, "%d test(s) FAILED.\n", g_failures);
    return 1;
}
