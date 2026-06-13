#!/usr/bin/env python3
"""
Argus EDR Dashboard — Backend

RUN DEMO flow per click:
  1. taskkill all argus_agent.exe (eliminates stale manual-test agents)
  2. Reset state + broadcast STATE_RESET with new generation token
  3. Start fresh argus_agent.exe, begin tailing its log
  4. Wait 3 s for YARA compile + named-pipe servers
  5. Start test_target.exe
  6. Wait 1.5 s, inject argus_hook.dll
  7. Wait 2 s for DLL→pipe handshake
  8. Send \\n to test_target  →  Trinity sequence
  9. Wait 5 s for scan + verdict, send \\n to exit target
"""

import asyncio
import json
import re
import subprocess
import threading
import time
import traceback
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
import uvicorn

HERE = Path(__file__).parent


# ── Build-output discovery ────────────────────────────────────────────────────
def _find_bin_dir() -> Path:
    root = HERE.parent
    for sub in ("", "Debug", "Release", "RelWithDebInfo", "MinSizeRel"):
        d = (root / "build" / "bin" / sub) if sub else (root / "build" / "bin")
        if (d / "argus_agent.exe").exists():
            return d
    return root / "build" / "bin"


# ── Shared state ──────────────────────────────────────────────────────────────
ws_clients: Set[WebSocket] = set()
start_time  = time.time()
demo_gen    = 0          # incremented on every RUN DEMO; guards against stale events

state = {
    "agent_running": False,
    "session_id":    None,
    "agent_pid":     None,
    "gen":           0,
    "stats": {
        "VirtualAllocEx":     0,
        "WriteProcessMemory": 0,
        "VirtualProtect":     0,
        "CreateRemoteThread": 0,
        "yara_matches":       0,
        "pesieve_findings":   0,
        "verdicts_low":       0,
        "verdicts_medium":    0,
        "verdicts_high":      0,
        "verdicts_critical":  0,
        "hook_clients":       0,
        "scans_triggered":    0,
    },
    "processes": {},
    "verdicts":  [],
    "findings":  [],
}

agent_proc: Optional[subprocess.Popen] = None
test_proc:  Optional[subprocess.Popen] = None


# ── App lifespan  (no agent start on boot — only on RUN DEMO) ─────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    state["_startup_called"] = True
    # Verify binaries exist but do NOT start the agent yet.
    # Starting on boot caused stale tail-thread events to bleed into the first demo.
    bin_dir = _find_bin_dir()
    agent_exe = bin_dir / "argus_agent.exe"
    if not agent_exe.exists():
        state["_stream_error"] = f"argus_agent.exe not found at {agent_exe}"
        print(f"[WARNING] {state['_stream_error']}", flush=True)
    yield


app = FastAPI(title="Argus EDR Dashboard", lifespan=lifespan)


# ── Helpers ───────────────────────────────────────────────────────────────────
def now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def ensure_process(pid: str):
    if pid not in state["processes"]:
        state["processes"][pid] = {
            "pid": pid, "name": "unknown", "severity": "NONE",
            "events": [], "verdicts": [], "yara_rules": [], "scans": 0, "findings": 0,
        }
    return state["processes"][pid]


def _reset_state(new_gen: int):
    state["agent_running"] = False
    state["session_id"]    = None
    state["agent_pid"]     = None
    state["gen"]           = new_gen
    state["processes"]     = {}
    state["verdicts"]      = []
    state["findings"]      = []
    for k in state["stats"]:
        state["stats"][k] = 0


# ── Line parser ───────────────────────────────────────────────────────────────
def parse_line(raw: str) -> Optional[dict]:
    line = raw.strip()
    if not line:
        return None

    if "ArgusEDR Agent" in line:
        return {"type": "AGENT_START"}

    if "Ready. Inject hook DLLs to begin" in line:
        return {"type": "AGENT_READY"}

    m = re.search(r'\[YARA\] Compiled (\d+) rule file', line)
    if m:
        return {"type": "YARA_INIT", "rule_count": int(m.group(1))}

    if "argus-events" in line and "pipe" in line:
        return {"type": "IPC_READY"}

    if "argus-pesieve" in line and "pipe" in line:
        return {"type": "PESIEVE_READY"}

    m = re.search(
        r'session\s+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})',
        line, re.IGNORECASE)
    if m:
        return {"type": "SESSION_ID", "session_id": m.group(1)}

    if "hook DLL connected" in line:
        return {"type": "CLIENT_CONNECTED"}

    if "PE-Sieve DLL connected" in line:
        return {"type": "CLIENT_PESIEVE_CONNECTED"}

    m = re.search(r'\[IPC\] event: ({.+})', line)
    if m:
        try:
            ev = json.loads(m.group(1))
            return {"type": "HOOK_EVENT", "event": ev}
        except Exception:
            pass

    if '"PROCESS_VERDICT"' in line and line.startswith('{'):
        try:
            v = json.loads(line)
            return {"type": "PROCESS_VERDICT", "verdict": v}
        except Exception:
            pass

    if '"ts":"' in line and '"finding_type"' in line and line.startswith('{'):
        try:
            f = json.loads(line)
            return {"type": "SCAN_FINDING", "finding": f}
        except Exception:
            pass

    m = re.search(r'\[MAIN\] scan triggered: pid=(\d+)', line)
    if m:
        return {"type": "SCAN_TRIGGERED", "pid": int(m.group(1))}

    m = re.search(r'\[SCANNER\] pid (\d+) -> (\d+) finding', line)
    if m:
        return {"type": "SCAN_COMPLETE", "pid": int(m.group(1)), "count": int(m.group(2))}

    if "[IPC] drop_notice" in line or "[DEBUG]" in line:
        return None

    return {"type": "LOG", "text": line}


# ── State updater ─────────────────────────────────────────────────────────────
def apply_to_state(parsed: dict):
    t = parsed.get("type")
    if t == "SESSION_ID":
        state["session_id"] = parsed["session_id"]
    elif t == "AGENT_START":
        state["agent_running"] = True
    elif t == "CLIENT_CONNECTED":
        state["stats"]["hook_clients"] += 1
    elif t == "CLIENT_PESIEVE_CONNECTED":
        pass  # display only; no stat to update
    elif t == "HOOK_EVENT":
        ev  = parsed["event"]
        api = ev.get("api", "")
        pid = str(ev.get("target_pid", ev.get("pid", "")))
        if api in state["stats"]:
            state["stats"][api] += 1
        if pid:
            ensure_process(pid)["events"].append(api)
    elif t == "PROCESS_VERDICT":
        v   = parsed["verdict"]
        sev = v.get("severity", "").upper()
        pid = str(v.get("pid", ""))
        state["verdicts"].append(v)
        key = f"verdicts_{sev.lower()}"
        if key in state["stats"]:
            state["stats"][key] += 1
        if pid:
            proc = ensure_process(pid)
            proc["severity"] = sev
            proc["verdicts"].append(sev)
    elif t == "SCAN_FINDING":
        f   = parsed["finding"]
        pid = str(f.get("pid", ""))
        ft  = f.get("finding_type", "")
        state["findings"].append(f)
        if ft == "FINDING_YARA_MATCH":
            state["stats"]["yara_matches"] += 1
            rule = (f.get("detail") or {}).get("yara_rule", "")
            if pid and rule:
                p = ensure_process(pid)
                if rule not in p["yara_rules"]:
                    p["yara_rules"].append(rule)
        elif "PE" in ft or "REFLECTIVE" in ft:
            state["stats"]["pesieve_findings"] += 1
        if pid:
            proc = ensure_process(pid)
            proc["findings"] += 1
            name = f.get("process_name", "")
            if name:
                proc["name"] = name
    elif t == "SCAN_TRIGGERED":
        state["stats"]["scans_triggered"] += 1
        pid = str(parsed.get("pid", ""))
        if pid:
            ensure_process(pid)["scans"] += 1
    elif t == "SCAN_COMPLETE":
        pid = str(parsed.get("pid", ""))
        if pid:
            ensure_process(pid)["findings"] = parsed.get("count", 0)


# ── Broadcast ─────────────────────────────────────────────────────────────────
async def broadcast(msg: dict):
    if not ws_clients:
        return
    text = json.dumps(msg)
    dead: Set[WebSocket] = set()
    for ws in list(ws_clients):
        try:
            await ws.send_text(text)
        except Exception:
            dead.add(ws)
    ws_clients.difference_update(dead)


# ── Agent lifecycle ───────────────────────────────────────────────────────────
async def _start_agent_and_tail(gen: int) -> bool:
    """Start a fresh argus_agent.exe and tail its log.  gen is the current
    demo generation; the tail thread will ignore lines once gen is stale."""
    global agent_proc

    bin_dir   = _find_bin_dir()
    agent_exe = str(bin_dir / "argus_agent.exe")
    agent_log = bin_dir / "argus_agent.log"

    if not Path(agent_exe).exists():
        await broadcast({"type": "ERROR",
                         "text": f"argus_agent.exe not found at {agent_exe}. Build first."})
        return False

    # Truncate (not unlink) — on Windows another reader may hold the file open.
    log_fh = open(agent_log, "wb")
    proc   = subprocess.Popen([agent_exe], stdout=log_fh, stderr=log_fh,
                               cwd=str(bin_dir))
    log_fh.close()

    agent_proc         = proc
    state["agent_pid"] = proc.pid
    state["_tail_lines_seen"] = 0
    state["_tail_error"]      = None

    await broadcast({"type": "AGENT_STATUS", "running": True, "pid": proc.pid})

    loop       = asyncio.get_running_loop()
    local_proc = proc  # snapshot; tail exits when agent_proc is replaced

    def _tail():
        buf = ""
        try:
            with open(agent_log, "r", encoding="utf-8", errors="replace") as fh:
                while local_proc.poll() is None and agent_proc is local_proc:
                    chunk = fh.read(4096)
                    if chunk:
                        buf += chunk
                        while "\n" in buf:
                            line, buf = buf.split("\n", 1)
                            state["_tail_lines_seen"] = state.get("_tail_lines_seen", 0) + 1
                            asyncio.run_coroutine_threadsafe(
                                _handle(line + "\n", gen), loop)
                    else:
                        time.sleep(0.05)
                # drain only if still the active proc
                if agent_proc is local_proc:
                    if buf:
                        asyncio.run_coroutine_threadsafe(_handle(buf, gen), loop)
                    for line in fh:
                        asyncio.run_coroutine_threadsafe(_handle(line, gen), loop)
        except Exception as exc:
            state["_tail_error"] = str(exc)
        if agent_proc is local_proc:
            asyncio.run_coroutine_threadsafe(_on_agent_exit(), loop)

    threading.Thread(target=_tail, daemon=True).start()
    return True


async def _handle(raw: str, gen: int):
    """Parse one log line and broadcast if it belongs to the current generation."""
    if gen != demo_gen:
        return   # stale — belongs to a previous demo run
    parsed = parse_line(raw)
    if parsed is None:
        return
    apply_to_state(parsed)
    await broadcast({"type": "PARSED_EVENT", "gen": gen, "ts": now_ts(),
                     "raw": raw.strip(), "parsed": parsed})


async def _on_agent_exit():
    state["agent_running"] = False
    await broadcast({"type": "AGENT_STATUS", "running": False})


# ── Demo sequence ─────────────────────────────────────────────────────────────
async def _inject_async(inj_exe: str, target_pid: int, dll_path: str, bin_dir: str):
    """Run injector.exe asynchronously so the event loop stays live during injection."""
    proc = await asyncio.create_subprocess_exec(
        inj_exe, str(target_pid), dll_path,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=bin_dir,
    )
    stdout_b, stderr_b = await proc.communicate()
    output = (stdout_b.decode(errors="replace") + stderr_b.decode(errors="replace")).strip()
    return proc.returncode == 0, output


async def run_test_sequence():
    global agent_proc, test_proc, demo_gen

    bin_dir      = _find_bin_dir()
    test_exe     = str(bin_dir / "test_target.exe")
    inj_exe      = str(bin_dir / "injector.exe")
    hook_dll     = str(bin_dir / "argus_hook.dll")
    pesieve_dll  = str(bin_dir / "argus_pesieve.dll")

    for exe in (test_exe, inj_exe, hook_dll):
        if not Path(exe).exists():
            await broadcast({"type": "ERROR", "text": f"Not found: {exe}"})
            return

    # ── Stage 0 : kill ALL stale processes ───────────────────────────────────
    # Kill stale argus_agent.exe (stale agents intercept the hook DLL connection).
    # Kill stale test_target.exe (its loaded DLLs reconnect to the new agent pipe).
    subprocess.run(["taskkill", "/F", "/IM", "argus_agent.exe", "/T"],
                   capture_output=True)
    subprocess.run(["taskkill", "/F", "/IM", "test_target.exe", "/T"],
                   capture_output=True)
    if agent_proc and agent_proc.poll() is None:
        agent_proc.kill()
    agent_proc = None

    # Advance generation so old tail-thread events are dropped
    demo_gen += 1
    gen = demo_gen

    _reset_state(gen)
    await broadcast({"type": "STATE_RESET", "gen": gen})

    # ── Stage 1 : fresh agent ─────────────────────────────────────────────────
    await broadcast({"type": "DEMO_STAGE", "stage": 1, "label": "Agent Starting"})
    ok = await _start_agent_and_tail(gen)
    if not ok:
        return

    # Wait for YARA compile + named-pipe servers to be ready
    await asyncio.sleep(3.0)

    # ── Stage 2 : test target ─────────────────────────────────────────────────
    await broadcast({"type": "DEMO_STAGE", "stage": 2, "label": "Target Started"})
    test_proc = subprocess.Popen(
        [test_exe],
        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        cwd=str(bin_dir), text=True,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    target_pid = test_proc.pid
    await broadcast({"type": "TEST_STARTED", "pid": target_pid, "ts": now_ts()})

    await asyncio.sleep(1.5)

    # ── Stage 3 : inject hook DLL (async — keeps event loop alive) ────────────
    hook_ok, hook_out = await _inject_async(inj_exe, target_pid, hook_dll, str(bin_dir))
    await broadcast({"type": "INJECT_RESULT", "pid": target_pid, "success": hook_ok,
                     "ts": now_ts(), "output": hook_out})

    if not hook_ok:
        await broadcast({"type": "ERROR",
                         "text": "Hook DLL injection failed — run start_dashboard.bat as Administrator"})
        try:
            test_proc.stdin.close()
        except Exception:
            pass
        return

    await broadcast({"type": "DEMO_STAGE", "stage": 3, "label": "Hook DLL Injected"})

    # Wait for hook DLL to connect to the agent pipe
    await asyncio.sleep(1.5)

    # ── Stage 4 : inject PE-Sieve DLL ─────────────────────────────────────────
    if Path(pesieve_dll).exists():
        ps_ok, ps_out = await _inject_async(inj_exe, target_pid, pesieve_dll, str(bin_dir))
        await broadcast({"type": "PESIEVE_INJECT_RESULT", "pid": target_pid, "success": ps_ok,
                         "ts": now_ts(), "output": ps_out})
        if ps_ok:
            await broadcast({"type": "DEMO_STAGE", "stage": 4, "label": "PE-Sieve Injected"})
    else:
        await broadcast({"type": "DEMO_STAGE", "stage": 4, "label": "PE-Sieve Injected"})

    # Allow PE-Sieve DLL scan to start (scan_thread runs immediately after DllMain)
    await asyncio.sleep(2.0)

    # ── Stage 5 : Trinity ─────────────────────────────────────────────────────
    await broadcast({"type": "DEMO_STAGE", "stage": 5, "label": "Trinity Triggered"})
    try:
        test_proc.stdin.write("\n")
        test_proc.stdin.flush()
        await broadcast({"type": "TEST_TRINITY_START", "pid": target_pid, "ts": now_ts()})
    except Exception as e:
        await broadcast({"type": "ERROR", "text": f"stdin write failed: {e}"})
        return

    # Wait for full detection chain: hook events → YARA scan → verdict
    await asyncio.sleep(8.0)

    # ── Stage 6 : let target exit ─────────────────────────────────────────────
    try:
        test_proc.stdin.write("\n")
        test_proc.stdin.flush()
    except Exception:
        pass  # target may already be dead (ENABLE_ACTIVE_RESPONSE killed it)

    await asyncio.sleep(1.0)
    await broadcast({"type": "TEST_COMPLETE", "pid": target_pid, "ts": now_ts()})


# ── Routes ────────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse((HERE / "index.html").read_text(encoding="utf-8"))


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    ws_clients.add(ws)
    await ws.send_text(json.dumps({
        "type": "STATE_SNAPSHOT", "state": state,
        "uptime": int(time.time() - start_time),
    }))
    try:
        while True:
            await asyncio.sleep(1)
            await ws.send_text(json.dumps({
                "type": "HEARTBEAT",
                "uptime": int(time.time() - start_time),
                "agent_running": state["agent_running"],
                "stats": state["stats"],
            }))
    except WebSocketDisconnect:
        ws_clients.discard(ws)
    except Exception:
        ws_clients.discard(ws)


@app.post("/api/run-test")
async def api_run_test():
    asyncio.create_task(run_test_sequence())
    return {"status": "started"}


@app.get("/api/state")
async def api_state():
    return {**state, "uptime": int(time.time() - start_time)}


@app.get("/api/debug")
async def api_debug():
    bin_dir   = _find_bin_dir()
    agent_log = bin_dir / "argus_agent.log"
    log_lines = []
    if agent_log.exists():
        with open(agent_log, "r", encoding="utf-8", errors="replace") as f:
            log_lines = [l.rstrip() for l in f.readlines()[:40]]
    return {
        "demo_gen":         demo_gen,
        "state_gen":        state.get("gen"),
        "agent_running":    state["agent_running"],
        "agent_pid":        state["agent_pid"],
        "session_id":       state["session_id"],
        "tail_lines_seen":  state.get("_tail_lines_seen"),
        "tail_error":       state.get("_tail_error"),
        "stream_error":     state.get("_stream_error"),
        "bin_dir":          str(bin_dir),
        "agent_exe_exists": (bin_dir / "argus_agent.exe").exists(),
        "log_exists":       agent_log.exists(),
        "log_path":         str(agent_log),
        "log_lines":        log_lines,
    }


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    bin_dir = _find_bin_dir()
    print("=" * 60)
    print("  ARGUS EDR Dashboard")
    print(f"  Binaries : {bin_dir}")
    print(f"  Listen   : http://localhost:8080")
    print("  Run as Administrator for injection to work")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="warning")
