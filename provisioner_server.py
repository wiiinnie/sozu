#!/usr/bin/env python3
"""
Provisioner Manager – Web Backend
Version: v0.5.30

Wraps provisioner manager CLI commands as REST endpoints.
Run: python3 provisioner_server.py
Then open provisioner_dashboard.html in your browser.

Requires: pip install flask flask-cors

  v0.4.0  Rotation logic fully rewritten — event-driven state machine.
          liquidating/terminating states wait for own SOZU events before proceeding.
          Amount distributed from liquidation event LUX field (not pool balance).
          Per-tick retry: liquidate or terminate independently if event missing.
Changelog:
  v0.3.4  Radio buttons for deactivate_stake and liquidate_terminate modals;
          remove_provisioner fixed to liquidate → terminate → remove_provisioner.
  v0.3.4  remove_provisioner: auto-detect status (active→liq+term, maturing/inactive→deactivate).
          withdraw_rewards: fix hex parsing (regex extract, strip shell prompt),
          remove 1 DUSK buffer, display decoded balance in output.

  v0.3.3  Clean baseline.
          - ANSI stripping fixed (non-raw \x1b regex in _strip_ansi)
          - stdout+stderr always combined in wallet output display
          - correct --wallet-dir / --network flags
          - staking address parsed from stake-info output
          - action routes renamed and reordered
          - standalone /liquidate and /terminate routes removed
"""

import json
import re
import os
import subprocess
import threading
import time
from datetime import datetime
from collections import deque

import logging

from flask import Flask, jsonify, request, Response, stream_with_context
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# ── Logging / output setup ───────────────────────────────────────────────────
# All output goes through _log() which holds a lock so concurrent threads
# (Flask request handlers, poller, rotation) never interleave on a single line.

_log_lock = threading.Lock()

def _log(msg: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    with _log_lock:
        print(f"{ts}  {msg}", flush=True)


class _OptionsFilter(logging.Filter):
    """Drop OPTIONS (CORS preflight) lines — pure noise."""
    def filter(self, record):
        return "OPTIONS" not in record.getMessage()


class _CompactFormatter(logging.Formatter):
    """Strip the redundant [DD/Mon/YYYY HH:MM:SS] date Werkzeug embeds in its messages."""
    import re as _re
    _DATE_PAT = _re.compile(r' - - \[[\d/A-Za-z: ]+\]')
    def format(self, record):
        msg = super().format(record)
        return self._DATE_PAT.sub("", msg)


_wz_logger = logging.getLogger("werkzeug")
_wz_logger.handlers.clear()
_wz_handler = logging.StreamHandler()
_wz_handler.setFormatter(_CompactFormatter(fmt="%(asctime)s  %(message)s", datefmt="%H:%M:%S"))
_wz_handler.addFilter(_OptionsFilter())
_wz_logger.addHandler(_wz_handler)
_wz_logger.propagate = False

# ── Config ────────────────────────────────────────────────────────────────────

WALLET_BIN     = "sozu-beta3-rusk-wallet"
WALLET_PATH    = os.path.expanduser("~/sozu_provisioner")
NETWORK        = "testnet"
GRAPHQL_URL    = "https://testnet.nodes.dusk.network/on/graphql/query"
CONTRACT_ID    = "72883945ac1aa032a88543aacc9e358d1dfef07717094c05296ce675f23078f2"
RUSK_VERSION   = "1.5"
NODE_INDICES       = [0, 1]          # provisioner indices to manage
PORT               = 7373
OPERATOR_WALLET    = os.path.expanduser("~/sozu_operator")
GAS_LIMIT          = 2000000

# ── Persistent configuration ──────────────────────────────────────────────────
# Stored in ~/.sozu_dashboard_config.json; overrides the compile-time defaults.

_CONFIG_PATH          = os.path.expanduser("~/.sozu_dashboard_config.json")
_SK_PATH              = os.path.expanduser("~/.sozu_keys")  # chmod 600, never in main config
_ROTATION_LOG_PATH    = os.path.expanduser("~/.sozu_rotation.log")
_ROTATION_STATE_PATH  = os.path.expanduser("~/.sozu_rotation_enabled")
# ~/.sozu_rotation_enabled contains a single JSON bool — persists enabled/disabled
# across restarts so headless operation survives without the UI being connected.

def _load_rotation_enabled() -> bool:
    """Read persisted rotation enabled state. Defaults to False if file absent."""
    try:
        with open(_ROTATION_STATE_PATH) as f:
            return json.load(f) is True
    except Exception:
        return False

def _save_rotation_enabled(enabled: bool) -> None:
    """Persist rotation enabled state to disk."""
    try:
        with open(_ROTATION_STATE_PATH, "w") as f:
            json.dump(enabled, f)
    except Exception as e:
        _log(f"[rotation] WARNING: could not persist enabled state: {e}")

def _load_sks() -> dict:
    """Load provisioner secret keys from protected file."""
    if os.path.exists(_SK_PATH):
        try:
            with open(_SK_PATH) as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def _save_sks(sks: dict) -> None:
    """Save provisioner secret keys to protected file (mode 600)."""
    with open(_SK_PATH, "w") as f:
        json.dump(sks, f, indent=2)
    os.chmod(_SK_PATH, 0o600)

def _get_sk(idx: int) -> str:
    return _load_sks().get(f"prov_{idx}_sk", "")
_CONFIG_DEFAULTS = {
    "network_id":           2,
    "contract_address":     CONTRACT_ID,
    "operator_address":     "",
    "prov_0_address":       "",          # provisioner 0 staking address (for event highlighting)
    "prov_1_address":       "",          # provisioner 1 staking address (for event highlighting)
    "operator_stake_limit": 3_000_000,   # DUSK, total across all provisioners
    "max_slash_pct":        0.02,        # max combined Reclaimable slashed stake as % of limit
    "rotation_window":      100,         # blocks before epoch end where rotation triggers
    "snatch_window":        50,          # blocks before epoch end for last-minute stake
    "backfill_blocks":      200,         # blocks to scan on poller startup
    "rotation_seed_dusk":   1000,        # DUSK to seed back into freshly-terminated provisioner
}
_cfg: dict = {}

def _load_config() -> dict:
    global _cfg
    stored = {}
    if os.path.exists(_CONFIG_PATH):
        try:
            with open(_CONFIG_PATH) as f:
                stored = json.load(f)
        except Exception:
            stored = {}
    # Merge: stored wins, but empty strings never override a non-empty default
    merged = {}
    for k, default_v in _CONFIG_DEFAULTS.items():
        stored_v = stored.get(k, default_v)
        if isinstance(default_v, str) and default_v and not stored_v:
            merged[k] = default_v  # keep non-empty default over blank stored value
        else:
            merged[k] = stored_v
    # Also keep any extra keys that are in stored but not in defaults
    for k, v in stored.items():
        if k not in merged:
            merged[k] = v
    # Upgrade: if key is new (not in stored at all), use the default
    for k, default_v in _CONFIG_DEFAULTS.items():
        if k not in stored:
            merged[k] = default_v
    # Migrate: old default was 50, new default is 200 — upgrade silently
    if merged.get("backfill_blocks", 200) == 50:
        merged["backfill_blocks"] = 200
    _cfg = merged
    # Always write to disk so file exists with all keys populated
    try:
        with open(_CONFIG_PATH, "w") as f:
            json.dump(_cfg, f, indent=2)
    except Exception as e:
        _log(f"[config] WARNING: could not write config file: {e}")
    return _cfg

def _save_config(data: dict) -> None:
    global _cfg
    _cfg = {**_CONFIG_DEFAULTS, **data}
    with open(_CONFIG_PATH, "w") as f:
        json.dump(_cfg, f, indent=2)

def cfg(key: str):
    """Get a config value, loading from disk if not yet loaded."""
    if not _cfg:
        _load_config()
    return _cfg.get(key, _CONFIG_DEFAULTS.get(key))

_load_config()  # load at import time

# Convenience aliases (keep code below readable)
def CONTRACT_ADDRESS():  return cfg("contract_address") or CONTRACT_ID
def OPERATOR_ADDRESS():  return cfg("operator_address")
def NETWORK_ID():        return cfg("network_id") or 2

# ── Command runner ────────────────────────────────────────────────────────────

def _strip_ansi(s: str) -> str:
    """Remove ANSI/VT100 escape sequences from wallet output."""
    import re as _re
    return _re.sub("\x1b[^a-zA-Z]*[a-zA-Z]|\r", "", s)


def run_cmd(cmd: str, timeout: int = 30) -> dict:
    """Run a shell command, return {ok, stdout, stderr, returncode, duration_ms}."""
    t0 = time.time()
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return {
            "ok":           result.returncode == 0,
            "stdout":       _strip_ansi(result.stdout).strip(),
            "stderr":       _strip_ansi(result.stderr).strip(),
            "returncode":   result.returncode,
            "duration_ms":  int((time.time() - t0) * 1000),
            "cmd":          cmd,
            "ts":           datetime.now().isoformat(),
        }
    except subprocess.TimeoutExpired:
        return {
            "ok": False, "stdout": "", "returncode": -1,
            "stderr": f"timeout after {timeout}s", "duration_ms": timeout * 1000,
            "cmd": cmd, "ts": datetime.now().isoformat(),
        }
    except Exception as exc:
        return {
            "ok": False, "stdout": "", "returncode": -1,
            "stderr": str(exc), "duration_ms": 0,
            "cmd": cmd, "ts": datetime.now().isoformat(),
        }


# Password flag used by the wallet CLI.
# Try "--password" first; if the wallet uses a different flag,
# update this constant (e.g. "-p", "--pwd", "--pass").
WALLET_PASSWORD_FLAG = "--password"


def wallet_cmd(subcmd: str, timeout: int = 30, password: str = "") -> dict:
    """
    Build and run a wallet command.

    Password delivery strategy (in order of preference):
      1. --password flag directly on the CLI  ← most reliable
      2. SSHPASS-style expect wrapper          ← fallback if flag unsupported
    The flag approach is tried first; if the binary rejects it the caller
    will see the error immediately rather than a 20s timeout.
    """
    if password:
        safe_pw   = password.replace("'", "'\''")
        inner     = f"{WALLET_BIN} --wallet-dir {WALLET_PATH} --network {NETWORK} {WALLET_PASSWORD_FLAG} '{safe_pw}' {subcmd}"
        log_cmd   = f"{WALLET_BIN} --wallet-dir {WALLET_PATH} --network {NETWORK} {WALLET_PASSWORD_FLAG} '***' {subcmd}"
    else:
        inner     = f"{WALLET_BIN} --wallet-dir {WALLET_PATH} --network {NETWORK} {subcmd}"
        log_cmd   = inner

    t0 = time.time()
    try:
        result = subprocess.run(
            inner, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return {
            "ok":          result.returncode == 0,
            "stdout":      _strip_ansi(result.stdout).strip(),
            "stderr":      _strip_ansi(result.stderr).strip(),
            "returncode":  result.returncode,
            "duration_ms": int((time.time() - t0) * 1000),
            "cmd":         log_cmd,
            "ts":          datetime.now().isoformat(),
        }
    except subprocess.TimeoutExpired:
        return {
            "ok": False, "stdout": "", "returncode": -1,
            "stderr": (
                f"timeout after {timeout}s — the wallet did not respond.\n"
                f"Tried flag: {WALLET_PASSWORD_FLAG}\n"
                f"If your wallet uses a different flag, update WALLET_PASSWORD_FLAG in provisioner_server.py"
            ),
            "duration_ms": timeout * 1000,
            "cmd": log_cmd, "ts": datetime.now().isoformat(),
        }
    except Exception as exc:
        return {
            "ok": False, "stdout": "", "returncode": -1,
            "stderr": str(exc), "duration_ms": 0,
            "cmd": log_cmd, "ts": datetime.now().isoformat(),
        }


# ── Password helper ──────────────────────────────────────────────────────────

_cached_wallet_pw: str = ""  # updated on every request that carries a password

def get_password() -> str:
    """
    Extract wallet password.
    - Inside a request context: reads from JSON body or header and caches it.
    - Outside a request context (background threads): returns cached value.
    """
    global _cached_wallet_pw
    try:
        from flask import has_request_context
        if has_request_context():
            data = request.get_json(silent=True) or {}
            pw = data.get("password", "") or request.headers.get("X-Wallet-Password", "")
            if pw:
                _cached_wallet_pw = pw
            return _cached_wallet_pw
    except Exception:
        pass
    return _cached_wallet_pw


# ── Routes: system ────────────────────────────────────────────────────────────

@app.route("/api/ping")
def ping():
    return jsonify({"ok": True, "ts": datetime.now().isoformat()})


@app.route("/api/status")
def status():
    """Quick health: wallet binary present, wallet dir exists."""
    binary_ok = run_cmd(f"which {WALLET_BIN}")["ok"]
    wallet_ok  = os.path.isdir(WALLET_PATH)
    return jsonify({
        "binary_found":  binary_ok,
        "wallet_dir":    WALLET_PATH,
        "wallet_dir_ok": wallet_ok,
        "network":       NETWORK,
        "nodes":         NODE_INDICES,
        "ts":            datetime.now().isoformat(),
    })


# ── Debug endpoint ───────────────────────────────────────────────────────────

@app.route("/api/debug/wallet", methods=["POST"])
def debug_wallet():
    """
    Test wallet command execution.
    Body: { "password": "...", "subcmd": "profiles", "timeout": 20 }
    Also accepts subcmd="help" to get wallet --help output without a password.
    """
    data    = request.get_json() or {}
    pw      = data.get("password", "")
    subcmd  = data.get("subcmd", "profiles")
    timeout = data.get("timeout", 20)

    if subcmd == "help":
        result = run_cmd(f"{WALLET_BIN} --help", timeout=10)
    elif subcmd == "help_network":
        result = run_cmd(f"{WALLET_BIN} --wallet-dir {WALLET_PATH} --network {NETWORK} --help", timeout=10)
    else:
        result = wallet_cmd(subcmd, timeout=timeout, password=pw)

    result["password_flag_used"] = WALLET_PASSWORD_FLAG
    return jsonify(result)


# ── Routes: stake info ────────────────────────────────────────────────────────

@app.route("/api/stake_info/<int:idx>", methods=["GET","POST"])
def stake_info(idx: int):
    """Get stake info for a provisioner index."""
    result = wallet_cmd(f"stake-info --profile-idx {idx}", timeout=20, password=get_password())
    return jsonify(result)


@app.route("/api/stake_info_all", methods=["GET","POST"])
def stake_info_all():
    """Get stake info for all configured node indices."""
    pw = get_password()
    results = {}
    for idx in NODE_INDICES:
        results[str(idx)] = wallet_cmd(f"stake-info --profile-idx {idx}", timeout=20, password=pw)
    return jsonify(results)


# ── Routes: balance ───────────────────────────────────────────────────────────

@app.route("/api/balance", methods=["GET","POST"])
def balance():
    """Get wallet balance (all profiles)."""
    result = wallet_cmd("balance", timeout=20, password=get_password())
    return jsonify(result)


@app.route("/api/balance/<int:idx>", methods=["GET","POST"])
def balance_idx(idx: int):
    """Get wallet balance for a specific profile index."""
    result = wallet_cmd(f"balance --profile-idx {idx}", timeout=20, password=get_password())
    return jsonify(result)


# ── Routes: profiles ──────────────────────────────────────────────────────────

@app.route("/api/profiles", methods=["GET","POST"])
def profiles():
    """List wallet profiles."""
    result = wallet_cmd("profiles", timeout=15, password=get_password())
    return jsonify(result)


# ── Routes: provisioner actions ───────────────────────────────────────────────

@app.route("/api/stake", methods=["POST"])
def stake():
    """
    Stake DUSK to a provisioner.
    Body: { "idx": 0, "amount": "1000000000" }
    """
    data = request.get_json() or {}
    idx    = data.get("idx")
    amount = data.get("amount")
    if idx is None or amount is None:
        return jsonify({"ok": False, "stderr": "missing idx or amount"}), 400
    result = wallet_cmd(f"stake --profile-idx {idx} --amt {amount}", timeout=60, password=data.get("password",""))
    return jsonify(result)


@app.route("/api/unstake", methods=["POST"])
def unstake():
    """
    Unstake from a provisioner.
    Body: { "idx": 0 }
    """
    data = request.get_json() or {}
    idx = data.get("idx")
    if idx is None:
        return jsonify({"ok": False, "stderr": "missing idx"}), 400
    result = wallet_cmd(f"unstake --profile-idx {idx}", timeout=60, password=data.get("password",""))
    return jsonify(result)


@app.route("/api/withdraw_reward", methods=["POST"])
def withdraw_reward():
    """
    Withdraw staking reward.
    Body: { "idx": 0 }
    """
    data = request.get_json() or {}
    idx = data.get("idx")
    if idx is None:
        return jsonify({"ok": False, "stderr": "missing idx"}), 400
    result = wallet_cmd(f"withdraw-reward --profile-idx {idx}", timeout=60, password=data.get("password",""))
    return jsonify(result)


# ── Routes: SOZU pool ─────────────────────────────────────────────────────────

@app.route("/api/sozu/balance_of", methods=["POST"])
def sozu_balance_of():
    """
    Query SOZU pool token balance for an account.
    Body: { "account": "<base58>" }
    Uses the 3-step encode → call → decode pattern.
    """
    import urllib.request as ur
    data = request.get_json() or {}
    account = data.get("account", "")
    if not account:
        return jsonify({"ok": False, "stderr": "missing account"}), 400

    DRIVER   = f"https://testnet.nodes.dusk.network/on/driver:{CONTRACT_ID}"
    CONTRACTS = f"https://testnet.nodes.dusk.network/on/contracts:{CONTRACT_ID}"
    HEADERS  = {"rusk-version": RUSK_VERSION}

    def curl(url, body, content_type="application/x-www-form-urlencoded"):
        import subprocess as sp
        r = sp.run(
            ["curl", "-s", "-X", "POST", url,
             "-H", f"rusk-version: {RUSK_VERSION}",
             "-H", f"Content-Type: {content_type}",
             "-d", body],
            capture_output=True, text=True, timeout=15
        )
        return r.stdout.strip()

    try:
        # 1. encode
        encoded = curl(f"{DRIVER}/encode_input_fn:balance_of",
                       json.dumps(account), "application/json")
        if not encoded or "error" in encoded.lower():
            return jsonify({"ok": False, "stderr": f"encode failed: {encoded}"})

        # 2. call
        body_hex = encoded if encoded.startswith("0x") else f"0x{encoded}"
        raw = curl(f"{CONTRACTS}/balance_of", body_hex)

        # 3. decode
        raw_hex = raw if raw.startswith("0x") else f"0x{raw}"
        decoded = curl(f"{DRIVER}/decode_output_fn:balance_of", raw_hex)

        lux = int(json.loads(decoded))
        dusk = lux / 1_000_000_000
        return jsonify({"ok": True, "lux": lux, "dusk": dusk,
                        "raw_encoded": encoded, "raw_response": raw})
    except Exception as exc:
        return jsonify({"ok": False, "stderr": str(exc)})


@app.route("/api/sozu/contract_balance", methods=["GET","POST"])
def sozu_contract_balance():
    """Query SOZU pool LUX balance from transfer contract."""
    import subprocess as sp
    url = "https://testnet.nodes.dusk.network/on/contracts:0100000000000000000000000000000000000000000000000000000000000000/contract_balance"
    r = sp.run(
        ["curl", "-s", "-X", "POST", url,
         "-H", f"rusk-version: {RUSK_VERSION}",
         "-H", "Content-Type: application/json",
         "-d", json.dumps(CONTRACT_ID)],
        capture_output=True, text=True, timeout=15
    )
    raw = r.stdout.strip()
    try:
        lux = int(json.loads(raw))
        return jsonify({"ok": True, "lux": lux, "dusk": lux / 1_000_000_000, "raw": raw})
    except Exception:
        # try little-endian hex
        try:
            hex_clean = raw.replace("0x", "")
            if len(hex_clean) == 16:
                lux = int(bytes.fromhex(hex_clean)[::-1].hex(), 16)
                return jsonify({"ok": True, "lux": lux, "dusk": lux / 1_000_000_000, "raw": raw})
        except Exception:
            pass
    return jsonify({"ok": False, "raw": raw, "stderr": "could not decode response"})


@app.route("/api/sozu/exchange_rate", methods=["GET","POST"])
def sozu_exchange_rate():
    """Query SOZU pool exchange rate."""
    import subprocess as sp
    DRIVER = f"https://testnet.nodes.dusk.network/on/driver:{CONTRACT_ID}"
    CONTRACTS_URL = f"https://testnet.nodes.dusk.network/on/contracts:{CONTRACT_ID}"

    def curl(url, body, ct="application/x-www-form-urlencoded"):
        r = sp.run(["curl", "-s", "-X", "POST", url,
                    "-H", f"rusk-version: {RUSK_VERSION}",
                    "-H", f"Content-Type: {ct}",
                    "-d", body],
                   capture_output=True, text=True, timeout=15)
        return r.stdout.strip()

    try:
        encoded = curl(f"{DRIVER}/encode_input_fn:exchange_rate", "null", "application/json")
        body_hex = encoded if encoded.startswith("0x") else f"0x{encoded}"
        raw = curl(f"{CONTRACTS_URL}/exchange_rate", body_hex)
        raw_hex = raw if raw.startswith("0x") else f"0x{raw}"
        decoded = curl(f"{DRIVER}/decode_output_fn:exchange_rate", raw_hex)
        rate = json.loads(decoded)
        num = int(rate["numerator"])
        den = int(rate["denominator"])
        ratio = num / den if den else 0
        return jsonify({"ok": True, "numerator": num, "denominator": den,
                        "rate": round(ratio, 8),
                        "meaning": f"1 SOZU token = {ratio:.6f} DUSK"})
    except Exception as exc:
        return jsonify({"ok": False, "stderr": str(exc)})


@app.route("/api/sozu/recycle", methods=["POST"])
def sozu_recycle():
    """Trigger SOZU pool recycle via operator wallet contract-call.
    Body: { "password": "..." }
    """
    data = request.get_json() or {}
    pw   = data.get("password", "")
    r = operator_cmd(
        f"contract-call --contract-id {CONTRACT_ADDRESS()} --fn-name recycle --fn-args ''",
        timeout=60, password=pw)
    return jsonify({"ok": r["ok"], "stdout": r.get("stdout",""), "stderr": r.get("stderr",""),
                    "duration_ms": r.get("duration_ms", 0)})


# ── Routes: network info ──────────────────────────────────────────────────────

@app.route("/api/network/tip", methods=["GET","POST"])
def network_tip():
    """Get current block height from Dusk network."""
    import urllib.request as ur, json as j
    query = '{ block(height: -1) { header { height } } }'
    req = ur.Request(GRAPHQL_URL, data=query.encode(),
                     headers={"rusk-version": RUSK_VERSION,
                              "Content-Type": "application/graphql"},
                     method="POST")
    try:
        with ur.urlopen(req, timeout=8) as resp:
            payload = j.loads(resp.read())
        block = payload.get("block") or payload.get("data", {}).get("block", {})
        height = int(block["header"]["height"])
        return jsonify({"ok": True, "height": height})
    except Exception as exc:
        return jsonify({"ok": False, "stderr": str(exc)})



# ── Helper: operator wallet command ──────────────────────────────────────────

def operator_cmd(subcmd: str, timeout: int = 30, password: str = "") -> dict:
    """Run a command using the OPERATOR wallet (~/sozu_operator).
    Delegates to run_cmd so ANSI stripping and error handling are consistent.
    """
    if password:
        safe_pw = password.replace("'", "'\''")
        cmd     = f"{WALLET_BIN} --wallet-dir {OPERATOR_WALLET} --network {NETWORK} --password '{safe_pw}' {subcmd}"
        log_cmd = f"{WALLET_BIN} --wallet-dir {OPERATOR_WALLET} --network {NETWORK} --password '***' {subcmd}"
    else:
        cmd     = f"{WALLET_BIN} --wallet-dir {OPERATOR_WALLET} --network {NETWORK} {subcmd}"
        log_cmd = cmd
    result = run_cmd(cmd, timeout=timeout)
    result["cmd"] = log_cmd  # replace with password-masked version
    # Mirror to command output panel when called from rotation thread
    import threading as _thr
    if _thr.current_thread().name == "rotation":
        _push_cmd_output(subcmd.split()[0], result)
    return result

def extract_payload(output: str) -> str:
    """
    Extract bare hex payload from wallet calculate-payload output.
    Handles: bare hex, "hex", Payload label: "hex"
    Returns longest hex token (40+ chars). Falls back to last non-empty
    line stripped of label prefix and surrounding quotes.
    """
    candidates = re.findall(r"[0-9a-fA-F]{40,}", output)
    if candidates:
        return max(candidates, key=len)
    for line in reversed(output.strip().splitlines()):
        line = line.strip()
        if not line:
            continue
        if ":" in line:
            line = line.split(":", 1)[1].strip()
        line = line.strip('"').strip("'")
        if line:
            return line
    return output.strip()


# ── Routes: provisioner management ───────────────────────────────────────────

@app.route("/api/provisioner/add_provisioner", methods=["POST"])
def provisioner_add_provisioner():
    """
    Add a provisioner to the SOZU pool.
    Body: { "password": "...", "operator_address": "...", "provisioner_address": "..." }
    """
    data = request.get_json() or {}
    pw   = data.get("password", "")
    op   = data.get("operator_address", OPERATOR_ADDRESS())
    prov = data.get("provisioner_address", "")
    if not op or not prov:
        return jsonify({"ok": False, "stderr": "operator_address and provisioner_address required"}), 400

    # Step 1: calculate payload
    r1 = operator_cmd(
        f"calculate-payload-add-provisioner --operator {op} --provisioner {prov}",
        timeout=30, password=pw)
    if not r1["ok"]:
        return jsonify({"ok": False, "step": "calculate_payload", **r1})

    payload = extract_payload(r1["stdout"])

    # Step 2: contract call
    r2 = operator_cmd(
        f"contract-call --contract-id {CONTRACT_ADDRESS()} --fn-name add_provisioner --fn-args '{payload}' --gas-limit {GAS_LIMIT}",
        timeout=60, password=pw)
    return jsonify({"ok": r2["ok"], "step": "contract_call", "payload": payload, **r2})



@app.route("/api/provisioner/addresses", methods=["GET","POST"])
def provisioner_addresses():
    """Return provisioner addresses for event highlighting.
    Merges: config-stored addresses (always available) + live stake-info addresses.
    Config addresses persist even after deactivation/termination.
    """
    pw = (request.get_json(silent=True) or {}).get("password", get_password())
    addrs = {}
    for idx in NODE_INDICES:
        # Config address takes priority — always present even after stake removal
        cfg_addr = cfg(f"prov_{idx}_address") or ""
        live_addr = _prov_addr(idx) if pw else ""
        addrs[str(idx)] = live_addr or cfg_addr  # live wins if available, else config
        # Auto-save live address to config so it survives deactivation
        if live_addr and not cfg_addr:
            try:
                current = _load_config()
                current[f"prov_{idx}_address"] = live_addr
                _save_config(current)
            except Exception:
                pass
    return jsonify({
        "ok": True,
        "addresses": addrs,
        "operator": OPERATOR_ADDRESS(),
    })

@app.route("/api/provisioner/list", methods=["GET","POST"])
def provisioner_list():
    """List provisioners from the provisioner wallet profiles."""
    pw = (request.get_json(silent=True) or {}).get("password", request.args.get("password",""))
    result = wallet_cmd("profiles", timeout=15, password=pw)
    return jsonify(result)


@app.route("/api/provisioner/allocate_stake", methods=["POST"])
def provisioner_allocate_stake():
    """
    Allocate stake to a provisioner (stake_activate).
    Body: { "password": "...", "provisioner_sk": "...", "amount_dusk": 1000 }
      OR  { "password": "...", "provisioner_idx": 0,   "amount_dusk": 1000 }
    provisioner_idx looks up the stored SK from ~/.sozu_keys automatically.
    """
    data   = request.get_json() or {}
    pw     = data.get("password", "")
    amount = data.get("amount_dusk", 0)
    # Resolve SK: prefer explicit provisioner_sk, fall back to idx lookup
    sk = data.get("provisioner_sk", "")
    if not sk and "provisioner_idx" in data:
        idx = int(data["provisioner_idx"])
        sk  = _get_sk(idx)
        if not sk:
            return jsonify({"ok": False,
                            "stderr": f"No secret key stored for provisioner {idx}. "
                                      f"Set it in the config modal."}), 400
    if not sk or not amount:
        return jsonify({"ok": False, "stderr": "provisioner_sk (or provisioner_idx) and amount_dusk required"}), 400

    amount_lux = int(float(amount) * 1_000_000_000)

    # Step 1: calculate payload
    r1 = operator_cmd(
        f"calculate-payload-stake-activate --provisioner-sk {sk} --amount {amount_lux} --network-id {NETWORK_ID()}",
        timeout=30, password=pw)
    if not r1["ok"]:
        return jsonify({"ok": False, "step": "calculate_payload", **r1})

    payload = extract_payload(r1["stdout"])

    # Step 2: contract call
    r2 = operator_cmd(
        f"contract-call --contract-id {CONTRACT_ADDRESS()} --fn-name stake_activate --fn-args '{payload}' --gas-limit {GAS_LIMIT}",
        timeout=60, password=pw)
    return jsonify({"ok": r2["ok"], "step": "contract_call", "payload": payload,
                    "amount_lux": amount_lux, **r2})


@app.route("/api/provisioner/deactivate_stake", methods=["POST"])
def provisioner_deactivate_stake():
    """
    Remove stake from a provisioner (stake_deactivate).
    Body: { "password": "...", "provisioner_address": "..." }
    """
    data = request.get_json() or {}
    pw   = data.get("password", "")
    prov = data.get("provisioner_address", "")
    if not prov:
        return jsonify({"ok": False, "stderr": "provisioner_address required"}), 400

    r1 = operator_cmd(
        f"calculate-payload-stake-deactivate --provisioner {prov}",
        timeout=30, password=pw)
    if not r1["ok"]:
        return jsonify({"ok": False, "step": "calculate_payload", **r1})

    payload = extract_payload(r1["stdout"])

    r2 = operator_cmd(
        f"contract-call --contract-id {CONTRACT_ADDRESS()} --fn-name stake_deactivate --fn-args '{payload}' --gas-limit {GAS_LIMIT}",
        timeout=60, password=pw)
    return jsonify({"ok": r2["ok"], "step": "contract_call", "payload": payload, **r2})


@app.route("/api/provisioner/liquidate_terminate", methods=["POST"])
def provisioner_liquidate_terminate():
    """
    Liquidate then terminate in one call.
    Body: { "password": "...", "provisioner_address": "..." }
    """
    data = request.get_json() or {}
    pw   = data.get("password", "")
    prov = data.get("provisioner_address", "")
    if not prov:
        return jsonify({"ok": False, "stderr": "provisioner_address required"}), 400

    results = {}

    # LIQUIDATE
    r1 = operator_cmd(f"calculate-payload-liquidate --provisioner {prov}", timeout=30, password=pw)
    results["liquidate_payload"] = r1
    if not r1["ok"]:
        return jsonify({"ok": False, "step": "liquidate_calculate_payload", "results": results})

    payload_liq = extract_payload(r1["stdout"])
    r2 = operator_cmd(
        f"contract-call --contract-id {CONTRACT_ADDRESS()} --fn-name liquidate --fn-args '{payload_liq}' --gas-limit {GAS_LIMIT}",
        timeout=60, password=pw)
    results["liquidate_call"] = r2
    if not r2["ok"]:
        return jsonify({"ok": False, "step": "liquidate_call", "results": results})

    # TERMINATE
    r3 = operator_cmd(f"calculate-payload-terminate --provisioner {prov}", timeout=30, password=pw)
    results["terminate_payload"] = r3
    if not r3["ok"]:
        return jsonify({"ok": False, "step": "terminate_calculate_payload", "results": results})

    payload_term = extract_payload(r3["stdout"])
    r4 = operator_cmd(
        f"contract-call --contract-id {CONTRACT_ADDRESS()} --fn-name terminate --fn-args '{payload_term}' --gas-limit {GAS_LIMIT}",
        timeout=60, password=pw)
    results["terminate_call"] = r4

    return jsonify({"ok": r4["ok"], "step": "complete", "results": results})


@app.route("/api/provisioner/remove_provisioner", methods=["POST"])
def provisioner_remove_provisioner():
    """
    Full provisioner removal with auto-detected pre-steps:
      active               → liquidate + terminate → remove_provisioner
      maturing/inactive    → deactivate (if has stake) → remove_provisioner
      inactive (no stake)  → remove_provisioner directly
    Body: { "password": "...", "provisioner_address": "...", "operator_address": "...",
            "provisioner_idx": 0 }
    provisioner_idx is used to look up stake status automatically.
    """
    data = request.get_json() or {}
    pw   = data.get("password", "")
    prov = data.get("provisioner_address", "")
    op   = data.get("operator_address", OPERATOR_ADDRESS())
    idx  = data.get("provisioner_idx")
    if not prov or not op:
        return jsonify({"ok": False, "stderr": "provisioner_address and operator_address required"}), 400

    results = {}

    # Auto-detect stake status using stake-info (requires idx)
    status    = None
    has_stake = False
    if idx is not None:
        r_info = wallet_cmd(f"stake-info --profile-idx {idx}", timeout=20, password=pw)
        info   = parse_stake_info(r_info.get("stdout","") + r_info.get("stderr",""))
        status    = info.get("status", "inactive")
        has_stake = info.get("has_stake", False)
        results["stake_info"] = {"status": status, "has_stake": has_stake}

    # Step 1a: active → liquidate + terminate
    if status == "active":
        r1 = operator_cmd(f"calculate-payload-liquidate --provisioner {prov}", timeout=30, password=pw)
        results["liquidate_payload"] = r1
        if not r1["ok"]:
            return jsonify({"ok": False, "step": "liquidate_calculate_payload", "results": results})
        payload_liq = extract_payload(r1["stdout"])
        r2 = operator_cmd(
            f"contract-call --contract-id {CONTRACT_ADDRESS()} --fn-name liquidate"
            f" --fn-args '{payload_liq}' --gas-limit {GAS_LIMIT}",
            timeout=60, password=pw)
        results["liquidate_call"] = r2
        if not r2["ok"]:
            return jsonify({"ok": False, "step": "liquidate_call", "results": results})
        time.sleep(8)
        r3 = operator_cmd(f"calculate-payload-terminate --provisioner {prov}", timeout=30, password=pw)
        results["terminate_payload"] = r3
        if not r3["ok"]:
            return jsonify({"ok": False, "step": "terminate_calculate_payload", "results": results})
        payload_term = extract_payload(r3["stdout"])
        r4 = operator_cmd(
            f"contract-call --contract-id {CONTRACT_ADDRESS()} --fn-name terminate"
            f" --fn-args '{payload_term}' --gas-limit {GAS_LIMIT}",
            timeout=60, password=pw)
        results["terminate_call"] = r4
        if not r4["ok"]:
            return jsonify({"ok": False, "step": "terminate_call", "results": results})
        time.sleep(8)

    # Step 1b: maturing or inactive with stake → deactivate
    elif has_stake and status in ("maturing", "inactive"):
        r1 = operator_cmd(f"calculate-payload-stake-deactivate --provisioner {prov}", timeout=30, password=pw)
        results["deactivate_payload"] = r1
        if not r1["ok"]:
            return jsonify({"ok": False, "step": "deactivate_calculate_payload", "results": results})
        payload_deact = extract_payload(r1["stdout"])
        r2 = operator_cmd(
            f"contract-call --contract-id {CONTRACT_ADDRESS()} --fn-name stake_deactivate"
            f" --fn-args '{payload_deact}' --gas-limit {GAS_LIMIT}",
            timeout=60, password=pw)
        results["deactivate_call"] = r2
        if not r2["ok"]:
            return jsonify({"ok": False, "step": "deactivate_call", "results": results})
        time.sleep(8)

    # Step 2: remove_provisioner
    r5 = operator_cmd(
        f"calculate-payload-remove-provisioner --operator {op} --provisioner {prov}",
        timeout=30, password=pw)
    results["remove_payload"] = r5
    if not r5["ok"]:
        return jsonify({"ok": False, "step": "remove_calculate_payload", "results": results})
    payload_rm = extract_payload(r5["stdout"])
    r6 = operator_cmd(
        f"contract-call --contract-id {CONTRACT_ADDRESS()} --fn-name remove_provisioner"
        f" --fn-args '{payload_rm}' --gas-limit {GAS_LIMIT}",
        timeout=60, password=pw)
    results["remove_call"] = r6

    return jsonify({"ok": r6["ok"], "step": "complete",
                    "pre_step": status or "unknown", "results": results})


@app.route("/api/provisioner/check_stake")
def provisioner_check_stake():
    """Check available LUX/DUSK stake in the SOZU pool (transfer contract balance)."""
    return sozu_contract_balance()


@app.route("/api/provisioner/withdraw_rewards", methods=["POST"])
def provisioner_withdraw_rewards():
    """
    Withdraw operator rewards from the SOZU pool.
    Body: { "password": "...", "operator_address": "..." }
    Steps: balance_of payload → query balance → calculate unstake payload → sozu_unstake
    """
    import struct
    data = request.get_json() or {}
    pw   = data.get("password", "")
    op   = data.get("operator_address", OPERATOR_ADDRESS())
    if not op:
        return jsonify({"ok": False, "stderr": "operator_address required"}), 400

    # Step 1: calculate balance_of payload
    r1 = operator_cmd(f"calculate-payload-balance-of --public-key {op}", timeout=30, password=pw)
    if not r1["ok"]:
        return jsonify({"ok": False, "step": "calculate_balance_payload", **r1})

    payload = extract_payload(r1["stdout"])

    # Step 2: query balance via contract
    import subprocess as sp
    url = f"https://testnet.nodes.dusk.network/on/contracts:{CONTRACT_ADDRESS()}/balance_of"
    r_curl = sp.run(
        ["curl", "-s", "-X", "POST", url,
         "-H", f"rusk-version: {RUSK_VERSION}",
         "-d", f"0x{payload}"],
        capture_output=True, text=True, timeout=15)

    # Extract exactly 16 hex chars (uint64) — strip shell prompt that may appear on same line
    import re as _re
    hex_match = _re.search(r'[0-9a-fA-F]{16}', r_curl.stdout)
    raw_balance = hex_match.group(0) if hex_match else r_curl.stdout.strip()

    # Step 3: decode little-endian hex to decimal
    try:
        hex_clean = raw_balance.replace("0x", "")[:16]
        lux = struct.unpack("<Q", bytes.fromhex(hex_clean.ljust(16,"0")))[0]
    except Exception as e:
        return jsonify({"ok": False, "step": "decode_balance",
                        "stderr": f"Could not decode balance hex '{raw_balance}': {e}"})

    dusk_full     = lux / 1_000_000_000
    # Withdraw floor(dusk) — no buffer, ignore fractional DUSK
    withdraw_dusk = int(dusk_full)

    if withdraw_dusk == 0:
        return jsonify({"ok": True, "step": "nothing_to_withdraw",
                        "lux": lux, "dusk": round(dusk_full, 9),
                        "stdout": f"Balance is {dusk_full:.6f} DUSK — nothing to withdraw (need ≥1 DUSK)"})

    # Step 4: calculate sozu_unstake payload
    r3 = operator_cmd(
        f"calculate-payload-sozu-unstake --unstake-amount {withdraw_dusk}",
        timeout=30, password=pw)
    if not r3["ok"]:
        return jsonify({"ok": False, "step": "calculate_unstake_payload", **r3})

    unstake_payload = extract_payload(r3["stdout"])

    # Step 5: execute sozu_unstake
    r4 = operator_cmd(
        f"contract-call --contract-id {CONTRACT_ADDRESS()} --fn-name sozu_unstake --fn-args '{unstake_payload}' --gas-limit {GAS_LIMIT}",
        timeout=60, password=pw)

    stdout_msg = (
        f"Balance: {dusk_full:.6f} DUSK (raw: {raw_balance})\n"
        f"Withdrawing: {withdraw_dusk} DUSK\n"
        + (r4.get("stdout","") or r4.get("stderr",""))
    )
    return jsonify({
        "ok":             r4["ok"],
        "step":           "sozu_unstake",
        "balance_lux":    lux,
        "balance_dusk":   round(dusk_full, 9),
        "withdrawn_dusk": withdraw_dusk,
        "stdout":         stdout_msg.strip(),
        "stderr":         r4.get("stderr", ""),
        "duration_ms":    r4.get("duration_ms", 0),
    })



# ── Live provisioner status ───────────────────────────────────────────────────

EPOCH_BLOCKS = 2160


def parse_stake_info(output: str, current_tip: int = 0) -> dict:
    """
    Parse stake-info wallet output into structured data.

    Status logic (matches provisioner_manager):
      - no stake                         → inactive (0 trans)
      - tip < active_block               → maturing (N trans)
      - tip >= active_block              → active (N trans)
      - active_block unknown, trans < 2  → maturing
      - active_block unknown, trans >= 2 → active
    """
    import re as _re
    result = {
        "has_stake":       False,
        "amount_dusk":     0.0,
        "slashed_dusk":    0.0,
        "transitions":     None,
        "active_block":    None,
        "active_epoch":    None,
        "status":          "inactive",
        "status_label":    "inactive (0 trans)",
        "staking_address": "",
        "raw":             output,
    }
    if not output:
        return result
    # Strip ANSI/VT100 escape sequences (e.g. \x1b[?25h cursor-show, colour codes)
    output = _re.sub(r'\x1b\[[\d;?]*[A-Za-z]', '', output)
    output = _re.sub(r'\x1b[()][A-Z0-9]', '', output)  # charset escapes
    if "A stake does not exist" in output:
        return result

    m_addr = _re.search(r"Staking address:\s*([A-Za-z0-9]{40,})", output)
    if m_addr:
        result["staking_address"] = m_addr.group(1).strip()

    m = _re.search(r"Eligible stake:\s*([\d,]+(?:\.\d+)?)\s*DUSK", output)
    if m:
        result["has_stake"]   = True
        result["amount_dusk"] = float(m.group(1).replace(",", ""))

    if not result["has_stake"]:
        return result

    m2 = _re.search(r"Reclaimable slashed stake:\s*([\d,]+(?:\.\d+)?)\s*DUSK", output)
    if m2:
        result["slashed_dusk"] = float(m2.group(1).replace(",", ""))

    # "Stake active from block #2676240 (Epoch 1239)"
    m_block = _re.search(r"Stake active from block\s*#?(\d+).*?Epoch\s+(\d+)", output, _re.IGNORECASE)
    if m_block:
        result["active_block"] = int(m_block.group(1))
        result["active_epoch"] = int(m_block.group(2))

    # Derive transitions from active_block/epoch if available
    if result["active_epoch"] is not None and current_tip > 0:
        stake_epoch   = result["active_epoch"] - 2
        current_epoch = current_tip // EPOCH_BLOCKS
        result["transitions"] = max(0, current_epoch - stake_epoch)
    else:
        m3 = _re.search(r"(?:epoch\s+transitions?|counter)[\s:]+(\d+)", output, _re.IGNORECASE)
        if m3:
            result["transitions"] = int(m3.group(1))

    t = result["transitions"]  # may be None

    # Status rules (exact match to provisioner_manager):
    #   0 trans (or unknown) → inactive
    #   1 trans              → maturing
    #   2+ trans             → active
    # Primary: use active_block vs tip for accuracy
    # Fallback: transitions counter
    if result["active_block"] is not None and current_tip > 0:
        if current_tip >= result["active_block"]:
            result["status"] = "active"
        else:
            # How many transitions has this stake seen?
            # active_block is start of active_epoch; each epoch = EPOCH_BLOCKS
            stake_epoch   = result["active_epoch"] - 2
            current_epoch = current_tip // EPOCH_BLOCKS
            seen = max(0, current_epoch - stake_epoch)
            if seen == 0:
                result["status"] = "inactive"
            else:
                result["status"] = "maturing"
            result["transitions"] = seen
    elif t is not None:
        if t == 0:
            result["status"] = "inactive"
        elif t == 1:
            result["status"] = "maturing"
        else:
            result["status"] = "active"
    else:
        result["status"] = "inactive"

    t = result["transitions"]  # refresh after possible update
    s = result["status"]
    if s == "active":
        result["status_label"] = f"active ({t if t is not None else 2}+ trans)"
    elif s == "maturing":
        result["status_label"] = f"maturing ({t if t is not None else 1} trans)"
    else:
        result["status_label"] = f"inactive ({t if t is not None else 0} trans)"

    return result


@app.route("/api/provisioner/live", methods=["GET", "POST"])
def provisioner_live():
    """
    Return live status for all node indices: stake info + epoch countdown.
    Password accepted via POST JSON body {"password": "..."} — never in URL params.
    GET without password returns epoch/tip data only (no wallet queries).
    """
    import urllib.request as _ur, json as _j

    # Get current block height
    tip = None
    try:
        q = '{ block(height: -1) { header { height } } }'
        req = _ur.Request(GRAPHQL_URL, data=q.encode(),
                          headers={"rusk-version": RUSK_VERSION,
                                   "Content-Type": "application/graphql"},
                          method="POST")
        with _ur.urlopen(req, timeout=6) as r:
            p = _j.loads(r.read())
        b = p.get("block") or p.get("data", {}).get("block", {})
        tip = int(b["header"]["height"])
    except Exception as e:
        tip = None

    epoch = (tip // EPOCH_BLOCKS) if tip else None
    blocks_in_epoch = (tip % EPOCH_BLOCKS) if tip else None
    blocks_until_transition = (EPOCH_BLOCKS - blocks_in_epoch) if blocks_in_epoch is not None else None

    # Password ONLY from POST JSON body — never from query string
    data = request.get_json(silent=True) or {}
    pw   = data.get("password", "")

    nodes = {}
    for idx in NODE_INDICES:
        r    = wallet_cmd(f"stake-info --profile-idx {idx}", timeout=20, password=pw)
        info = parse_stake_info(r.get("stdout", "") + r.get("stderr", ""), current_tip=tip or 0)
        with _stake_cache_lock:
            authoritative = (info["has_stake"]
                             or "A stake does not exist" in (r.get("stdout","") + r.get("stderr","")))
            if authoritative:
                _stake_cache[idx] = {**info, "ok": r["ok"], "cached": False}
            elif idx in _stake_cache:
                info = dict(_stake_cache[idx])
                info["cached"] = True
        nodes[str(idx)] = {**info, "ok": r["ok"]}

    return jsonify({
        "tip":                     tip,
        "epoch":                   epoch,
        "blocks_in_epoch":         blocks_in_epoch,
        "blocks_until_transition": blocks_until_transition,
        "epoch_blocks":            EPOCH_BLOCKS,
        "nodes":                   nodes,
    })



# ── Rotation Manager ─────────────────────────────────────────────────────────
#
# While enabled, a background thread assesses provisioner state every 15s and
# dispatches to one of two functions:
#
#   stake_rotation()         — Regular operation: A:1 & M:1
#   recover_stake_rotation() — Irregular operation: anything else
#
# Both functions are stubs — implement each independently once logic is agreed.

_rotation_state: dict = {
    "enabled":       _load_rotation_enabled(),  # restored from disk on startup
    "state":         "idle",   # idle | assessing | rotating | recovering | error
    "step":          "",
    "last_error":    None,
    "epoch_rotated": None,     # epoch number when rotation was last completed
    "last_epoch":    None,      # epoch seen on previous tick — cache cleared on change
    "warmup":        True,      # first tick after enable: assess-only, no actions
    "irregular_streak": 0,    # consecutive ticks seeing irregular state
    "log":           deque(maxlen=200),
}
# Log startup state so it's visible in the rotation log
if _rotation_state["enabled"]:
    print("[rotation] auto-rotation ENABLED (restored from disk — headless mode active)")
else:
    print("[rotation] auto-rotation disabled (persisted state)")

# Background command results — polled by dashboard to show in Command Output panel
_cmd_log: deque = deque(maxlen=50)
_cmd_log_lock   = threading.Lock()


def _push_cmd_output(name: str, result: dict):
    """Store a background command result for dashboard display + write to log file."""
    entry = {
        "ts":          datetime.now().strftime("%H:%M:%S"),
        "name":        f"[auto] {name}",
        "ok":          result.get("ok", False),
        "stdout":      result.get("stdout", ""),
        "stderr":      result.get("stderr", ""),
        "duration_ms": result.get("duration_ms", 0),
    }
    with _cmd_log_lock:
        _cmd_log.append(entry)
    try:
        with open(_ROTATION_LOG_PATH, "a") as _f:
            status = "OK " if entry["ok"] else "ERR"
            _f.write(f"{entry['ts']}  {status}  {name}\n")
            if entry["stdout"]:
                for line in entry["stdout"].splitlines():
                    _f.write(f"  out: {line}\n")
            if entry["stderr"]:
                for line in entry["stderr"].splitlines():
                    _f.write(f"  err: {line}\n")
    except Exception:
        pass


def _rlog(msg: str, level: str = "info"):
    entry = {"ts": datetime.now().strftime("%H:%M:%S"), "msg": msg, "level": level}
    _rotation_state["log"].appendleft(entry)
    _log(f"[rotation] {level.upper():<5}  {msg}")
    try:
        with open(_ROTATION_LOG_PATH, "a") as _f:
            _f.write(f"{entry['ts']}  {level.upper():<5}  {msg}\n")
    except Exception:
        pass


def _rset(state: str, step: str = ""):
    _rotation_state["state"] = state
    _rotation_state["step"]  = step


# ── State assessment ──────────────────────────────────────────────────────────

def _assess_state(tip: int, pw: str) -> dict:
    """
    Read stake-info for all provisioners and return a summary.
    Returns:
        {
            "active":   [node_dict, ...],
            "maturing": [node_dict, ...],
            "inactive": [node_dict, ...],
            "regular":  bool,   # True iff A:1 & M:1
            "label":    str,    # human-readable "A:1 M:1 I:0" etc.
        }
    """
    nodes    = {}
    for idx in NODE_INDICES:
        r    = wallet_cmd(f"stake-info --profile-idx {idx}", timeout=20, password=pw)
        info = parse_stake_info(r.get("stdout", "") + r.get("stderr", ""),
                                current_tip=tip)
        with _stake_cache_lock:
            authoritative = (info["has_stake"]
                             or "A stake does not exist" in (r.get("stdout","") + r.get("stderr","")))
            if authoritative:
                _stake_cache[idx] = {**info, "ok": r["ok"], "cached": False}
            elif idx in _stake_cache:
                info = dict(_stake_cache[idx])
                info["cached"] = True
        info["idx"] = idx
        nodes[idx]  = info

    active   = [n for n in nodes.values() if n["status"] == "active"]
    maturing = [n for n in nodes.values() if n["status"] == "maturing"]
    inactive = [n for n in nodes.values() if n["status"] == "inactive"]
    regular  = (len(active) == 1 and len(maturing) == 1)

    return {
        "active":   active,
        "maturing": maturing,
        "inactive": inactive,
        "regular":  regular,
        "label":    f"A:{len(active)} M:{len(maturing)} I:{len(inactive)}",
    }


# ── stake_rotation helpers ────────────────────────────────────────────────────

def _query_contract_total_dusk() -> float:
    """Query total DUSK held by SOZU contract in the transfer contract.
    NOTE: this includes already-staked funds — use _query_pool_available_dusk() instead.
    """
    import subprocess as _sp, struct as _struct
    url = ("https://testnet.nodes.dusk.network/on/contracts:"
           "0100000000000000000000000000000000000000000000000000000000000000"
           "/contract_balance")
    rc = _sp.run(
        ["curl", "-s", "-X", "POST", url,
         "-H", f"rusk-version: {RUSK_VERSION}",
         "-H", "Content-Type: application/json",
         "-d", json.dumps(CONTRACT_ADDRESS())],
        capture_output=True, text=True, timeout=15)
    raw = rc.stdout.strip()
    try:
        lux = int(json.loads(raw))
        return lux / 1_000_000_000
    except Exception:
        pass
    try:
        import re as _re
        hex_match = _re.search(r'[0-9a-fA-F]{16}', raw)
        if hex_match:
            lux = _struct.unpack("<Q", bytes.fromhex(hex_match.group(0)))[0]
            return lux / 1_000_000_000
    except Exception:
        pass
    _rlog(f"contract total balance decode failed: {raw!r}", "warn")
    return 0.0


def _query_pool_balance_dusk(staked_dusk: float = 0.0) -> float:
    """
    Query allocatable DUSK in the SOZU pool.
    The contract_balance IS the uninvested/pending amount — staked funds
    have already left the pool contract, so no subtraction needed.
    staked_dusk parameter kept for API compatibility but ignored.
    """
    available = _query_contract_total_dusk()
    _rlog(f"pool balance: {available:.4f} DUSK available")
    return available


def _stake_lux(idx: int, amount_lux: int, pw: str) -> bool:
    """Issue stake_activate for idx with exact LUX amount. Returns True on success."""
    sk = _get_sk(idx)
    if not sk:
        _rlog(f"prov[{idx}] SK not configured", "error")
        return False
    if amount_lux < 1_000_000_000:
        _rlog(f"prov[{idx}] amount {amount_lux} LUX too small, skipping")
        return True
    dusk = amount_lux / 1_000_000_000
    _rlog(f"stake_activate prov[{idx}] {dusk:.4f} DUSK")
    r1 = operator_cmd(
        f"calculate-payload-stake-activate --provisioner-sk {sk} "
        f"--amount {amount_lux} --network-id {NETWORK_ID()}",
        timeout=30, password=pw)
    if not r1["ok"]:
        _rlog(f"stake_activate payload failed: {(r1.get('stderr') or '')[:120]}", "error")
        return False
    pl = extract_payload(r1["stdout"])
    r2 = operator_cmd(
        f"contract-call --contract-id {CONTRACT_ADDRESS()} --fn-name stake_activate "
        f"--fn-args '{pl}' --gas-limit {GAS_LIMIT}",
        timeout=60, password=pw)
    # The wallet CLI exits with code 0 even on on-chain panics — check stderr too.
    tx_stderr = (r2.get("stderr") or "")
    tx_panic  = ("Transaction error" in tx_stderr or "Panic" in tx_stderr)
    if not r2["ok"] or tx_panic:
        _rlog(f"stake_activate tx failed: {tx_stderr[:200]}", "error")
        return False
    _rlog(f"prov[{idx}] staked {dusk:.4f} DUSK OK")
    # Invalidate cache so next tick forces a fresh stake-info read
    # rather than accumulating on top of a stale value.
    with _stake_cache_lock:
        _stake_cache.pop(idx, None)
    return True


def _do_liquidate_terminate(addr: str, idx: int, pw: str) -> tuple:
    """
    Liquidate then terminate provisioner at addr/idx.
    Returns (ok: bool, lux_amount: int) where lux_amount is read from the
    liquidation event (matched by provisioner address prefix).
    Blocks until both events appear or timeout.
    """
    # ── Liquidate ─────────────────────────────────────────────────────────────
    r1 = operator_cmd(f"calculate-payload-liquidate --provisioner {addr}",
                      timeout=30, password=pw)
    if not r1["ok"]:
        _rlog(f"liquidate payload failed: {(r1.get('stderr') or '')[:120]}", "error")
        return False, 0
    pl = extract_payload(r1["stdout"])
    log_idx_before_liq = len(_event_log)
    r2 = operator_cmd(
        f"contract-call --contract-id {CONTRACT_ADDRESS()} --fn-name liquidate "
        f"--fn-args '{pl}' --gas-limit {GAS_LIMIT}",
        timeout=60, password=pw)
    liq_stderr = (r2.get("stderr") or "")
    liq_panic  = ("Transaction error" in liq_stderr or "Panic" in liq_stderr)
    if not r2["ok"] or liq_panic:
        _rlog(f"liquidate tx failed: {liq_stderr[:200]}", "error")
        return False, 0

    # Wait for liquidation event (up to 15s) — read LUX amount from it
    _rlog(f"liquidate tx submitted — waiting for event (prov prefix: {addr[:8]})")
    lux_amount = 0
    prefix = addr[:8]
    deadline = time.time() + 15
    while time.time() < deadline:
        with _event_log_lock:
            new_entries = list(_event_log[log_idx_before_liq:])
        for ev in new_entries:
            if "liquidate" in ev.get("topic", ""):
                haystack = json.dumps(ev.get("decoded", "")) + (ev.get("data", ""))
                if prefix in haystack:
                    lux_amount = _extract_lux_from_event(ev)
                    _rlog(f"liquidation event confirmed — {lux_amount} LUX "
                          f"({lux_amount/1_000_000_000:.4f} DUSK)")
                    break
        if lux_amount:
            break
        time.sleep(2)

    if not lux_amount:
        _rlog("liquidation event not seen within 15s — proceeding anyway", "warn")

    # ── Terminate ─────────────────────────────────────────────────────────────
    r3 = operator_cmd(f"calculate-payload-terminate --provisioner {addr}",
                      timeout=30, password=pw)
    if not r3["ok"]:
        _rlog(f"terminate payload failed: {(r3.get('stderr') or '')[:120]}", "error")
        return False, lux_amount
    pl2 = extract_payload(r3["stdout"])
    log_idx_before_term = len(_event_log)
    r4 = operator_cmd(
        f"contract-call --contract-id {CONTRACT_ADDRESS()} --fn-name terminate "
        f"--fn-args '{pl2}' --gas-limit {GAS_LIMIT}",
        timeout=60, password=pw)
    term_stderr = (r4.get("stderr") or "")
    term_panic  = ("Transaction error" in term_stderr or "Panic" in term_stderr)
    if not r4["ok"] or term_panic:
        _rlog(f"terminate tx failed: {term_stderr[:200]}", "error")
        return False, lux_amount

    # Wait for terminate event (up to 15s)
    _rlog("terminate tx submitted — waiting for event")
    deadline = time.time() + 15
    term_confirmed = False
    while time.time() < deadline:
        with _event_log_lock:
            new_entries = list(_event_log[log_idx_before_term:])
        for ev in new_entries:
            if "terminate" in ev.get("topic", ""):
                haystack = json.dumps(ev.get("decoded", "")) + (ev.get("data", ""))
                if prefix in haystack:
                    _rlog("terminate event confirmed")
                    term_confirmed = True
                    break
        if term_confirmed:
            break
        time.sleep(2)

    if not term_confirmed:
        _rlog("terminate event not seen within 15s — proceeding anyway", "warn")

    return True, lux_amount


def _extract_lux_from_event(ev: dict) -> int:
    """Extract LUX integer from a decoded SOZU event entry."""
    decoded = ev.get("decoded", {})
    if isinstance(decoded, dict):
        for k in ("amount", "value", "lux", "stake"):
            v = decoded.get(k)
            if v is not None:
                try:
                    return int(v)
                except Exception:
                    pass
    return 0


def _collect_deposit_lux(log_cursor: int, timeout_sec: int) -> int:
    """
    Sum LUX from all deposit events appearing in _event_log[log_cursor:]
    within timeout_sec seconds. Returns total LUX deposited.
    """
    deadline = time.time() + timeout_sec
    seen_keys = set()
    total_lux = 0
    while time.time() < deadline:
        with _event_log_lock:
            new_entries = list(_event_log[log_cursor:])
            log_cursor = len(_event_log)
        for ev in new_entries:
            if not ev.get("topic", "").startswith("deposit"):
                continue
            key = (ev.get("height"), ev.get("topic"), json.dumps(ev.get("decoded", "")))
            if key in seen_keys:
                continue
            seen_keys.add(key)
            lux = _extract_lux_from_event(ev)
            if lux > 0:
                _rlog(f"deposit event: +{lux/1_000_000_000:.4f} DUSK")
                total_lux += lux
        time.sleep(3)
    return total_lux


# ── stake_rotation ────────────────────────────────────────────────────────────

def stake_rotation(state: dict, tip: int, pw: str):
    """
    Called every tick when A:1 & M:1 (regular operation).

    epoch_state_regular  (blk_left > rot_win):
        Top up active provisioner (respecting slash budget), then maturing with remainder.

    epoch_state_rotation (snatch_win < blk_left <= rot_win):
        1. Liq+term active (once per epoch)
        2. Seed 1k DUSK back into former-active
        3. Send rest of liquidated amount to maturing
        4. Listen for deposit events and top up maturing to capacity

    epoch_state_snatch   (blk_left <= snatch_win):
        Grab pool balance and fill maturing to capacity.
    """
    rot_win     = int(cfg("rotation_window")        or 100)
    snatch_win  = int(cfg("snatch_window")           or 50)
    stake_limit = float(cfg("operator_stake_limit")  or 3_000_000)
    max_slash_f = float(cfg("max_slash_pct")         or 0.02)
    seed_dusk   = float(cfg("rotation_seed_dusk")    or 1_000)
    SEED_LUX    = int(seed_dusk * 1_000_000_000)

    blk_left    = EPOCH_BLOCKS - (tip % EPOCH_BLOCKS)
    epoch       = tip // EPOCH_BLOCKS

    act = state["active"][0]   if state["active"]   else {}
    mat = state["maturing"][0] if state["maturing"] else {}

    act_addr = (act.get("staking_address")
                or (cfg(f"prov_{act['idx']}_address") if act.get("idx") is not None else "") or "")

    max_slash_dusk    = stake_limit * max_slash_f
    combined_slashed  = (act.get("slashed_dusk", 0.0)
                         + mat.get("slashed_dusk", 0.0))

    # ── epoch_state_regular ───────────────────────────────────────────────────
    if blk_left > rot_win and not act:
        _rlog("regular window but no active provisioner — skipping", "warn")
        _rset("idle")
        return
    if blk_left > rot_win:
        _rset("rotating", "epoch_state_regular: pool top-up")

        staked_total = (act.get("amount_dusk", 0.0)
                       + mat.get("amount_dusk", 0.0))
        pool_dusk = _query_pool_balance_dusk(staked_total)
        if pool_dusk < 1:
            _rlog(f"regular: pool={pool_dusk:.2f} DUSK — nothing to allocate")
            _rset("idle")
            return

        _rlog(f"regular: pool={pool_dusk:.2f} DUSK  slashed={combined_slashed:.2f}/"
              f"{max_slash_dusk:.2f} DUSK")

        # Active top-up — slash budget gating
        slash_headroom_dusk = max(0.0, max_slash_dusk - combined_slashed)
        # Each DUSK top-up adds 0.10 DUSK slash → max top-up = headroom / 0.10
        max_topup_act_dusk  = slash_headroom_dusk / 0.10
        act_occupied        = act.get("amount_dusk", 0.0) + act.get("slashed_dusk", 0.0)
        mat_occupied_pre    = mat.get("amount_dusk", 0.0) + mat.get("slashed_dusk", 0.0)
        act_staked          = act_occupied  # keep for log compat
        act_capacity        = max(0.0, stake_limit - act_occupied - mat_occupied_pre)
        topup_act_dusk      = min(pool_dusk, min(max_topup_act_dusk, act_capacity))

        if topup_act_dusk >= 1:
            topup_act_lux = int(topup_act_dusk * 100) * 10_000_000
            _rlog(f"top-up active prov[{act['idx']}] {topup_act_dusk:.2f} DUSK "
                  f"(slash budget remaining: {slash_headroom_dusk:.2f} DUSK)")
            ok = _stake_lux(act["idx"], topup_act_lux, pw)
            if ok:
                pool_dusk    -= topup_act_dusk
                act_occupied += topup_act_dusk   # keep in-memory view consistent
            time.sleep(5)
        else:
            reason = ("slash limit reached"
                      if slash_headroom_dusk < 0.10
                      else f"at capacity ({act_occupied:.0f}+{mat_occupied_pre:.0f}/{stake_limit:.0f} DUSK)")
            _rlog(f"active prov[{act['idx']}] no top-up: {reason}")

        # Maturing top-up — no slash risk
        # act_occupied already updated above if the active tx succeeded.
        if pool_dusk >= 1:
            mat_occupied = mat.get("amount_dusk", 0.0) + mat.get("slashed_dusk", 0.0)
            # Capacity = stake_limit minus all occupied stake (staked + slashed) across all provisioners
            mat_capacity = max(0.0, stake_limit - act_occupied - mat_occupied)
            topup_mat    = min(pool_dusk, mat_capacity)
            if topup_mat >= 1:
                _rlog(f"top-up maturing prov[{mat['idx']}] {topup_mat:.2f} DUSK")
                _stake_lux(mat["idx"], int(topup_mat * 100) * 10_000_000, pw)
            else:
                _rlog(f"maturing prov[{mat['idx']}] at capacity")

        _rset("idle")
        return

    # ── epoch_state_rotation ──────────────────────────────────────────────────
    if snatch_win < blk_left <= rot_win and not act:
        _rlog("rotation window but no active provisioner — skipping", "warn")
        _rset("idle")
        return
    if snatch_win < blk_left <= rot_win:
        _rset("rotating", "epoch_state_rotation")

        # Gate: only run liq+term+distribute once per epoch
        if _rotation_state.get("epoch_rotated") != epoch:
            if not act_addr:
                _rlog(f"prov[{act['idx']}] staking address unknown — cannot rotate", "error")
                _rset("error")
                _rotation_state["last_error"] = f"prov[{act['idx']}] address unknown"
                return

            _rlog(f"rotation window: liq+term prov[{act['idx']}] ({act_addr[:10]}…)")
            ok, lux_amount = _do_liquidate_terminate(act_addr, act["idx"], pw)
            if not ok:
                _rset("error")
                _rotation_state["last_error"] = "liq+term failed"
                return

            # Seed 1k back into former-active
            _rlog(f"seed 1k DUSK → prov[{act['idx']}]")
            _stake_lux(act["idx"], SEED_LUX, pw)
            time.sleep(5)

            # Send remainder to maturing
            remainder_lux = max(0, lux_amount - SEED_LUX)
            if remainder_lux > 0:
                _rlog(f"distribute remainder {remainder_lux/1_000_000_000:.4f} DUSK "
                      f"→ maturing prov[{mat['idx']}]")
                ok = _stake_lux(mat["idx"], remainder_lux, pw)
                if not ok:
                    remainder_lux = 0   # tx failed — don't subtract from capacity

            _rotation_state["epoch_rotated"] = epoch
            _rlog(f"liq+term+distribute complete — epoch {epoch} rotated")

        # Listen for deposit events for the remaining time in the rotation window
        # and top up maturing to capacity (stake_limit - 1k reserved for former-active).
        # mat_occupied_now comes from the state snapshot (pre-remainder); subtract
        # remainder_lux to reflect what was actually staked this tick.
        mat_occupied_now = mat.get("amount_dusk", 0.0) + mat.get("slashed_dusk", 0.0)
        # After rotation former-active has only seed_dusk (no slash yet)
        mat_capacity_lux = int(max(0.0, (stake_limit - seed_dusk - mat_occupied_now)
                                   * 1_000_000_000))
        # Deduct remainder already staked this tick so capacity isn't overstated
        mat_capacity_lux = max(0, mat_capacity_lux - remainder_lux)

        if mat_capacity_lux < 1_000_000_000:
            _rlog(f"maturing prov[{mat['idx']}] already at capacity — "
                  f"no deposit listening needed")
            _rset("idle")
            return

        # Calculate how long we have left in the rotation window
        # Each tick is ~15s; we block here listening for deposits for the remaining time.
        # blk_left - snatch_win blocks remain in this window × ~10s per block
        listen_sec = max(15, (blk_left - snatch_win) * 10 - 15)
        _rlog(f"listening for deposit events for ~{listen_sec}s "
              f"(mat capacity: {mat_capacity_lux/1_000_000_000:.2f} DUSK available)")

        log_cursor = len(_event_log)
        total_deposit_lux = _collect_deposit_lux(log_cursor, listen_sec)

        if total_deposit_lux > 0:
            topup_lux = min(total_deposit_lux, mat_capacity_lux)
            _rlog(f"deposits collected: {total_deposit_lux/1_000_000_000:.4f} DUSK "
                  f"— topping up maturing prov[{mat['idx']}] {topup_lux/1_000_000_000:.4f} DUSK")
            _stake_lux(mat["idx"], topup_lux, pw)
        else:
            _rlog("no deposit events during rotation window")

        _rset("idle")
        return

    # ── epoch_state_snatch ────────────────────────────────────────────────────
    if blk_left <= snatch_win:
        _rset("rotating", "epoch_state_snatch")

        staked_total = (act.get("amount_dusk", 0.0)
                       + mat.get("amount_dusk", 0.0))
        pool_dusk = _query_pool_balance_dusk(staked_total)
        _rlog(f"snatch window: pool={pool_dusk:.2f} DUSK  blk_left={blk_left}")

        if pool_dusk < 1:
            _rlog("snatch: pool empty")
            _rset("idle")
            return

        # ── Maturing top-up (preferred — no slash penalty) ───────────────────
        if mat:
            mat_occupied = mat.get("amount_dusk", 0.0) + mat.get("slashed_dusk", 0.0)
            # At snatch time rotation has already run: former-active holds seed_dusk (no slash yet)
            mat_capacity = max(0.0, stake_limit - seed_dusk - mat_occupied)
            topup_dusk   = min(pool_dusk, mat_capacity)
            if topup_dusk >= 1:
                _rlog(f"snatch: top-up maturing prov[{mat['idx']}] {topup_dusk:.2f} DUSK")
                _stake_lux(mat["idx"], int(topup_dusk * 100) * 10_000_000, pw)
            else:
                _rlog(f"snatch: maturing prov[{mat['idx']}] at capacity")
            _rset("idle")
            return

        # ── No maturing provisioner — top-up active instead (slash-budget gated) ──
        # Typical state: A:1 M:0 I:1 — rotation ran last epoch, inactive hasn't
        # transitioned yet. Active stays active; top it up while waiting.
        if not act:
            _rlog("snatch: no maturing or active provisioner — nothing to do")
            _rset("idle")
            return

        act_occupied        = act.get("amount_dusk", 0.0) + act.get("slashed_dusk", 0.0)
        inact_occupied      = sum(
            n.get("amount_dusk", 0.0) + n.get("slashed_dusk", 0.0)
            for n in state.get("inactive", [])
        )
        slash_headroom_dusk = max(0.0, max_slash_dusk - combined_slashed)
        max_topup_act_dusk  = slash_headroom_dusk / 0.10
        act_capacity        = max(0.0, stake_limit - act_occupied - inact_occupied)
        topup_dusk          = min(pool_dusk, min(max_topup_act_dusk, act_capacity))

        if topup_dusk >= 1:
            _rlog(f"snatch: top-up active prov[{act['idx']}] {topup_dusk:.2f} DUSK "
                  f"(slash budget remaining: {slash_headroom_dusk:.2f} DUSK)")
            _stake_lux(act["idx"], int(topup_dusk * 100) * 10_000_000, pw)
        else:
            reason = ("slash limit reached"
                      if slash_headroom_dusk < 0.10
                      else f"at capacity ({act_occupied:.0f}+{inact_occupied:.0f}/{stake_limit:.0f} DUSK)")
            _rlog(f"snatch: active prov[{act['idx']}] no top-up: {reason}")

        _rset("idle")
        return


def _seed_from_pool(idx: int, seed_dusk: float, pw: str) -> tuple:
    """
    Seed provisioner idx with exactly seed_dusk DUSK from pool balance.

    The contract enforces a minimum stake of seed_dusk (1k DUSK) — partial amounts
    are rejected with "staked value is lower than the minimum amount". So we only
    proceed when pool >= seed_dusk; otherwise we wait silently without submitting
    any transaction (no mempool spam).

    Behaviour:
      - pool < seed_dusk: logs and returns (False, 0) — no tx submitted.
      - pool >= seed_dusk: stakes exactly seed_dusk DUSK.
        Active provisioner stays active until this succeeds and the inactive
        slot transitions to maturing.

    Returns (ok: bool, staked_dusk: float).
    """
    pool = _query_pool_balance_dusk()
    if pool < seed_dusk:
        _rlog(f"prov[{idx}] seed skipped — pool has {pool:.4f} DUSK, "
              f"need >= {seed_dusk:.0f} DUSK (contract minimum). "
              f"Active provisioner stays active until pool refills.")
        return False, 0.0

    amount_lux = int(seed_dusk * 100) * 10_000_000   # round to 0.01 DUSK
    ok = _stake_lux(idx, amount_lux, pw)
    return ok, seed_dusk if ok else 0.0


def recover_stake_rotation(state: dict, tip: int, pw: str):
    """
    Called when provisioner state is irregular (anything other than A:1 & M:1).
    Recovers back to regular operation (A:1 & M:1).

    Handled states:
      A:2 M:0 I:0  — liq+term one active, seed with 1k
      I:2          — seed only the unseeded one (or first if both at 0)
      M:2          — liq+term one maturing, seed with 1k
      A:1 M:0 I:1  — seed inactive with 1k
      A:0 M:1 I:1  — seed inactive with 1k
    """
    seed_dusk   = float(cfg("rotation_seed_dusk")       or 1_000)
    stake_limit = float(cfg("operator_stake_limit")     or 3_000_000)
    max_slash_f = float(cfg("max_slash_pct")            or 0.02)
    max_slash_dusk = stake_limit * max_slash_f

    active   = state["active"]
    maturing = state["maturing"]
    inactive = state["inactive"]
    n_a, n_m, n_i = len(active), len(maturing), len(inactive)

    act = active[0]   if active   else {}
    mat = maturing[0] if maturing else {}

    combined_slashed = (act.get("slashed_dusk", 0.0)
                        + mat.get("slashed_dusk", 0.0))

    _rlog(f"recover: state={state['label']}", "warn")

    # ── A:2 M:0 I:0 — liq+term the one with more transitions ─────────────────
    if n_a == 2 and n_m == 0 and n_i == 0:
        to_rm  = max(active, key=lambda n: n.get("transitions") or 0)
        to_keep = [n for n in active if n["idx"] != to_rm["idx"]][0]
        addr   = (to_rm.get("staking_address")
                  or cfg(f"prov_{to_rm['idx']}_address") or "")
        if not addr:
            _rlog(f"prov[{to_rm['idx']}] address unknown — cannot recover A:2", "error")
            _rset("error")
            _rotation_state["last_error"] = f"prov[{to_rm['idx']}] address unknown"
            return
        _rlog(f"A:2 recovery: liq+term prov[{to_rm['idx']}] "
              f"(transitions={to_rm.get('transitions')}), keep prov[{to_keep['idx']}]")
        _rset("recovering", f"liq+term prov[{to_rm['idx']}]")
        ok, _ = _do_liquidate_terminate(addr, to_rm["idx"], pw)
        if not ok:
            _rset("error")
            _rotation_state["last_error"] = "A:2 liq+term failed"
            return
        _rlog(f"A:2 → seeding prov[{to_rm['idx']}] with up to {seed_dusk:.0f} DUSK from pool")
        ok, _ = _seed_from_pool(to_rm["idx"], seed_dusk, pw)
        if not ok:
            _rset("idle")   # pool empty or tx failed — retry next tick
            return
        _rlog("A:2 recovery done — expecting A:1 I:1 → A:1 M:1 after transition")
        _rset("idle")
        return

    # ── I:2 — seed only the unseeded provisioner (or first if both at 0) ──────
    if n_i == 2 and n_a == 0 and n_m == 0:
        unseeded = [n for n in inactive if n.get("amount_dusk", 0.0) == 0]
        seeded   = [n for n in inactive if n.get("amount_dusk", 0.0) > 0]

        if len(seeded) >= 1 and len(unseeded) == 0:
            # Both already seeded — just wait for transitions
            _rlog("I:2 both provisioners already seeded — waiting for transitions")
            _rset("idle")
            return

        if len(seeded) == 1:
            # One seeded, one not — seed the other
            target = unseeded[0]
            _rlog(f"I:2 prov[{seeded[0]['idx']}] already seeded — "
                  f"seeding prov[{target['idx']}] with {seed_dusk:.0f} DUSK")
        else:
            # Both at 0 — seed only the first
            target = inactive[0]
            _rlog(f"I:2 both unseeded — seeding prov[{target['idx']}] only "
                  f"({seed_dusk:.0f} DUSK). Will seed other after transition.")

        _rset("recovering", f"seed prov[{target['idx']}]")
        ok, _ = _seed_from_pool(target["idx"], seed_dusk, pw)
        if not ok:
            _rset("idle")   # pool empty or tx failed — retry next tick
            return
        _rlog("I:2 recovery step done — expecting I:1 seeded + I:1 unseeded → "
              "seed other next epoch → A:1 M:1")
        _rset("idle")
        return

    # ── M:2 — liq+term one maturing, seed with 1k ─────────────────────────────
    if n_m == 2 and n_a == 0 and n_i == 0:
        # Pick the one with fewer transitions (less progressed) to terminate
        to_rm  = min(maturing, key=lambda n: n.get("transitions") or 0)
        addr   = (to_rm.get("staking_address")
                  or cfg(f"prov_{to_rm['idx']}_address") or "")
        if not addr:
            _rlog(f"prov[{to_rm['idx']}] address unknown — cannot recover M:2", "error")
            _rset("error")
            _rotation_state["last_error"] = f"prov[{to_rm['idx']}] address unknown"
            return
        _rlog(f"M:2 recovery: liq+term prov[{to_rm['idx']}] "
              f"(transitions={to_rm.get('transitions')})")
        _rset("recovering", f"liq+term prov[{to_rm['idx']}]")
        ok, _ = _do_liquidate_terminate(addr, to_rm["idx"], pw)
        if not ok:
            _rset("error")
            _rotation_state["last_error"] = "M:2 liq+term failed"
            return
        to_keep_mat = [n for n in maturing if n["idx"] != to_rm["idx"]][0]
        _rlog(f"M:2 → seeding prov[{to_rm['idx']}] with up to {seed_dusk:.0f} DUSK from pool")
        ok, _ = _seed_from_pool(to_rm["idx"], seed_dusk, pw)
        if not ok:
            _rset("idle")   # pool empty or tx failed — retry next tick
            return
        time.sleep(5)
        # Top up surviving maturing provisioner from pool
        rot_win     = int(cfg("rotation_window")       or 100)
        blk_left    = EPOCH_BLOCKS - (tip % EPOCH_BLOCKS)
        if blk_left > rot_win:
            _staked_r4   = to_keep_mat.get("amount_dusk", 0.0)
            pool_dusk    = _query_pool_balance_dusk(_staked_r4)
            stake_limit  = float(cfg("operator_stake_limit") or 3_000_000)
            mat_occupied = (to_keep_mat.get("amount_dusk", 0.0)
                           + to_keep_mat.get("slashed_dusk", 0.0))
            # Other provisioner just got seed_dusk (no slash yet)
            mat_capacity = max(0.0, stake_limit - seed_dusk - mat_occupied)
            topup_dusk   = min(pool_dusk, mat_capacity)
            if topup_dusk >= 1:
                _rlog(f"M:2 — top-up surviving maturing prov[{to_keep_mat['idx']}] "
                      f"{topup_dusk:.2f} DUSK from pool")
                _stake_lux(to_keep_mat["idx"], int(topup_dusk * 100) * 10_000_000, pw)
            else:
                _rlog(f"M:2 — maturing prov[{to_keep_mat['idx']}] at capacity "
                      f"or pool empty (pool={pool_dusk:.2f} cap={mat_capacity:.2f} DUSK)")
        _rlog("M:2 recovery done — expecting M:1 I:1 → A:1 M:1 after transition")
        _rset("idle")
        return

    # ── A:1 M:0 I:1 — seed inactive, top up active while waiting ────────────
    if n_a == 1 and n_m == 0 and n_i == 1:
        target = inactive[0]
        if target.get("amount_dusk", 0.0) >= seed_dusk:
            _rlog(f"A:1 M:0 I:1 — prov[{target['idx']}] already seeded, "
                  f"waiting for transition")
        else:
            # Seed from pool — no tx if pool < seed_dusk (contract minimum)
            _rset("recovering", f"seed prov[{target['idx']}]")
            ok, _ = _seed_from_pool(target["idx"], seed_dusk, pw)
            if not ok:
                # Pool insufficient — active stays active, still try active top-up below
                pass
            else:
                _rlog("A:1 M:0 I:1 — inactive seeded, topping up active while waiting")

        # Top up active from pool regardless — inactive just needs to transition,
        # active has headroom and the pool may have available DUSK.
        staked_total        = act.get("amount_dusk", 0.0) + target.get("amount_dusk", 0.0)
        pool_dusk           = _query_pool_balance_dusk(staked_total)
        act_occupied        = act.get("amount_dusk", 0.0) + act.get("slashed_dusk", 0.0)
        inact_occupied      = target.get("amount_dusk", 0.0) + target.get("slashed_dusk", 0.0)
        slash_headroom_dusk = max(0.0, max_slash_dusk - combined_slashed)
        max_topup_act_dusk  = slash_headroom_dusk / 0.10
        act_capacity        = max(0.0, stake_limit - act_occupied - inact_occupied)
        topup_dusk          = min(pool_dusk, min(max_topup_act_dusk, act_capacity))

        if pool_dusk >= 1 and topup_dusk >= 1:
            _rlog(f"A:1 M:0 I:1 — top-up active prov[{act['idx']}] {topup_dusk:.2f} DUSK "
                  f"(slash budget remaining: {slash_headroom_dusk:.2f} DUSK)")
            _stake_lux(act["idx"], int(topup_dusk * 100) * 10_000_000, pw)
        elif pool_dusk >= 1:
            reason = ("slash limit reached"
                      if slash_headroom_dusk < 0.10
                      else f"at capacity ({act_occupied:.0f}+{inact_occupied:.0f}/{stake_limit:.0f} DUSK)")
            _rlog(f"A:1 M:0 I:1 — active prov[{act['idx']}] no top-up: {reason}")

        _rlog("A:1 M:0 I:1 recovery done — expecting A:1 M:1 after transition")
        _rset("idle")
        return

    # ── A:0 M:1 I:1 — seed inactive, then top up maturing from pool ────────────
    if n_a == 0 and n_m == 1 and n_i == 1:
        mat    = maturing[0]
        target = inactive[0]
        if target.get("amount_dusk", 0.0) >= seed_dusk:
            _rlog(f"A:0 M:1 I:1 — prov[{target['idx']}] already seeded, "
                  f"waiting for transition")
        else:
            # Seed from pool — no tx if pool < seed_dusk (contract minimum)
            _rset("recovering", f"seed prov[{target['idx']}]")
            ok, _ = _seed_from_pool(target["idx"], seed_dusk, pw)
            if ok:
                time.sleep(5)
            # If pool insufficient, fall through to maturing top-up check anyway
        # Top up maturing from pool (epoch_state_regular only)
        rot_win     = int(cfg("rotation_window")       or 100)
        blk_left    = EPOCH_BLOCKS - (tip % EPOCH_BLOCKS)
        if blk_left > rot_win:
            _staked_r3   = mat.get("amount_dusk", 0.0)
            pool_dusk    = _query_pool_balance_dusk(_staked_r3)
            stake_limit  = float(cfg("operator_stake_limit") or 3_000_000)
            mat_occupied  = mat.get("amount_dusk", 0.0) + mat.get("slashed_dusk", 0.0)
            # Inactive prov has seed_dusk just added (no slash yet)
            inact_occupied = max(seed_dusk, target.get("amount_dusk", 0.0))
            mat_capacity  = max(0.0, stake_limit - inact_occupied - mat_occupied)
            topup_dusk   = min(pool_dusk, mat_capacity)
            if topup_dusk >= 1:
                _rlog(f"A:0 M:1 I:1 — top-up maturing prov[{mat['idx']}] "
                      f"{topup_dusk:.2f} DUSK from pool")
                _stake_lux(mat["idx"], int(topup_dusk * 100) * 10_000_000, pw)
            else:
                _rlog(f"A:0 M:1 I:1 — maturing prov[{mat['idx']}] at capacity "
                      f"or pool empty (pool={pool_dusk:.2f} cap={mat_capacity:.2f} DUSK)")
        _rlog("A:0 M:1 I:1 done — expecting A:1 M:1 after next transition")
        _rset("idle")
        return

    # ── Unhandled state ───────────────────────────────────────────────────────
    _rlog(f"unhandled irregular state {state['label']} — standing by", "warn")
    _rset("idle")



# ── Main tick ─────────────────────────────────────────────────────────────────

def _rotation_tick():
    pw = get_password()
    if not pw:
        _rlog("no password cached — skipping tick", "warn")
        return

    # Fetch tip
    try:
        import urllib.request as _ur, json as _j
        q   = '{ block(height: -1) { header { height } } }'
        req = _ur.Request(GRAPHQL_URL, data=q.encode(),
                          headers={"rusk-version": RUSK_VERSION,
                                   "Content-Type": "application/graphql"},
                          method="POST")
        with _ur.urlopen(req, timeout=6) as r:
            p = _j.loads(r.read())
        b   = p.get("block") or p.get("data", {}).get("block", {})
        tip = int(b["header"]["height"])
    except Exception as e:
        _rlog(f"fetch_tip failed: {e}", "warn")
        return

    epoch            = tip // EPOCH_BLOCKS
    blocks_until_end = EPOCH_BLOCKS - (tip % EPOCH_BLOCKS)

    # Clear stake cache on epoch transition so stale maturing→active
    # values don't corrupt capacity calculations after a rotation.
    last_epoch = _rotation_state.get("last_epoch")
    if last_epoch is not None and epoch != last_epoch:
        with _stake_cache_lock:
            _stake_cache.clear()
        _rlog(f"epoch {last_epoch}→{epoch}: stake cache cleared")
    _rotation_state["last_epoch"] = epoch

    _rset("assessing")
    st = _assess_state(tip, pw)

    _rlog(f"epoch={epoch} blk_left={blocks_until_end}  state={st['label']}  "
          f"({'regular' if st['regular'] else 'IRREGULAR'})")

    if _rotation_state.get("warmup"):
        _rlog(f"warmup tick — state assessed, no actions taken. "
              "Rotation active from next tick.")
        _rotation_state["warmup"] = False
        _rotation_state["irregular_streak"] = 0
        _rset("idle")
        return

    snatch_win = int(cfg("snatch_window") or 50)
    in_snatch  = blocks_until_end <= snatch_win

    if st["regular"] or in_snatch:
        # During snatch window A:0 M:1 I:1 is expected post-rotation — always
        # dispatch to stake_rotation which handles all three epoch states.
        _rotation_state["irregular_streak"] = 0
        _rset("rotating", "stake_rotation")
        stake_rotation(st, tip, pw)
    else:
        streak = _rotation_state["irregular_streak"] + 1
        _rotation_state["irregular_streak"] = streak
        if streak < 2:
            _rlog(f"irregular state {st['label']} — streak={streak}/2, "
                  f"waiting for confirmation before acting", "warn")
            _rset("idle")
            return
        _rset("recovering", "recover_stake_rotation")
        recover_stake_rotation(st, tip, pw)


def _rotation_thread():
    while True:
        time.sleep(15)
        if not _rotation_state["enabled"]:
            continue
        try:
            _rotation_tick()
        except Exception as e:
            _rlog(f"unhandled exception: {e}", "error")
            _rset("error")
            _rotation_state["last_error"] = str(e)

threading.Thread(target=_rotation_thread, daemon=True, name="rotation").start()




@app.route("/api/rotation/status", methods=["GET","POST"])
def rotation_status():
    st = {k: (list(v) if hasattr(v, '__iter__') and not isinstance(v, str) else v)
          for k, v in _rotation_state.items()}
    return jsonify(st)

@app.route("/api/rotation/enable", methods=["POST"])
def rotation_enable():
    _rotation_state["enabled"] = True
    _rotation_state["warmup"]  = True
    _rset("idle")
    _save_rotation_enabled(True)
    _rlog("rotation ENABLED — first tick will assess state only, no actions")
    return jsonify({"ok": True, "enabled": True})

@app.route("/api/rotation/disable", methods=["POST"])
def rotation_disable():
    _rotation_state["enabled"] = False
    _rset("idle")
    _save_rotation_enabled(False)
    _rlog("rotation DISABLED")
    return jsonify({"ok": True, "enabled": False})


@app.route("/api/rotation/cmd_log", methods=["GET"])
def rotation_cmd_log():
    """Return background command results for the dashboard Command Output panel.
    Client passes ?after=N to get only entries after index N."""
    with _cmd_log_lock:
        entries = list(_cmd_log)
    after_idx = int(request.args.get("after", -1))
    new_entries = entries[after_idx + 1:] if after_idx >= 0 else entries
    return jsonify({"entries": new_entries, "total": len(entries)})


# ── Configuration API ─────────────────────────────────────────────────────────

@app.route("/api/config", methods=["GET"])
def get_config():
    """Return current dashboard configuration (no secrets). SKs are never returned."""
    _load_config()
    safe = {k: v for k, v in _cfg.items() if not k.endswith("_sk")}
    # Tell dashboard which SKs are configured (bool only, not the values)
    sks = _load_sks()
    safe["prov_0_sk_set"] = bool(sks.get("prov_0_sk"))
    safe["prov_1_sk_set"] = bool(sks.get("prov_1_sk"))
    return jsonify(safe)

@app.route("/api/config", methods=["POST"])
def set_config():
    """
    Update configuration. Accepts partial updates.
    Body: { "network_id": 2, "contract_address": "...", ... }
    """
    data = request.get_json() or {}
    current = dict(_cfg) if _cfg else dict(_CONFIG_DEFAULTS)
    # Validate and coerce types
    if "network_id" in data:
        current["network_id"] = int(data["network_id"])
    if "contract_address" in data:
        current["contract_address"] = str(data["contract_address"]).strip()
    if "operator_address" in data:
        current["operator_address"] = str(data["operator_address"]).strip()
    if "operator_stake_limit" in data:
        current["operator_stake_limit"] = float(data["operator_stake_limit"])
    if "max_slash_pct" in data:
        val = float(data["max_slash_pct"])
        if val > 1:   # accept "2" meaning 2% as well as "0.02"
            val = val / 100
        current["max_slash_pct"] = round(val, 6)
    if "rotation_window" in data:
        current["rotation_window"] = int(data["rotation_window"])
    if "snatch_window" in data:
        current["snatch_window"] = int(data["snatch_window"])
    if "backfill_blocks" in data:
        current["backfill_blocks"] = int(data["backfill_blocks"])
    if "rotation_seed_dusk" in data:
        current["rotation_seed_dusk"] = float(data["rotation_seed_dusk"])
    if "prov_0_address" in data:
        current["prov_0_address"] = str(data["prov_0_address"]).strip()
    if "prov_1_address" in data:
        current["prov_1_address"] = str(data["prov_1_address"]).strip()
    _save_config(current)
    # Handle SK updates separately (stored in protected file)
    sk_updated = False
    sks = _load_sks()
    for key in ("prov_0_sk", "prov_1_sk"):
        if key in data and data[key]:
            sks[key] = str(data[key]).strip()
            sk_updated = True
    if sk_updated:
        _save_sks(sks)
    safe = {k: v for k, v in current.items() if not k.endswith("_sk")}
    sks_now = _load_sks()
    safe["prov_0_sk_set"] = bool(sks_now.get("prov_0_sk"))
    safe["prov_1_sk_set"] = bool(sks_now.get("prov_1_sk"))
    return jsonify({"ok": True, "config": safe})

@app.route("/api/config/reset", methods=["POST"])
def reset_config():
    """Reset configuration to defaults."""
    _save_config(dict(_CONFIG_DEFAULTS))
    return jsonify({"ok": True, "config": _cfg})


# ── SSE: live SOZU events stream ──────────────────────────────────────────────

# Event log: list, append-only, newest at end.
# SSE clients track by index so new items are always correctly detected.
_event_log: list = []
_event_log_lock = threading.Lock()
_poller_errors: deque = deque(maxlen=50)   # visible error log

# Last known good stake-info per node index.
# Never replaced by an empty/failed result — stale is better than wrong.
_stake_cache: dict = {}   # {idx: parse_stake_info result dict}
_stake_cache_lock = threading.Lock()
_poller_running = False
_backfill_progress: dict = {"done": 0, "total": 0, "running": False}  # backfill progress


def _log_event(entry: dict):
    with _event_log_lock:
        _event_log.append(entry)
        # trim to last 500
        if len(_event_log) > 500:
            del _event_log[:-500]


def _sozu_poller(backfill: int = 0):
    """Background thread: poll new blocks and push SOZU events to log.
    backfill: number of past blocks to scan before watching live.
    """
    global _poller_running
    import urllib.request as ur
    import subprocess as sp
    import json as j

    def fetch_tip() -> int:
        q = '{ block(height: -1) { header { height } } }'
        req = ur.Request(GRAPHQL_URL, data=q.encode(),
                         headers={"rusk-version": RUSK_VERSION,
                                  "Content-Type": "application/graphql"},
                         method="POST")
        with ur.urlopen(req, timeout=8) as r:
            raw = r.read()
        try:
            p = j.loads(raw)
        except Exception:
            snippet = raw[:200].decode("utf-8", errors="replace")
            raise ValueError(f"GraphQL returned non-JSON: {snippet!r}")
        b = p.get("block") or p.get("data", {}).get("block", {})
        return int(b["header"]["height"])

    def fetch_events(height: int) -> list:
        q = f'{{ contractEvents(height: {height}) {{ json }} }}'
        req = ur.Request(GRAPHQL_URL, data=q.encode(),
                         headers={"rusk-version": RUSK_VERSION,
                                  "Content-Type": "application/graphql"},
                         method="POST")
        with ur.urlopen(req, timeout=8) as r:
            p = j.loads(r.read())
        # Response: {"contractEvents": {"json": [{source, topic, data, ...}, ...]}}
        # The json field contains already-parsed dicts — do NOT json.loads them again.
        ce    = p.get("contractEvents") or p.get("data", {}).get("contractEvents", {})
        items = ce.get("json", []) if isinstance(ce, dict) else (ce if isinstance(ce, list) else [])
        return [ev for ev in items
                if isinstance(ev, dict)
                and ev.get("source", "").lower() == CONTRACT_ID.lower()]

    def decode(topic: str, data_hex: str) -> dict:
        if not data_hex:
            return {}
        hex_val = data_hex if data_hex.startswith("0x") else f"0x{data_hex}"
        url = f"https://testnet.nodes.dusk.network/on/driver:{CONTRACT_ID}/decode_event:{topic}"
        r = sp.run(["curl", "-s", "-X", "POST", url,
                    "-H", f"rusk-version: {RUSK_VERSION}",
                    "-d", hex_val],
                   capture_output=True, text=True, timeout=12)
        raw = r.stdout.strip()
        try:
            return j.loads(raw)
        except Exception:
            return {"_raw": raw[:200]}

    last = None
    seen_events: set = set()   # (height, source, topic) dedup
    _log(f"[poller] started — {GRAPHQL_URL}")
    while _poller_running:
        try:
            tip = fetch_tip()
            if last is None:
                if backfill > 0:
                    last = max(0, tip - backfill)
                    _backfill_progress.update({"done": 0, "total": tip - last, "running": True})
                    _log(f"[poller] tip={tip}, backfilling {backfill} blocks from {last}")
                else:
                    last = tip
                    _log(f"[poller] tip={tip}, watching from next block")
            blocks_scanned = 0
            events_found   = 0
            is_backfilling = _backfill_progress["running"]
            while last < tip:
                h = last + 1
                try:
                    evs = fetch_events(h)
                    blocks_scanned += 1
                    def _decode_ev(ev):
                        topic    = ev.get("topic", "")
                        data_hex = ev.get("data", "")
                        decoded  = decode(topic, data_hex)
                        op = decoded.get("operation", "") if isinstance(decoded, dict) else ""
                        display_topic = f"{topic}-{op}" if op else topic
                        return ev, topic, data_hex, decoded, display_topic

                    from concurrent.futures import ThreadPoolExecutor as _TPE
                    if not evs:
                        decoded_evs = []
                    else:
                        with _TPE(max_workers=min(len(evs), 8)) as _ex:
                            decoded_evs = list(_ex.map(_decode_ev, evs))

                    for ev, topic, data_hex, decoded, display_topic in decoded_evs:
                        entry = {
                            "ts":      datetime.now().strftime("%H:%M:%S"),
                            "height":  h,
                            "topic":   display_topic,
                            "decoded": decoded,
                            "data":    data_hex,   # raw hex for highlight matching
                        }
                        dedup_key = (h, ev.get("source",""), topic)
                        if dedup_key not in seen_events:
                            seen_events.add(dedup_key)
                            _log_event(entry)
                            events_found += 1
                            _log(f"[poller] block={h}  {display_topic}")
                except Exception as e:
                    _poller_errors.append({"ts": datetime.now().isoformat(),
                                           "block": h, "error": str(e)})
                    _log(f"[poller] ERROR block={h}: {e}")
                last = h
                if is_backfilling:
                    _backfill_progress["done"] = blocks_scanned
                    # Rate-limit during backfill to avoid testnet throttling
                    time.sleep(0.15)
            if is_backfilling and blocks_scanned > 0:
                _backfill_progress.update({"done": blocks_scanned, "running": False})
                _log(f"[poller] scan done: {blocks_scanned} blocks, {events_found} events")
        except Exception as e:
            _poller_errors.append({"ts": datetime.now().isoformat(),
                                   "error": f"fetch_tip failed: {e}"})
        time.sleep(4)


def _start_poller(backfill: int = 0):
    global _poller_running
    if not _poller_running:
        _poller_running = True
        t = threading.Thread(target=_sozu_poller, kwargs={"backfill": backfill}, daemon=True)
        t.start()


@app.route("/api/events/stream")
def events_stream():
    """SSE endpoint — streams new SOZU events to the browser."""
    _start_poller(backfill=int(cfg("backfill_blocks") or 200))

    def generate():
        with _event_log_lock:
            cursor = len(_event_log)
        yield ": connected\n\n"
        heartbeat = 0
        while True:
            time.sleep(1)
            with _event_log_lock:
                new_entries = _event_log[cursor:]
                cursor = len(_event_log)
            out = ""
            for entry in new_entries:
                out += f"data: {json.dumps(entry)}\n\n"
            heartbeat += 1
            if heartbeat >= 5:
                heartbeat = 0
                out += ": ping\n\n"
            if out:
                yield out

    return Response(stream_with_context(generate()),
                    mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no",
                             "Transfer-Encoding": "chunked"})


@app.route("/api/events/backfill", methods=["POST"])
def events_backfill():
    """
    Trigger a backfill scan of the last N blocks.
    Body: { "blocks": 100 }
    If poller is already running, restarts it with the given backfill window.
    """
    global _poller_running
    data   = request.get_json() or {}
    blocks = int(data.get("blocks", 100))
    blocks = max(1, min(blocks, 5000))  # cap at 5000

    # stop existing poller
    _poller_running = False
    time.sleep(0.5)

    # restart with backfill
    _start_poller(backfill=blocks)
    return jsonify({"ok": True, "backfill": blocks})


@app.route("/api/events/history", methods=["GET","POST"])
def events_history():
    """Return recent events newest-first."""
    with _event_log_lock:
        return jsonify(list(reversed(_event_log[-200:])))


@app.route("/api/events/errors", methods=["GET","POST"])
def events_errors():
    """Return poller error log for debugging."""
    return jsonify({"errors": list(_poller_errors)})


@app.route("/api/events/probe", methods=["GET","POST"])
def events_probe():
    """
    Raw GraphQL probe for debugging backfill.
    GET /api/events/probe            → probes the current tip block
    GET /api/events/probe?height=N   → probes block N
    Returns raw event count, matched count, sample source values.
    """
    import urllib.request as _ur, json as _j
    height = request.args.get("height")
    out = {"contract_id": CONTRACT_ID}
    try:
        if not height:
            q = '{ block(height: -1) { header { height } } }'
            req = _ur.Request(GRAPHQL_URL, data=q.encode(),
                              headers={"rusk-version": RUSK_VERSION, "Content-Type": "application/graphql"},
                              method="POST")
            with _ur.urlopen(req, timeout=6) as r:
                p = _j.loads(r.read())
            b = p.get("block") or p.get("data", {}).get("block", {})
            height = b["header"]["height"]
        height = int(height)
        out["height"] = height

        q2 = f'{{ contractEvents(height: {height}) {{ json }} }}'
        req2 = _ur.Request(GRAPHQL_URL, data=q2.encode(),
                           headers={"rusk-version": RUSK_VERSION, "Content-Type": "application/graphql"},
                           method="POST")
        with _ur.urlopen(req2, timeout=8) as r:
            raw = r.read()
        try:
            parsed = _j.loads(raw)
        except Exception:
            out["error"] = "non-JSON response"
            out["raw_preview"] = raw[:400].decode("utf-8", errors="replace")
            return jsonify(out)

        ce    = parsed.get("contractEvents") or (parsed.get("data") or {}).get("contractEvents") or {}
        items = ce.get("json", []) if isinstance(ce, dict) else (ce if isinstance(ce, list) else [])
        all_sources = list({(ev.get("source","") if isinstance(ev,dict) else "?") for ev in items[:20]})
        matched = [ev for ev in items
                   if isinstance(ev, dict) and ev.get("source","").lower() == CONTRACT_ID.lower()]

        out.update({
            "ok":             True,
            "total_events":   len(items),
            "matched":        len(matched),
            "all_sources":    all_sources,
            "matched_events": matched,
        })
    except Exception as e:
        out["ok"]    = False
        out["error"] = str(e)
    return jsonify(out)


@app.route("/api/events/debug", methods=["GET","POST"])
def events_debug():
    """Debug: fetch tip and one block of events right now."""
    import urllib.request as ur, json as j
    out = {}
    try:
        q = '{ block(height: -1) { header { height } } }'
        req = ur.Request(GRAPHQL_URL, data=q.encode(),
                         headers={"rusk-version": RUSK_VERSION,
                                  "Content-Type": "application/graphql"},
                         method="POST")
        with ur.urlopen(req, timeout=8) as r:
            out["tip_raw"] = j.loads(r.read())
    except Exception as e:
        out["tip_error"] = str(e)

    try:
        height = out.get("tip_raw", {}).get("block", {}).get("header", {}).get("height")
        if height:
            q2 = f'{{ contractEvents(height: {height}) {{ json }} }}'
            req2 = ur.Request(GRAPHQL_URL, data=q2.encode(),
                              headers={"rusk-version": RUSK_VERSION,
                                       "Content-Type": "application/graphql"},
                              method="POST")
            with ur.urlopen(req2, timeout=8) as r:
                out["events_raw"] = j.loads(r.read())
    except Exception as e:
        out["events_error"] = str(e)

    out["poller_running"] = _poller_running
    out["log_size"] = len(_event_log)
    out["recent_errors"] = list(_poller_errors)
    return jsonify(out)


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    _load_config()  # ensure config is fresh before reading backfill_blocks
    backfill_n = int(cfg('backfill_blocks') or 200)
    print(f"  Provisioner Manager API  →  http://localhost:{PORT}")
    print(f"  Wallet: {WALLET_PATH}  |  Network: {NETWORK}")
    print(f"  Contract: {CONTRACT_ID[:20]}…")
    print(f"  Backfill: {backfill_n} blocks  |  Config: {_CONFIG_PATH}")
    _start_poller(backfill=backfill_n)
    app.run(host="0.0.0.0", port=PORT, threaded=True, debug=False)
