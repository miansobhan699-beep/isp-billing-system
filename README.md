# NetFlow VSOL Multi-OLT Monitoring Adapter

This project includes a read-only VSOL/BDCOM-compatible EPON monitoring adapter and the NetFlow dashboard in the same application.

## What it does

- Multiple OLTs
- SNMP v2c read-only telemetry
- OLT system name/description/object ID/uptime
- PON inventory and status
- Active/inactive ONU counts per PON when exposed by the OLT MIB
- ONU MAC/LLID, status, PON, distance, alive time
- ONU RX/TX optical power when exposed by the OLT MIB
- Dashboard API: `/api/health`, `/api/olts`, `/api/olts/{id}/live`
- No SNMP SET, reboot, reset, registration, VLAN, bandwidth or configuration operations are implemented
- Short server-side telemetry cache to avoid hammering the OLT

## Install

Python 3.10+ is recommended.

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# Linux/macOS: source .venv/bin/activate
pip install -r adapter/requirements.txt
```

## Run

Windows: double-click `adapter/start.bat`.

Linux/macOS:

```bash
./adapter/start.sh
```

Then open `http://127.0.0.1:8080/`.

## Add an OLT

Use **Device Management → Add OLT**. The dashboard sends the SNMP read-only settings to this server. The SNMP community is stored in `config/olts.json`, not in the browser's local database.

For a new OLT you need:

- OLT management IP/hostname
- SNMP v2c enabled on the OLT
- a read-only SNMP community
- UDP 161 reachable from this server

The web UI URL is separate; your VSOL web URL can be kept as the management shortcut.

## Security

Do not expose this adapter directly to the public Internet. Put it behind a VPN, firewall, reverse proxy with authentication, or a private management network. You can set `ADAPTER_API_KEY` to require a Bearer token on API calls.

Example:

```bash
# Windows PowerShell
$env:ADAPTER_API_KEY="change-this-long-random-key"
python -m uvicorn adapter.app:app --host 0.0.0.0 --port 8080
```

## VSOL/BDCOM MIB note

The adapter uses numeric OIDs from the NMS-EPON MIB family and is intentionally conservative. Exact availability can vary by VSOL firmware/model. If a specific firmware exposes different OIDs, add a model-specific profile rather than inventing values.
