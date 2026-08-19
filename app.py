from __future__ import annotations

import asyncio
import base64
import json
import os
import secrets
import socket
import struct
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[1]
CONFIG_DIR = ROOT / "config"
CONFIG_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_FILE = CONFIG_DIR / "olts.json"

DEFAULT_CONFIG = {
    "olts": []
}

# VSOL/BDCOM-compatible EPON MIBs. These are read-only objects used by the adapter.
OID = {
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysObjectID": "1.3.6.1.2.1.1.2.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "ifOperStatus": "1.3.6.1.2.1.2.2.1.8",
    # NMS-EPON-OLT-PON
    "ponTable": "1.3.6.1.4.1.3320.101.6.1.1",
    "ponIndex": "1.3.6.1.4.1.3320.101.6.1.1.1",
    "ponAdmin": "1.3.6.1.4.1.3320.101.6.1.1.9",
    "ponLaser": "1.3.6.1.4.1.3320.101.6.1.1.12",
    "ponData": "1.3.6.1.4.1.3320.101.6.1.1.13",
    "ponActive": "1.3.6.1.4.1.3320.101.6.1.1.21",
    "ponInactive": "1.3.6.1.4.1.3320.101.6.1.1.22",
    # NMS-EPON-ONU
    "onuTable": "1.3.6.1.4.1.3320.101.10.1.1",
    "onuId": "1.3.6.1.4.1.3320.101.10.1.1.3",
    "onuStatus": "1.3.6.1.4.1.3320.101.10.1.1.26",
    "onuDistance": "1.3.6.1.4.1.3320.101.10.1.1.27",
    "onuPon": "1.3.6.1.4.1.3320.101.10.1.1.64",
    "onuAlive": "1.3.6.1.4.1.3320.101.10.1.1.80",
    # NMS-EPON-ONU optical port
    "onuOpticalTable": "1.3.6.1.4.1.3320.101.10.5.1",
    "onuOpticalIndex": "1.3.6.1.4.1.3320.101.10.5.1.1",
    "onuRxPower": "1.3.6.1.4.1.3320.101.10.5.1.5",
    "onuTxPower": "1.3.6.1.4.1.3320.101.10.5.1.6",
    # NMS-EPON-LLID-ONU-BIND
    "bindTable": "1.3.6.1.4.1.3320.101.11.1.1",
    "bindPon": "1.3.6.1.4.1.3320.101.11.1.1.1",
    "bindSeq": "1.3.6.1.4.1.3320.101.11.1.1.2",
    "bindMac": "1.3.6.1.4.1.3320.101.11.1.1.3",
    "bindStatus": "1.3.6.1.4.1.3320.101.11.1.1.6",
    "bindDistance": "1.3.6.1.4.1.3320.101.11.1.1.7",
}

STATUS = {
    0: "authenticated",
    1: "registered",
    2: "deregistered",
    3: "auto_config",
    4: "lost",
    5: "standby",
}
BIND_STATUS = {
    0: "authenticated",
    1: "registered",
    2: "deregistered",
    3: "discovered",
    4: "lost",
    5: "auto_configured",
    255: "unknown",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_config() -> dict[str, Any]:
    if not CONFIG_FILE.exists():
        CONFIG_FILE.write_text(json.dumps(DEFAULT_CONFIG, indent=2))
    try:
        data = json.loads(CONFIG_FILE.read_text())
        if not isinstance(data, dict) or not isinstance(data.get("olts"), list):
            raise ValueError("Invalid config")
        return data
    except Exception:
        return json.loads(json.dumps(DEFAULT_CONFIG))


def save_config(data: dict[str, Any]) -> None:
    tmp = CONFIG_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    tmp.replace(CONFIG_FILE)


def public_olt(item: dict[str, Any]) -> dict[str, Any]:
    out = dict(item)
    for key in ("community", "snmp_password", "snmp_user"):
        if key in out:
            out[key] = "configured" if out[key] else "not configured"
    return out


# ----------------------------- minimal SNMPv2c -----------------------------
# This avoids requiring net-snmp on the host. It intentionally implements only
# read operations (GET and GETBULK), so the adapter cannot write OLT settings.


def ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + ber_len(len(value)) + value


def ber_int(n: int) -> bytes:
    n = int(n)
    if n == 0:
        raw = b"\x00"
    else:
        length = max(1, (n.bit_length() + 7) // 8)
        raw = n.to_bytes(length, "big", signed=True)
        if n >= 0 and raw[0] & 0x80:
            raw = b"\x00" + raw
        while len(raw) > 1 and ((raw[0] == 0 and not raw[1] & 0x80) or (raw[0] == 0xff and raw[1] & 0x80)):
            raw = raw[1:]
    return tlv(0x02, raw)


def ber_null() -> bytes:
    return b"\x05\x00"


def ber_oid(oid: str) -> bytes:
    parts = [int(x) for x in oid.strip(".").split(".")]
    if len(parts) < 2:
        raise ValueError("Bad OID")
    out = bytes([40 * parts[0] + parts[1]])
    for x in parts[2:]:
        if x == 0:
            out += b"\x00"
            continue
        chunks = []
        while x:
            chunks.append(x & 0x7f)
            x >>= 7
        for i, c in enumerate(reversed(chunks)):
            out += bytes([c | (0x80 if i < len(chunks) - 1 else 0)])
    return tlv(0x06, out)


def parse_tlv(data: bytes, pos: int = 0):
    if pos >= len(data):
        raise ValueError("TLV out of range")
    tag = data[pos]
    pos += 1
    first = data[pos]
    pos += 1
    if first & 0x80:
        count = first & 0x7f
        if count == 0 or pos + count > len(data):
            raise ValueError("Invalid BER length")
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    else:
        length = first
    end = pos + length
    if end > len(data):
        raise ValueError("Invalid BER payload length")
    return tag, data[pos:end], end


def parse_oid(raw: bytes) -> str:
    if not raw:
        return ""
    first = raw[0]
    a, b = (0, first) if first < 40 else (1, first - 40) if first < 80 else (2, first - 80)
    vals = [a, b]
    cur = 0
    for byte in raw[1:]:
        cur = (cur << 7) | (byte & 0x7f)
        if not byte & 0x80:
            vals.append(cur)
            cur = 0
    return ".".join(map(str, vals))


def decode_value(tag: int, raw: bytes) -> Any:
    if tag == 0x02:
        return int.from_bytes(raw, "big", signed=True)
    if tag in (0x41, 0x42, 0x43, 0x46):
        return int.from_bytes(raw, "big", signed=False)
    if tag == 0x06:
        return parse_oid(raw)
    if tag == 0x40:
        return ".".join(str(x) for x in raw)
    if tag == 0x04:
        if len(raw) == 6:
            return ":".join(f"{x:02X}" for x in raw)
        try:
            return raw.decode("utf-8").rstrip("\x00")
        except UnicodeDecodeError:
            return raw.hex()
    if tag in (0x80, 0x81, 0x82):
        return None
    if tag == 0x05:
        return None
    return raw.hex()


def parse_response(packet: bytes) -> list[tuple[str, Any, int]]:
    tag, outer, _ = parse_tlv(packet)
    if tag != 0x30:
        raise ValueError("SNMP response is not a sequence")
    p = 0
    _, _, p = parse_tlv(outer, p)  # version
    _, _, p = parse_tlv(outer, p)  # community
    pdu_tag, pdu, p = parse_tlv(outer, p)
    if pdu_tag not in (0xA0, 0xA1, 0xA2, 0xA5):
        raise ValueError(f"Unsupported SNMP PDU 0x{pdu_tag:02x}")
    q = 0
    _, _, q = parse_tlv(pdu, q)  # request id
    _, error_status, q = parse_tlv(pdu, q)
    _, error_index, q = parse_tlv(pdu, q)
    if int.from_bytes(error_status, "big", signed=True) != 0:
        raise RuntimeError(f"SNMP error status {int.from_bytes(error_status, 'big', signed=True)} index {int.from_bytes(error_index, 'big', signed=True)}")
    _, vb_raw, q = parse_tlv(pdu, q)
    varbinds = []
    p = 0
    while p < len(vb_raw):
        _, vb, p = parse_tlv(vb_raw, p)
        q2 = 0
        _, oid_raw, q2 = parse_tlv(vb, q2)
        vtag, vraw, q2 = parse_tlv(vb, q2)
        varbinds.append((parse_oid(oid_raw), decode_value(vtag, vraw), vtag))
    return varbinds


def build_request(community: str, pdu_tag: int, request_id: int, oid: str, max_repetitions: int = 25) -> bytes:
    varbind = tlv(0x30, ber_oid(oid) + ber_null())
    varbind_list = tlv(0x30, varbind)
    if pdu_tag == 0xA5:  # GETBULK
        body = ber_int(request_id) + ber_int(0) + ber_int(max_repetitions) + varbind_list
    else:  # GETNEXT
        body = ber_int(request_id) + ber_int(0) + ber_int(0) + varbind_list
    pdu = tlv(pdu_tag, body)
    return tlv(0x30, ber_int(1) + tlv(0x04, community.encode()) + pdu)


class SNMPClient:
    def __init__(self, host: str, port: int, community: str, timeout: float = 3.0, retries: int = 1):
        self.host = host
        self.port = int(port)
        self.community = community
        self.timeout = float(timeout)
        self.retries = int(retries)

    def request(self, oid: str, bulk: bool = True, max_repetitions: int = 25) -> list[tuple[str, Any, int]]:
        last_error = None
        for _ in range(self.retries + 1):
            rid = secrets.randbelow(2**31 - 1) + 1
            packet = build_request(self.community, 0xA5 if bulk else 0xA1, rid, oid, max_repetitions)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            try:
                sock.sendto(packet, (self.host, self.port))
                data, _ = sock.recvfrom(65535)
                return parse_response(data)
            except Exception as exc:
                last_error = exc
            finally:
                sock.close()
        raise RuntimeError(f"SNMP request failed: {last_error}")

    def get(self, oid: str) -> Any:
        values = self.request(oid, bulk=False)
        return values[0][1] if values else None

    def walk(self, base_oid: str, max_repetitions: int = 25) -> list[tuple[str, Any, int]]:
        result = []
        current = base_oid.strip(".")
        base = current + "."
        for _ in range(100):
            rows = self.request(current, bulk=True, max_repetitions=max_repetitions)
            if not rows:
                break
            advanced = False
            for oid, value, tag in rows:
                if oid == current or not (oid == base_oid.strip(".") or oid.startswith(base)):
                    continue
                result.append((oid, value, tag))
                current = oid
                advanced = True
            if not advanced:
                break
            if len(rows) < max_repetitions:
                break
        return result


def suffix_index(oid: str, base: str) -> str:
    prefix = base.strip(".") + "."
    return oid[len(prefix):] if oid.startswith(prefix) else oid


def column_rows(items: list[tuple[str, Any, int]], table_base: str) -> dict[str, dict[int, Any]]:
    rows: dict[str, dict[int, Any]] = {}
    base = table_base.strip(".") + "."
    for oid, value, _ in items:
        if not oid.startswith(base):
            continue
        suffix = oid[len(base):]
        bits = suffix.split(".")
        if len(bits) < 2:
            continue
        try:
            col = int(bits[0])
        except ValueError:
            continue
        index = ".".join(bits[1:])
        rows.setdefault(index, {})[col] = value
    return rows


def mac(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, str) and ":" in v:
        return v.upper()
    if isinstance(v, bytes):
        return ":".join(f"{x:02X}" for x in v)
    return str(v)


def fmt_uptime(ticks: Any) -> str:
    try:
        sec = int(ticks) / 100
        d = int(sec // 86400); sec -= d * 86400
        h = int(sec // 3600); sec -= h * 3600
        m = int(sec // 60); sec -= m * 60
        return f"{d}d {h}h {m}m {int(sec)}s"
    except Exception:
        return str(ticks or "—")


def status_is_online(v: Any) -> bool:
    try:
        return int(v) in (0, 1, 3, 5)
    except Exception:
        return str(v).lower() in {"registered", "authenticated", "auto_config", "online"}


def normalize_power(v: Any) -> float | None:
    if v is None:
        return None
    try:
        return round(int(v) / 10, 1)
    except Exception:
        return None


async def collect_olt(cfg: dict[str, Any]) -> dict[str, Any]:
    host = cfg.get("host") or cfg.get("ip")
    if not host:
        raise ValueError("OLT host/IP is missing")
    community = cfg.get("community")
    if not community:
        raise ValueError("SNMP read community is not configured")
    client = SNMPClient(host, int(cfg.get("snmp_port", 161)), community, float(cfg.get("timeout", 2.5)), int(cfg.get("retries", 1)))

    sys_name, sys_descr, sys_oid, sys_uptime = await asyncio.gather(
        asyncio.to_thread(client.get, OID["sysName"]),
        asyncio.to_thread(client.get, OID["sysDescr"]),
        asyncio.to_thread(client.get, OID["sysObjectID"]),
        asyncio.to_thread(client.get, OID["sysUpTime"]),
    )

    pon_raw, onu_raw, opt_raw, bind_raw = await asyncio.gather(
        asyncio.to_thread(client.walk, OID["ponTable"]),
        asyncio.to_thread(client.walk, OID["onuTable"]),
        asyncio.to_thread(client.walk, OID["onuOpticalTable"]),
        asyncio.to_thread(client.walk, OID["bindTable"]),
    )

    pon_rows = column_rows(pon_raw, OID["ponTable"])
    onus_rows = column_rows(onu_raw, OID["onuTable"])
    opt_rows = column_rows(opt_raw, OID["onuOpticalTable"])
    bind_rows = column_rows(bind_raw, OID["bindTable"])

    optical = {}
    for idx, row in opt_rows.items():
        optical[idx] = {
            "rxPower": normalize_power(row.get(5)),
            "txPower": normalize_power(row.get(6)),
        }

    bindings = {}
    for idx, row in bind_rows.items():
        bindings[idx] = {
            "pon": row.get(1),
            "seq": row.get(2),
            "mac": mac(row.get(3)),
            "bindStatus": BIND_STATUS.get(int(row.get(6)), str(row.get(6))) if row.get(6) is not None else None,
            "distance": row.get(7),
        }

    onus = []
    for idx, row in onus_rows.items():
        status_value = row.get(26)
        status = STATUS.get(int(status_value), str(status_value)) if status_value is not None else "unknown"
        opt = optical.get(idx, {})
        bind = bindings.get(idx, {})
        pon = row.get(64) or bind.get("pon")
        onus.append({
            "id": idx,
            "llid": idx,
            "serial": mac(row.get(3)),
            "status": "online" if status_is_online(status_value) else "offline",
            "statusDetail": status,
            "pon": pon,
            "distance": row.get(27) if row.get(27) is not None else bind.get("distance"),
            "rxPower": opt.get("rxPower"),
            "txPower": opt.get("txPower"),
            "lastSeen": None,
            "aliveSeconds": row.get(80),
            "bindStatus": bind.get("bindStatus"),
        })

    # If the main ONU table is not exposed by this firmware, binding data still gives useful ONU rows.
    if not onus and bindings:
        for idx, b in bindings.items():
            onus.append({
                "id": idx,
                "llid": idx,
                "serial": b.get("mac") or "",
                "status": "online" if b.get("bindStatus") in {"registered", "authenticated", "discovered", "auto_configured"} else "offline",
                "statusDetail": b.get("bindStatus") or "unknown",
                "pon": b.get("pon"),
                "distance": b.get("distance"),
                "rxPower": optical.get(idx, {}).get("rxPower"),
                "txPower": optical.get(idx, {}).get("txPower"),
                "lastSeen": None,
            })

    ports = []
    for idx, row in sorted(pon_rows.items(), key=lambda x: int(x[0].split(".")[-1]) if x[0].split(".")[-1].isdigit() else x[0]):
        pon_index = row.get(1) or idx.split(".")[-1]
        active = row.get(21)
        inactive = row.get(22)
        oper = None
        try:
            oper = await asyncio.to_thread(client.get, f"{OID['ifOperStatus']}.{pon_index}")
        except Exception:
            pass
        up = str(oper) == "1" or row.get(9) == 1 or row.get(12) == 1 or row.get(13) == 1
        ports.append({
            "name": f"PON {pon_index}",
            "port": pon_index,
            "status": "up" if up else "down",
            "activeOnus": int(active) if isinstance(active, int) else active,
            "inactiveOnus": int(inactive) if isinstance(inactive, int) else inactive,
            "rxPower": None,
        })

    online = sum(1 for x in onus if x.get("status") == "online")
    offline = sum(1 for x in onus if x.get("status") == "offline")

    return {
        "status": "online",
        "source": "VSOL/BDCOM SNMPv2c read-only",
        "updatedAt": utc_now(),
        "model": cfg.get("model") or "VSOL EPON OLT",
        "serial": None,
        "firmware": None,
        "sysName": sys_name,
        "sysDescr": sys_descr,
        "sysObjectID": sys_oid,
        "uptime": fmt_uptime(sys_uptime),
        "ponCount": len(ports),
        "onuTotal": len(onus),
        "onuOnline": online,
        "onuOffline": offline,
        "ports": ports,
        "onus": onus,
        "alarms": [],
        "notes": "Read-only telemetry. No SNMP SET/write operation is implemented.",
    }


class OltInput(BaseModel):
    id: str | None = None
    name: str = Field(min_length=1)
    model: str = "VSOL EPON OLT"
    host: str
    snmp_port: int = 161
    snmp_version: str = "2c"
    community: str | None = None
    timeout: float = 2.5
    retries: int = 1
    web_url: str | None = None
    location: str | None = None
    notes: str | None = None


app = FastAPI(title="NetFlow VSOL Multi-OLT Monitoring Adapter", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

API_KEY = os.getenv("ADAPTER_API_KEY", "")


def check_key(request: Request):
    if not API_KEY:
        return
    auth = request.headers.get("authorization", "")
    if auth != f"Bearer {API_KEY}":
        raise HTTPException(status_code=401, detail="Invalid adapter API key")


@app.get("/api/health")
async def health(request: Request):
    check_key(request)
    return {"ok": True, "service": "netflow-vsol-monitor", "time": utc_now(), "readOnly": True}


@app.get("/api/olts")
async def list_olts(request: Request):
    check_key(request)
    return {"olts": [public_olt(x) for x in load_config()["olts"]]}


@app.post("/api/olts")
async def create_or_update_olt(payload: OltInput, request: Request):
    check_key(request)
    data = load_config()
    item = payload.model_dump()
    item["id"] = payload.id or secrets.token_hex(6)
    existing = next((x for x in data["olts"] if x.get("id") == item["id"]), None)
    if existing:
        if not item.get("community"):
            item["community"] = existing.get("community")
        existing.update(item)
    else:
        if not item.get("community"):
            raise HTTPException(status_code=400, detail="SNMP read community is required for a new OLT")
        data["olts"].append(item)
    save_config(data)
    return {"olt": public_olt(item)}


@app.delete("/api/olts/{olt_id}")
async def delete_olt(olt_id: str, request: Request):
    check_key(request)
    data = load_config()
    before = len(data["olts"])
    data["olts"] = [x for x in data["olts"] if x.get("id") != olt_id]
    if len(data["olts"]) == before:
        raise HTTPException(status_code=404, detail="OLT not found")
    save_config(data)
    return {"ok": True}


_cache: dict[str, tuple[float, dict[str, Any]]] = {}
CACHE_SECONDS = float(os.getenv("TELEMETRY_CACHE_SECONDS", "8"))


@app.get("/api/olts/{olt_id}/live")
async def live_olt(olt_id: str, request: Request, refresh: bool = False):
    check_key(request)
    cfg = next((x for x in load_config()["olts"] if x.get("id") == olt_id), None)
    if not cfg:
        raise HTTPException(status_code=404, detail="OLT not found")
    cached = _cache.get(olt_id)
    if cached and not refresh and time.monotonic() - cached[0] < CACHE_SECONDS:
        return cached[1]
    try:
        data = await collect_olt(cfg)
    except Exception as exc:
        data = {
            "status": "offline",
            "source": "VSOL/BDCOM SNMPv2c read-only",
            "updatedAt": utc_now(),
            "error": str(exc),
            "ponCount": None,
            "onuTotal": None,
            "onuOnline": None,
            "onuOffline": None,
            "ports": [],
            "onus": [],
            "alarms": [],
        }
    _cache[olt_id] = (time.monotonic(), data)
    return data


@app.get("/", include_in_schema=False)
async def index():
    return FileResponse(ROOT / "index.html")


@app.get("/adapter", include_in_schema=False)
async def adapter_page():
    return FileResponse(ROOT / "adapter" / "README.md", media_type="text/plain")
