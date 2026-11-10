#!/usr/bin/env python3
"""
ble_identify.py
----------------

 Copyright (c) 2026, Vincent Demanet

 Licensed under the EUPL, Version 1.2 or - as soon they will be approved
 by the European Commission - subsequent versions of the EUPL (the "Licence");
 You may not use this work except in compliance with the Licence.
 You may obtain a copy of the Licence at:

     https://joinup.ec.europa.eu/software/page/eupl

 Unless required by applicable law or agreed to in writing, software
 distributed under the Licence is distributed on an "AS IS" basis,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the Licence for the specific language governing permissions and
 limitations under the Licence.

Best-effort BLE device identification, used when an advertisement carries
no local name -- e.g. "iPhone (nearby)" or "Mac (findmy)" instead of a
bare MAC address.

Two independent signals are combined, both taken from the Manufacturer
Specific Data AD structure (AD type 0xFF) of the advertisement:

1. Company ID -- the first 2 bytes of the AD value, little-endian. This
   tells you who made the chip/stack (Apple, Samsung, Google, ...).
   Source: Bluetooth SIG assigned numbers
   https://www.bluetooth.com/specifications/assigned-numbers/
   (cross-check / bulk list: https://github.com/NordicSemiconductor/bluetooth-numbers-database)

   The full table is no longer hardcoded here -- it's loaded at import
   time via manufacturer_loader.py, which can read either the SIG-style
   YAML export (company_identifiers.yaml) or a JSON export
   (company_identifiers.json). See `_load_company_ids()` below for the
   search order and how to point it at your own file.

2. For Apple (company ID 0x004C) specifically, the byte right after the
   company ID is an Apple "Continuity" message type -- Nearby Info,
   Find My, AirPods proximity pairing, Handoff, etc. Reverse-engineered
   publicly by the furiousMAC project:
   https://github.com/furiousMAC/continuity
   and the original "Handoff All Your Privacy" paper (Martin et al.,
   PETS 2019): https://arxiv.org/pdf/1904.10600

This module is intentionally stateless -- it decodes a single
advertisement and returns what it found. It keeps no per-MAC memory of
its own (unlike the old apple_bleee-derived script, which kept a global
`phones` dict). The caller (ble_aggregator.py) already owns per-device
state; this module only supplies one extra fact per packet.
"""

from __future__ import annotations
import logging
import os
from typing import Optional, Union

from manufacturer_loader import load_manufacturer_ids, load_manufacturer_ids_json,load_manufacturer_ids_company_ids

logger = logging.getLogger(__name__)

BytesLike = Union[str, bytes, bytearray]

APPLE_COMPANY_ID = 0x004C

# ---------------------------------------------------------------------------
# Fallback table, used only if no company_identifiers.yaml/json can be
# found or parsed. Kept intentionally tiny -- this is a safety net, not
# meant to be extended. Extend the real data file instead (see the
# NordicSemiconductor/bluetooth-numbers-database repo linked above, or the
# official Bluetooth SIG YAML export).
# ---------------------------------------------------------------------------
_FALLBACK_COMPANY_IDS = {
    0x004C: "Apple",
    0x0006: "Microsoft",
    0x00E0: "Google",
    0x0075: "Samsung Electronics",
}


def _load_company_ids() -> dict[int, str]:
    """
    Build the company-ID table via manufacturer_loader.py.

    Search order (first one that loads successfully wins):
      1. $BLE_COMPANY_IDS_YAML  (explicit path, YAML)
      2. $BLE_COMPANY_IDS_JSON  (explicit path, JSON)
      3. ./company_identifiers.yaml  (cwd, YAML -- loader's own default)
      4. ./company_identifiers.json  (cwd, JSON)

    Falls back to _FALLBACK_COMPANY_IDS with a warning if none of the
    above are present/parseable, so this module still works out of the
    box before you've fetched the full list.
    """
    candidates = []
    if os.environ.get("BLE_COMPANY_IDS_YAML"):
        candidates.append(("yaml", os.environ["BLE_COMPANY_IDS_YAML"]))
    if os.environ.get("BLE_COMPANY_IDS_JSON"):
        candidates.append(("json", os.environ["BLE_COMPANY_IDS_JSON"]))
    candidates.append(("yaml", "company_identifiers.yaml"))
    candidates.append(("json", "company_ids.json"))

    for kind, path in candidates:
        try:
            if kind == "yaml":
                table = load_manufacturer_ids(path)
            else:
                #table = load_manufacturer_ids_json(path)
                table=load_manufacturer_ids_company_ids(path)
            if table:
                logger.info("Loaded %d company IDs from %s", len(table), path)
                return table
        except FileNotFoundError:
            continue
        except Exception:
            logger.exception("Failed to parse company ID file %s, skipping", path)
            continue

    logger.warning(
        "No company_identifiers.yaml/json found (checked %s) -- falling back "
        "to a %d-entry built-in table. Fetch the full list from "
        "https://github.com/NordicSemiconductor/bluetooth-numbers-database "
        "and set BLE_COMPANY_IDS_YAML/BLE_COMPANY_IDS_JSON or drop it in the "
        "working directory to get full coverage.",
        [c[1] for c in candidates],
        len(_FALLBACK_COMPANY_IDS),
    )
    return dict(_FALLBACK_COMPANY_IDS)


# Built once at import time. Call reload_company_ids() if the data file
# changes on disk and you want this process to pick it up without a
# restart (e.g. after refreshing company_identifiers.yaml).
COMPANY_IDS: dict[int, str] = _load_company_ids()


def reload_company_ids() -> None:
    """Re-run discovery/loading and refresh the module-level COMPANY_IDS."""
    global COMPANY_IDS
    COMPANY_IDS = _load_company_ids()


# ---------------------------------------------------------------------------
# Apple Continuity message types (the byte after the company ID).
# label = short human tag used for the "frame type" shown in the UI,
# e.g. iPhone(nearby), Mac(findmy).
# ---------------------------------------------------------------------------
APPLE_CONTINUITY_TYPES = {
    0x02: {"key": "ibeacon", "label": "ibeacon"},
    0x03: {"key": "airprint", "label": "airprint"},
    0x05: {"key": "airdrop", "label": "airdrop"},
    0x06: {"key": "homekit", "label": "homekit"},
    0x07: {"key": "airpods", "label": "airpods"},       # Proximity Pairing
    0x08: {"key": "siri", "label": "siri"},              # Hey Siri
    0x09: {"key": "airplay", "label": "airplay"},
    0x0B: {"key": "magic_switch", "label": "magicswitch"},
    0x0C: {"key": "handoff", "label": "handoff"},
    0x0D: {"key": "wifi_set", "label": "wifiset"},        # Tethering Target Presence
    0x0E: {"key": "hotspot", "label": "hotspot"},         # Tethering Source Presence
    0x0F: {"key": "nearby_action", "label": "action"},    # incl. legacy "wifi-join"
    0x10: {"key": "nearby_info", "label": "nearby"},
    0x12: {"key": "find_my", "label": "findmy"},
}

# Nearby Info (0x10) low-nibble "action code" -> user activity.
# https://github.com/furiousMAC/continuity/blob/master/messages/nearby_info.md
NEARBY_ACTIVITY = {
    0x00: "activity unknown",
    0x01: "activity reporting disabled",
    0x03: "idle",
    0x05: "audio playing, locked",
    0x07: "active, screen on",
    0x09: "screen on, video playing",
    0x0A: "watch on wrist, unlocked",
    0x0B: "recent interaction",
    0x0D: "driving",
    0x0E: "on a call",
}

# Nearby Action (0x0F) "action type" byte.
# https://github.com/furiousMAC/continuity/blob/master/messages/nearby_action.md
NEARBY_ACTION_TYPES = {
    0x04: "mobile backup",
    0x05: "watch setup",
    0x06: "apple tv pair",
    0x07: "internet relay",
    0x08: "wifi password",
    0x09: "ios setup",
    0x0A: "repair",
    0x0B: "speaker setup",
    0x0C: "apple pay",
    0x0D: "whole home audio setup",
    0x0E: "developer tools pairing",
    0x0F: "answered call",
    0x10: "ended call",
    0x13: "remote autofill",
    0x14: "companion link proximity",
    0x15: "remote management",
    0x17: "remote display",
}

# Best-effort / observed mapping from the "wifi" byte inside Nearby Info to
# an OS hint + wifi state. Community-sourced (apple_bleee project and
# similar), not from an official spec -- treat as a heuristic, not fact.
_OS_WIFI_CODES = {
    "00": ("iOS10", None),
    "04": ("iOS13", "on"),
    "09": ("macOS", None),
    "0c": ("iOS12", "on"),
    "0e": ("iOS13", "connecting"),
    "10": ("iOS11", None),
    "14": ("macOS", "on"),
    "18": ("iOS12/macOS", "off"),
    "1a": ("iOS13", "off"),
    "1c": ("iOS12/macOS", "on"),
    "1e": ("iOS13", "on"),
    "98": ("watchOS", None),
}


def _hexlify(data: BytesLike) -> bytes:
    if isinstance(data, str):
        data = data.strip()
        return bytes.fromhex(data) if data else b""
    return bytes(data)


def parse_manufacturer_ad(raw: BytesLike):
    """
    raw = the Manufacturer Specific Data AD *value* (company id + payload),
    as a hex string or bytes. Does NOT include the AD length/type prefix.

    Returns (company_id: int | None, payload: bytes).
    """
    data = _hexlify(raw)
    if len(data) < 2:
        return None, b""
    company_id = data[0] | (data[1] << 8)  # little-endian on air
    return company_id, data[2:]


def decode_apple_continuity(payload: bytes):
    """
    payload = bytes after the Apple company ID: one or more concatenated
    Continuity records of the form [type][len][data...].

    Returns a list of dicts, one per record found, e.g.:
      [{"type": 16, "key": "nearby_info", "label": "nearby",
        "activity": "active, screen on", "os": "iOS13", "wifi": "on"}]
    """
    findings = []
    i = 0
    n = len(payload)
    while i + 2 <= n:
        msg_type = payload[i]
        msg_len = payload[i + 1]
        data = payload[i + 2: i + 2 + msg_len]
        if len(data) < msg_len:
            break  # truncated / corrupt tail, stop rather than misparse

        meta = APPLE_CONTINUITY_TYPES.get(msg_type)
        entry = {
            "type": msg_type,
            "key": meta["key"] if meta else f"unknown_0x{msg_type:02x}",
            "label": meta["label"] if meta else f"0x{msg_type:02x}",
        }

        if msg_type == 0x10 and len(data) >= 2:  # Nearby Info
            action_code = data[0] & 0x0F
            entry["activity"] = NEARBY_ACTIVITY.get(action_code)
            os_wifi = _OS_WIFI_CODES.get(f"{data[1]:02x}")
            if os_wifi:
                entry["os"], entry["wifi"] = os_wifi

        elif msg_type == 0x0F and len(data) >= 2:  # Nearby Action
            entry["action"] = NEARBY_ACTION_TYPES.get(data[1], f"0x{data[1]:02x}")

        findings.append(entry)
        i += 2 + msg_len

    return findings


def _guess_apple_device(findings) -> Optional[str]:
    """Rough device-type guess from whichever Continuity records fired.

    We deliberately don't try to tell iPhone from iPad -- Continuity
    doesn't reliably distinguish them. AirPods-style "airpods" pairing
    frames and the Nearby Info OS hint are the two decent signals we have.
    """
    keys = {f["key"] for f in findings}

    if "airpods" in keys:
        return "AirPods/Beats"

    for f in findings:
        if f.get("os") == "watchOS":
            return "Apple Watch"
        if f.get("os") == "macOS":
            return "Mac"
        if f.get("os") and f["os"].startswith("iOS"):
            return "iPhone/iPad"

    if "homekit" in keys:
        return "HomeKit accessory"
    if "airplay" in keys:
        return "Apple TV/AirPlay"

    return "Apple device"


def identify(name: Optional[str] = None, manufacturer: Optional[BytesLike] = None) -> dict:
    """
    Main entry point. Call this per-advertisement with whatever the
    publisher gave you.

      name:         the advertised local name, if any.
      manufacturer: raw hex string/bytes of the Manufacturer Specific Data
                    AD *value* (company id + payload), if any.

    Returns:
      {
        "vendor": "Apple" | "Samsung Electronics" | ... | None,
        "device_type": "iPhone/iPad" | "Apple Watch" | "Samsung Electronics" | None,
        "frame_types": ["nearby", "findmy", ...],
        "label": best short string to show the user instead of a MAC,
      }
    """
    result = {"vendor": None, "device_type": None, "frame_types": [], "label": None}

    if manufacturer:
        company_id, payload = parse_manufacturer_ad(manufacturer)
        if company_id is not None:
            result["vendor"] = COMPANY_IDS.get(company_id)

            if company_id == APPLE_COMPANY_ID:
                findings = decode_apple_continuity(payload)
                result["frame_types"] = [f["label"] for f in findings]
                result["device_type"] = _guess_apple_device(findings)
            elif result["vendor"]:
                result["device_type"] = result["vendor"]

    if name:
        result["label"] = name
    elif result["device_type"]:
        if result["frame_types"]:
            result["label"] = f"{result['device_type']}({','.join(result['frame_types'])})"
        else:
            result["label"] = result["device_type"]

    return result


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    # Quick self-test using the sample bytes from the public ble-spam-analysis
    # write-up: Nearby Action (0x0f) + Nearby Info (0x10) concatenated.
    sample = "4c000f0590 00e1efd2 100501".replace(" ", "")
    # (company 4c00) (0f 05 90 00 e1 ef d2) (10 05 01 ...)
    print(identify(manufacturer=sample))
