# BLE aggregator (sniff_zmq)

Laptop-side aggregator and device-identification modules for a distributed
BLE sniffer: one or more Raspberry Pi + CC2540 sniffers or hci or sniffle 
(one per advertising channel: 37, 38, 39), each publishing its packets as JSON over a ZeroMQ PUBsocket. `ble_aggregator.py` merges all feeds into a single deduplicated live dashboard in your browser; `ble_identify.py` gives unnamed devices a
human-readable label (vendor, device type, Apple Continuity frame types).

## Architecture

```
Pi + CC2540 (ch37) ── tcp://pi1:5555 ─┐
Pi + CC2540 (ch38) ── tcp://pi2:5555 ─┼──> ble_aggregator.py ── WebSocket ──> browser dashboard
Pi + CC2540 (ch39) ── tcp://pi3:5555 ─┘         │
                                                └── ble_identify.py (vendor / Apple Continuity)
```

## Files

| File                     | Purpose                                                                                 |
| ------------------------ | --------------------------------------------------------------------------------------- |
| `ble_aggregator.py`      | ZMQ subscriber, deduplicated state, HTTP/WebSocket dashboard, RSSI calibration          |
| `ble_identify.py`        | Stateless per-packet device identification (company IDs + Apple Continuity)             |
| `manufacturer_loader.py` | Loads the Bluetooth SIG company-ID table from YAML/JSON (imported by `ble_identify.py`) |
| `index.html`             | Dashboard frontend served at `/`                                                        |
| `esp32_ref_beacon.ino`   | Reference beacon firmware used for RSSI calibration                                     |
| `ble_calibration.json`   | Written/loaded calibration file (per source+channel offset/slope)                       |

## Requirements

```
pip install pyzmq aiohttp --break-system-packages
```

For full vendor coverage, fetch the company-ID database and drop one of these
in the working directory (or point an env var at it):

- `company_identifiers.yaml` (Bluetooth SIG YAML export), or
- `company_ids.json` (NordicSemiconductor/bluetooth-numbers-database export)

Without one, `ble_identify.py` falls back to a tiny built-in table
(Apple, Microsoft, Google, Samsung) and logs a warning.

Company-ID file search order:

1. `$BLE_COMPANY_IDS_YAML` (explicit path, YAML)
2. `$BLE_COMPANY_IDS_JSON` (explicit path, JSON)
3. `./company_identifiers.yaml`
4. `./company_ids.json`

## Quick start

```
python3 ble_aggregator.py \
    --source tcp://192.168.1.101:5555 \
    --source tcp://192.168.1.102:5555 \
    --source tcp://192.168.1.103:5555 \
    --http-port 8000
```

Then open `http://localhost:8000/`.

## What the dashboard shows

- **Devices**: one entry per BD ADDR, updated in place: advertised name,
  RSSI (raw and calibrated), TX power, channels seen, last-seen time, and
  vendor / device type / Apple Continuity frame types guessed from the
  Manufacturer Specific Data when there is no advertised name
  (e.g. `iPhone/iPad(nearby)`, `Mac(findmy)`).
- **Connections**: one entry per CONNECT_REQ access address: initiator and
  advertiser (resolved back to their advertised names), hop/channel-map
  recipe, and a lifecycle state:
  - `seen`: only the CONNECT_REQ was heard
  - `following`: a Sniffle instance is following it onto the data channels
    (kept alive by `conn_data` heartbeats; shows `quiet` after 5 s of silence)
  - `ended`: Sniffle stopped following (kept greyed out for `--ended-ttl`)
- **Scans**: SCAN_REQ / SCAN_RSP pairs between scanner and advertiser.

Stale entries are aged out automatically. A *followed* connection uses
`--followed-ttl` (reset by every heartbeat) instead of `--connection-ttl`, so
it survives as long as Sniffle keeps following it, not just 120 s from the
initial CONNECT_REQ.

## Message events

The aggregator consumes these JSON events from each sniffer feed:

| Event                   | Notes                                                                                              |
| ----------------------- | -------------------------------------------------------------------------------------------------- |
| `adv`                   | Advertisement: `adv_addr`, `name`, `rssi`, `channel`, `tx_power`, `manufacturer`, `service_data`   |
| `connect_req`           | CONNECT_IND: `access_address`, `connect.init_addr` / `adv_addr`                                    |
| `conn_data`             | Heartbeat from the Sniffle instance following a connection (with `stats`, incl. per-endpoint RSSI) |
| `conn_end`              | Sniffle stopped following (`reason`)                                                               |
| `scan_req` / `scan_rsp` | Scanning activity                                                                                  |

Messages with `crc_ok: false` are dropped before they touch state, so a
corrupted address never appears as a brand-new device.

**Note for the publisher:** to get vendor/device-type/frame-type info, the
publisher must include a `manufacturer` field: the hex string (or bytes) of
the Manufacturer Specific Data AD *value*, i.e. company ID bytes plus
payload, NOT including the AD length/type prefix. That is the only upstream
change needed; everything else is handled here.

## Command-line options

```
--source URL            ZMQ PUB endpoint; repeat once per sniffer (required)
--http-port PORT        Dashboard port (default 8000)
--device-ttl SEC        Device dropped after this much silence (default 60)
--connection-ttl SEC    Unfollowed connection TTL (default 120)
--scan-ttl SEC          Scan edge TTL (default 5)
--followed-ttl SEC      Heartbeat timeout for followed connections (default 20)
--ended-ttl SEC         How long an ended connection stays visible (default 30)
--debug, -d             Log every incoming ZMQ message with addresses and raw JSON
```

## RSSI calibration

Every sniffer has a different RSSI offset/gain. A calibration file maps each
`(source, channel)` onto one common RSSI scale:

```
corrected = (raw - offset) / slope
```

The raw value is always kept (`rssi_raw`, `rssi_by_source`); the device's
`rssi` is the corrected value, combined over all sources that heard it within
`--rssi-window` seconds (`--combine median|mean|max|latest`, default median).

Calibrate with the ESP32 reference beacon (`esp32_ref_beacon.ino`):

1. Put all sniffers in a tight cluster (same antenna orientation as
   deployed), ESP32 1-3 m away in line of sight, all sniffers tuned to the
   SAME channel.

2. Run:
   
   ```
   python3 ble_aggregator.py --source ... --calibrate 90
   ```
   
   and step the ESP32 through its TX power levels with `BTN_POWER`
   (at least 3 levels spanning at least 6 dB, all inside every radio's
   linear range). This writes `ble_calibration.json` and prints a report.
   
   Or do the same interactively through the HTTP API:
   
   ```
   POST /api/cal/start    start collecting samples
   POST /api/cal/stop     stop collecting
   POST /api/cal/fit      fit (accepts reference, ref_channel, min_samples, slope, ...)
   POST /api/cal/apply    activate and save the pending calibration
   GET  /api/cal          current status / progress
   POST /api/cal/enable?on=0|1   temporarily bypass calibration (raw RSSI)
   POST /api/cal/clear    drop the active calibration in memory (file untouched)
   ```

3. Optionally repeat with the sniffers on their deployed channels while one
   reference sniffer is retuned across 37/38/39, to capture per-channel
   offsets.

4. Run normally; `ble_calibration.json` is loaded automatically.

Extra calibration options: `--calibration FILE`, `--no-calibration`,
`--cal-reference SOURCE`, `--cal-ref-channel CH`, `--cal-min-samples N`
(default 30), `--cal-no-slope` (offset only), `--cal-rssi-range LO HI`
(default -100 -30 dBm), `--cal-beacon-addr MAC` (recommended: restrict
calibration packets to your beacon).

The fitter maps all sources onto the scale of a reference source (default:
the one with the most samples) on its busiest channel, chains every other
source through the reference on the same channel, and adds a per-source
fallback entry for uncalibrated channels. It warns about large offsets,
high residuals, and sources that ended up with no entry.

## HTTP endpoints

| Endpoint        | Description                                        |
| --------------- | -------------------------------------------------- |
| `/`             | Dashboard (serves `index.html`)                    |
| `/ws`           | WebSocket: full JSON snapshot a few times a second |
| `/api/cal`      | Calibration status (GET)                           |
| `/api/cal/start | stop                                               |

## Dashboard state model

- Devices and connections expire after their TTLs; endpoints of a live
  connection are protected from expiry so the connection edge is never
  dangling.
- Identities (name, label, vendor, device type, frame types) survive device
  expiry in an LRU cache (5000 entries), so a device that reappears, or one
  known only from a CONNECT_REQ, still shows its name.
- A monotonically increasing version counter lets the frontend tell "nothing
  changed" from "changed but values happen to match"; it is also nudged when
  a connection flips between `following` and `quiet` without a new message.

## Identification details (`ble_identify.py`)

Stateless module: it decodes one advertisement and returns what it found.
Called per packet by the aggregator; it keeps no per-MAC memory of its own.

- **Company ID**: first 2 bytes of the Manufacturer Specific Data AD value,
  little-endian, resolved against the Bluetooth SIG assigned-numbers table
  (see file search order above).
- **Apple Continuity** (company ID `0x004C`): the byte after the company ID
  is a Continuity message type, reverse-engineered by the furiousMAC project
  and the "Handoff All Your Privacy" paper (Martin et al., PETS 2019).
  Recognised types include iBeacon, AirPrint, AirDrop, HomeKit, AirPods
  proximity pairing, Hey Siri, AirPlay, Handoff, tethering presence, Nearby
  Action/Info, Find My.
- **Nearby Info (0x10)**: the low nibble of the first data byte is an action
  code (idle, driving, on a call, screen on, ...); the second byte is
  heuristically mapped to an OS hint (iOS 10-13, macOS, watchOS) and Wi-Fi
  state.
- **Nearby Action (0x0F)**: the action-type byte is mapped to activities
  (iOS setup, Apple Pay, watch setup, ...).

Return shape from `identify(name=..., manufacturer=...)`:

```json
{
  "vendor": "Apple",
  "device_type": "iPhone/iPad",
  "frame_types": ["nearby", "findmy"],
  "label": "iPhone/iPad(nearby,findmy)"
}
```

Self-test:

```
python3 ble_identify.py
```

## Troubleshooting

- **No vendor info at all**: the publisher is not sending the `manufacturer`
  field, or no company-ID data file was found (check the startup warning).
- **Devices appear/disappear rapidly**: raise `--device-ttl`; check that all
  sniffers are actually publishing (run with `--debug`).
- **Connections drop right after connecting**: raise `--followed-ttl` above
  the connection interval.
- **RSSI values jump between sources**: run the calibration procedure above,
  or lower `--rssi-window`.

## Licence

Copyright (c) 2026 Vincent Demanet. Licensed under the EUPL, Version 1.2 or
later. See https://joinup.ec.europa.eu/software/page/eupl.