# blette.py

Multi-dongle BLE (Bluetooth Low Energy) advertising capture with deduplication, PCAP logging, and ZMQ forwarding.

The script listens on up to three HCI adapters (`hci0`, `hci1`, `hci2`), each nominally assigned to one BLE advertising channel (37, 38, 39). Since the same advertisement is typically heard on all three channels, a sliding-window deduplicator removes repeats before the packet is written to a PCAP file and published over ZeroMQ.

## Features

- Capture BLE advertising events from multiple HCI dongles concurrently (asyncio).
- Deduplicate packets seen on multiple channels using a fingerprint (MAC address + raw HCI payload, RSSI excluded) within a configurable time window.
- Write unique packets to a PCAP file using link type `BLUETOOTH_HCI_H4_WITH_PHDR` (201), with a 4-byte direction pseudo-header (received frames).
- Publish deduplicated packets over ZMQ (PUB socket) as single-frame JSON messages compatible with `ble_aggregator.py`.
- Parse HCI LE Advertising Report events (0x3E / subevent 0x02) into structured fields: PDU type, advertiser address, RSSI, device name, manufacturer data, TX power, service data, and service UUIDs.
- Periodic statistics logging (totals, unique, duplicates, per-device counts).

## Requirements

- Linux with BlueZ and raw HCI access (root or `CAP_NET_RAW` / appropriate capabilities).
- Python 3.8+
- Python packages:
  - `aioblescan`
  - `pyzmq`

```bash
pip install aioblescan pyzmq
```

## Hardware setup

Attach one USB BLE dongle per advertising channel and identify them:

```bash
hciconfig -a
```

Make sure the interfaces are down and not managed by BlueZ before starting the script:

```bash
sudo hciconfig hci0 down
sudo hciconfig hci1 down
sudo hciconfig hci2 down
```

## Usage

```bash
sudo python3 blette.py [options]
```

Run the capture (default devices `hci0 hci1 hci2`):

```bash
sudo python3 blette.py
```

Options:

| Option | Default | Description |
| --- | --- | --- |
| `--devices` | `hci0 hci1 hci2` | Space-separated list of HCI devices to use |
| `--pcap` | `ble_capture_YYYYmmdd_HHMMSS.pcap` | Output PCAP file |
| `--zmq` | `tcp://127.0.0.1:5555` | ZMQ PUB endpoint |
| `--window` | `2.0` | Deduplication window in seconds |
| `--subscribe` | off | Run only as a ZMQ subscriber (for testing output) |

Example with two dongles and a custom file:

```bash
sudo python3 blette.py --devices hci0 hci1 --pcap capture.pcap --window 1.5
```

Test the ZMQ stream in another terminal:

```bash
sudo python3 blette.py --subscribe
```

## ZMQ message format

The publisher sends a single JSON string per unique packet (no topic prefix, no multipart). Example advertisement message:

```json
{
  "event": "adv",
  "ts": 1730000000.123,
  "source": "hci0",
  "channel": 37,
  "adv_addr": "aa:bb:cc:dd:ee:ff",
  "rssi": -72,
  "pdu_type": "ADV_IND",
  "tx_addr_random": true,
  "crc_ok": true,
  "name": "Sensor",
  "manufacturer": "4c0001...",
  "tx_power": -12,
  "service_data": "16...",
  "service_uuids": ["180f"]
}
```

Optional event types:

- `scan_req`: includes `scanner_addr` and `adv_addr` (the advertised target).
- `scan_rsp`: scan response with optional `name`, `manufacturer`, `service_uuids`, `service_data`.
- `connect_req`: connection request with `adv_addr` and `rssi`.

Optional fields are omitted when absent.

## Architecture

- `ProductionBLECapture`: main class; starts one capture task and one queue-processing task per HCI device, plus a stats loop.
- `BLECaptureProtocol`: subclass of `aiobs.BLEScanRequester`; decodes each HCI event, extracts RSSI and peer address, and queues a `BLEPacket`.
- `PacketDeduplicator`: sliding-window deduplication keyed on a SHA-256 fingerprint (address + payload, RSSI stripped so the same packet heard on different channels matches). Entries expire after the window; the table is capped at 10,000 entries.
- `PCAPWriter`: writes the global header and per-packet records (direction pseudo-header + raw HCI frame).
- `parse_le_advertising_report()`: low-level parser for the LE Advertising Report HCI event.
- `ZMQSubscriber`: simple example subscriber that prints received messages.

## Notes and limitations

- Fixed per-dongle channels are only nominal: standard HCI scan commands do not pin a dongle to a single advertising channel; the kernel/controller still hops across 37/38/39. Deduplication handles the resulting overlap.
- Non-advertising HCI events are counted but not forwarded over ZMQ.
- Packets whose queues are full are dropped (queue size 5,000 per device).
- Running two instances on the same ZMQ endpoint will fail to bind; stop one first.
- `SIGINT`/`SIGTERM` trigger a graceful shutdown (PCAP flush/close, socket teardown).

## Troubleshooting

- **No packets captured**: check the interfaces exist, are down, and that you run as root.
- **PCAP unreadable in Wireshark**: the file uses link type 201 (HCI H4 with pseudo-header); open it with Wireshark's "Bluetooth HCI UART" framing (this is the default for that link type).
- **ZMQ receive fails with JSON errors**: make sure the consumer uses `recv_string()` + `json.loads()` on a single frame, not multipart topics.