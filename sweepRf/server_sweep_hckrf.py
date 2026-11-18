"""
BLE Workshop – SDR Spectrum + BLE Packet WebSocket server

Run:
  pip install fastapi uvicorn pyzmq
  python server.py [--bin-width 2] [--port 8080]
"""

import asyncio, json, struct, time, argparse, random
from pathlib import Path
from typing import Optional

import zmq, zmq.asyncio
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
import uvicorn

# ---------------------------------------------------------------------------
# CLI args
# ---------------------------------------------------------------------------
_parser = argparse.ArgumentParser(add_help=False)
_parser.add_argument("--host",       default="0.0.0.0")
_parser.add_argument("--port",       type=int, default=8080)
_parser.add_argument("--bin-width",  type=float, default=0.25,
                     help="hackrf_sweep bin width in KHz... actually MHz (e.g. 1, 0.5, 2)")
_parser.add_argument("--freq-start", type=int, default=2398)
_parser.add_argument("--freq-stop",  type=int, default=2484)
_parser.add_argument("--zmq-ep",     default="tcp://localhost:5555")
_parser.add_argument("--no-zmq",     action="store_true")
_parser.add_argument("--sniffer-ts", action="store_true", default=True)
_known, _ = _parser.parse_known_args()
ARGS = _known

FREQ_START_HZ = ARGS.freq_start * 1_000_000
FREQ_STOP_HZ  = ARGS.freq_stop  * 1_000_000
BIN_WIDTH_HZ  = int(ARGS.bin_width  * 1_000_000)
ZMQ_ENDPOINT  = ARGS.zmq_ep

# ---------------------------------------------------------------------------
# BLE channel map
# ---------------------------------------------------------------------------
def ble_chan_to_mhz(ch):
    if ch == 37: return 2402
    if ch == 38: return 2426
    if ch == 39: return 2480
    if ch <= 10: return 2404 + ch * 2
    return 2428 + (ch - 11) * 2

BLE_CHAN_FREQ = {ch: ble_chan_to_mhz(ch) for ch in range(40)}

# ---------------------------------------------------------------------------
# App + WebSocket hub
# ---------------------------------------------------------------------------
app = FastAPI()
clients: list[WebSocket] = []

async def broadcast(msg: dict):
    dead, data = [], json.dumps(msg)
    for ws in clients:
        try:    await ws.send_text(data)
        except: dead.append(ws)
    for ws in dead:
        if ws in clients: clients.remove(ws)

def config_msg():
    return {
        "type":           "config",
        "freq_start_mhz": FREQ_START_HZ / 1e6,
        "freq_stop_mhz":  FREQ_STOP_HZ  / 1e6,
        "bin_width_mhz":  BIN_WIDTH_HZ  / 1e6,
        #"bin_width_mhz":  BIN_WIDTH_HZ  / 1e3,
        "ble_channels":   {str(k): v for k, v in BLE_CHAN_FREQ.items()},
    }

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    clients.append(ws)
    await ws.send_text(json.dumps(config_msg()))
    try:
        while True: await ws.receive_text()
    except WebSocketDisconnect:
        if ws in clients: clients.remove(ws)

# ---------------------------------------------------------------------------
# hackrf_sweep reader
#
# hackrf_sweep text format (one line per tuner step, ~8 MHz wide each):
#   date, time, hz_low, hz_high, bin_width, num_samples, db0, db1, ...
#
# For a 2398-2500 MHz sweep the tool steps through several 8 MHz chunks.
# Each sweep pass covers the full band; the SAME hz_low reappears once
# the tool loops back.  We detect a new sweep when we see hz_low equal
# to the very first hz_low we recorded (i.e. it has wrapped around),
# NOT by looking for hz_low < prev_hz_low which can fail if the band
# fits in one chunk or if there is only one step.
# ---------------------------------------------------------------------------
async def hackrf_task():
    cmd = [
        "hackrf_sweep",
        "-f", f"{FREQ_START_HZ//1_000_000}:{FREQ_STOP_HZ//1_000_000}",
        "-w", str(BIN_WIDTH_HZ),
    ]
    print(f"[hackrf] {' '.join(cmd)}", flush=True)
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    except FileNotFoundError:
        print("[hackrf] not found – DEMO mode", flush=True)
        await hackrf_demo_task()
        return

    accumulator: dict[float, float] = {}
    first_hz_low: Optional[float] = None   # hz_low of the very first line in a sweep
    in_sweep = False

    while True:
        raw = await proc.stdout.readline()
        if not raw:
            break
        line = raw.decode("utf-8", errors="ignore").strip()
        if not line:
            continue
        parts = line.split(", ")
        if len(parts) < 7:
            continue
        try:
            hz_low    = float(parts[2])
            bin_width = float(parts[4])
            db_values = [float(v) for v in parts[6:]]
        except ValueError:
            continue

        # Detect sweep boundary: hz_low returned to (approximately) the first
        # frequency we saw, meaning a new sweep has started.
        if first_hz_low is None:
            first_hz_low = hz_low
            in_sweep = True
        elif abs(hz_low - first_hz_low) < bin_width * 0.5 and accumulator:
            # Flush the completed sweep
            sorted_bins = sorted(accumulator.items())
            await broadcast({
                "type": "sweep",
                "ts":   time.time(),
                "bins": sorted_bins,   # list of [freq_mhz, db]
            })
            accumulator = {}

        # Accumulate bins for this line
        for i, db in enumerate(db_values):
            freq_mhz = (hz_low + bin_width * (i + 0.5)) / 1e6
            if FREQ_START_HZ/1e6 <= freq_mhz <= FREQ_STOP_HZ/1e6:
                accumulator[round(freq_mhz, 3)] = round(db, 1)


# ---------------------------------------------------------------------------
# Demo mode (no HackRF)
# ---------------------------------------------------------------------------
async def hackrf_demo_task():
    freq_start = FREQ_START_HZ / 1e6
    freq_stop  = FREQ_STOP_HZ  / 1e6
    bin_w      = BIN_WIDTH_HZ  / 1e6
    #bin_w      = BIN_WIDTH_HZ  / 1e3
    freqs = []
    f = freq_start + bin_w / 2
    while f < freq_stop:
        freqs.append(round(f, 3))
        f += bin_w

    print(f"[demo] {len(freqs)} bins, {bin_w} MHz each", flush=True)

    while True:
        bins = []
        for freq in freqs:
            db = -85.0 + random.gauss(0, 2.5)
            for wc in (2412, 2437, 2462):
                d = abs(freq - wc)
                if d < 12: db += max(0, 28 - d*2.3) * (0.8 + 0.2*random.random())
            for af in (2402, 2426, 2480):
                if abs(freq - af) < bin_w * 1.5 and random.random() < 0.15:
                    db += random.uniform(18, 32)
            bins.append([freq, round(db, 1)])

        await broadcast({"type": "sweep", "ts": time.time(), "bins": bins})
        await asyncio.sleep(0.12)

        if random.random() < 0.07:
            ch = random.choice([37, 38, 39, 37, 38, 39] + list(range(10)))
            aa = random.choice([0x8E89BED6, 0x5A3F2B1C, 0x7E2A9D4F, 0x3C8B1E7A])
            await broadcast({
                "type": "ble_packet", "ts": time.time(),
                "channel": ch, "freq_mhz": BLE_CHAN_FREQ[ch],
                "aa": f"0x{aa:08X}",
            })

# ---------------------------------------------------------------------------
# ZMQ BLE receiver
# ---------------------------------------------------------------------------
async def zmq_task():
    ctx  = zmq.asyncio.Context()
    sock = ctx.socket(zmq.SUB)
    sock.connect(ZMQ_ENDPOINT)
    sock.setsockopt(zmq.SUBSCRIBE, b"")
    print(f"[zmq] connected to {ZMQ_ENDPOINT}", flush=True)
    while True:
        try:
            raw = await sock.recv()
        except Exception as e:
            print(f"[zmq] {e}", flush=True)
            await asyncio.sleep(0.1)
            continue
        try:
            if ARGS.sniffer_ts and len(raw) >= 13:
                ts_us   = struct.unpack_from("<Q", raw, 0)[0]
                channel = raw[8]
                aa_int  = struct.unpack_from("<I", raw, 9)[0]
                pdu     = raw[13:]
                ts_wall = ts_us / 1e6
            else:
                if len(raw) < 5: continue
                channel = raw[0]
                aa_int  = struct.unpack_from("<I", raw, 1)[0]
                pdu     = raw[5:]
                ts_wall = time.time()
            if channel > 39: continue
            aa = f"0x{aa_int:08X}"
            await broadcast({
                "type": "ble_packet", "ts": ts_wall,
                "channel": channel, "freq_mhz": BLE_CHAN_FREQ[channel], "aa": aa,
            })
        except Exception as e:
            print(f"[zmq] parse: {e}", flush=True)

# ---------------------------------------------------------------------------
# Frontend
# ---------------------------------------------------------------------------
HTML_FILE = Path(__file__).parent / "index.html"

@app.get("/")
async def ui():
    return HTMLResponse(HTML_FILE.read_text())

@app.on_event("startup")
async def startup():
    asyncio.create_task(hackrf_task())
    if not ARGS.no_zmq:
        asyncio.create_task(zmq_task())

if __name__ == "__main__":
    print(f"[server] http://{ARGS.host}:{ARGS.port}  bin={ARGS.bin_width}MHz  "
          f"{ARGS.freq_start}–{ARGS.freq_stop}MHz", flush=True)
    uvicorn.run("server:app", host=ARGS.host, port=ARGS.port, reload=False)