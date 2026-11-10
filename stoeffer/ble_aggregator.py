#!/usr/bin/env python3
"""
ble_aggregator.py

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
------------------
Laptop-side aggregator for the sniff_zmq distributed BLE sniffer.

Subscribes to one ZMQ PUB feed per sniffer (typically one Raspberry Pi +
CC2540 per advertising channel: 37, 38, 39), merges everything into a
single deduplicated live picture:

  - devices:     one entry per BD ADDR, updated in place (name, rssi,
                 tx power, which channel(s) it's seen on, last-seen time,
                 and now: vendor / device type / Continuity frame types
                 guessed from the manufacturer-specific data, when there
                 is no advertised name to show instead)
  - connections: one entry per CONNECT_REQ access address, holding the
                 initiator/advertiser pair, the hop/channel-map recipe, and
                 (when a Sniffle instance is following the link onto the
                 data channels) a 'state' of seen -> following -> quiet ->
                 ended, kept alive by periodic conn_data heartbeats rather
                 than expiring the moment the initial CONNECT_REQ ages out.
                 init_addr/adv_addr are resolved back to the advertised
                 name of that device (if any) so a connection doesn't just
                 show the access address once the sniffer's radio channel
                 map has moved off the raw advertising channels.

State is pushed to any number of browser tabs over a WebSocket as a full
JSON snapshot, a few times a second. Stale devices/connections are aged
out automatically -- a *followed* connection uses --followed-ttl (reset by
every heartbeat) instead of --connection-ttl, so it survives as long as
Sniffle keeps following it, not just 120s from the initial CONNECT_REQ.

RSSI CALIBRATION (new)
----------------------
Every sniffer has a different RSSI offset/gain.  A calibration file maps each
(source, channel) onto one common RSSI scale:   corrected = (raw - offset)/slope
The raw value is always kept (device['rssi_raw'], device['rssi_by_source']);
device['rssi'] is now the corrected value, combined over all sources that heard
the device within --rssi-window seconds (--combine median|mean|max|latest).

Calibrate with the ESP32 reference beacon (esp32_ref_beacon.ino):
  1. Put all sniffers in a tight cluster (same antenna orientation as deployed),
     ESP32 1-3 m away in line of sight, all sniffers tuned to the SAME channel.
  2. Run   python3 ble_aggregator.py --source ... --calibrate 90
     and step the ESP32 through its TX power levels with BTN_POWER (>= 3 levels,
     spanning >= 6 dB, all inside every radio's linear range) while it runs.
     -> writes ble_calibration.json and prints a report.
     (Or do the same interactively through the HTTP API: POST /api/cal/start,
      /api/cal/stop, /api/cal/fit, /api/cal/apply; GET /api/cal for progress.)
  3. Optionally repeat with the sniffers on their deployed channels while one
     reference sniffer is retuned across 37/38/39, to capture channel offsets
     (the reference source is fitted on every channel it was heard on).
  4. Run normally; ble_calibration.json is loaded automatically.

Usage:
    pip install pyzmq aiohttp --break-system-packages
    python3 ble_aggregator.py \\
        --source tcp://192.168.1.101:5555 \\
        --source tcp://192.168.1.102:5555 \\
        --source tcp://192.168.1.103:5555 \\
        --http-port 8000

Then open http://localhost:8000/ in a browser.

NOTE ON IDENTIFICATION:
This file only *consumes* whatever the sniffer/publisher puts in each
'adv' message. To get vendor/device-type/frame-type info you need the
publisher to include a `manufacturer` field: the hex string (or bytes)
of the Manufacturer Specific Data AD *value* -- i.e. company ID bytes
plus payload, NOT including the AD length/type prefix. If your publisher
currently drops that field on the floor, that's the one thing to add
upstream; everything else below already handles it.
"""

import argparse
import asyncio
import collections
import json
import logging
import os
import pathlib
import statistics
import time

import zmq
import zmq.asyncio
from aiohttp import web

from ble_identify import identify as identify_ble

logger = logging.getLogger('ble_aggregator')

HERE = pathlib.Path(__file__).parent.resolve()

# ---------------------------------------------------------------------------
# RSSI calibration
# ---------------------------------------------------------------------------
#
# Model:  raw_rssi(source, channel) = offset + slope * common_rssi
# so       corrected = (raw - offset) / slope
# (slope is ~1.0 for a healthy radio; it only differs when the receiver's AGC
# / RSSI detector is non-linear).  Entries are keyed by (source, channel); an
# entry with channel '*' is the per-source fallback used for a channel that was
# never calibrated (and for conn_data heartbeats, which carry no adv channel).

CAL_ANY = '*'
CAL_FILE_VERSION = 1

# esp32_ref_beacon.ino advertises an iBeacon-format packet:
#   4C 00 02 15 | UUID(16) | major(2) | minor hi = point id | minor lo = 128+dBm | tx@1m
CAL_UUID_PREFIX = bytes.fromhex('ca1b3a11b00b40d38e339ac0')   # first 12 UUID bytes
CAL_MAJOR = 0xB1B0


class CalibrationError(Exception):
    pass


def parse_cal_beacon(manufacturer):
    """Return (point_id, tx_dbm) if `manufacturer` (hex str or bytes: company ID
    + payload) is a packet from our reference beacon, else None."""
    if not manufacturer:
        return None
    if isinstance(manufacturer, (bytes, bytearray)):
        b = bytes(manufacturer)
    else:
        try:
            b = bytes.fromhex(str(manufacturer).strip())
        except ValueError:
            return None
    if len(b) < 24 or b[0:4] != b'\x4c\x00\x02\x15':
        return None
    if b[4:16] != CAL_UUID_PREFIX or int.from_bytes(b[20:22], 'big') != CAL_MAJOR:
        return None
    return b[22], b[23] - 128


class Calibration:
    """Per-(source, channel) affine RSSI correction."""

    def __init__(self, entries=None, meta=None):
        self.entries = entries or {}    # (source, channel|'*') -> dict
        self.meta = meta or {}

    def __len__(self):
        return len(self.entries)

    def lookup(self, source, channel):
        e = self.entries.get((source, channel))
        if e is None:
            e = self.entries.get((source, CAL_ANY))
        return e

    def apply(self, source, channel, raw):
        e = self.lookup(source, channel)
        if e is None:
            return float(raw)
        return (raw - e['offset']) / (e.get('slope') or 1.0)

    def to_dict(self):
        rows = []
        for (s, c), e in sorted(self.entries.items(), key=lambda kv: (str(kv[0][0]), str(kv[0][1]))):
            row = {'source': s, 'channel': c}
            row.update(e)
            rows.append(row)
        return {'version': CAL_FILE_VERSION, 'meta': self.meta, 'entries': rows}

    @classmethod
    def from_dict(cls, d):
        entries = {}
        for row in d.get('entries', []):
            row = dict(row)
            key = (row.pop('source'), row.pop('channel', CAL_ANY))
            row['offset'] = float(row['offset'])
            row['slope'] = float(row.get('slope', 1.0))
            entries[key] = row
        return cls(entries, d.get('meta') or {})

    def save(self, path):
        path = pathlib.Path(path)
        tmp = path.with_suffix(path.suffix + '.tmp')
        tmp.write_text(json.dumps(self.to_dict(), indent=2))
        os.replace(tmp, path)

    @classmethod
    def load(cls, path):
        return cls.from_dict(json.loads(pathlib.Path(path).read_text()))


class CalSession:
    """Collects beacon RSSI samples, grouped by (source, channel, tx power dBm)."""

    def __init__(self, max_per_group=20000):
        self.max_per_group = max_per_group
        self.active = False
        self.started = None
        self.stopped = None
        self.samples = {}
        self.points = collections.Counter()

    def start(self):
        self.samples = {}
        self.points = collections.Counter()
        self.active = True
        self.started = time.time()
        self.stopped = None

    def stop(self):
        if self.active:
            self.active = False
            self.stopped = time.time()

    def add(self, source, channel, power_dbm, rssi, point=None):
        dq = self.samples.get((source, channel, power_dbm))
        if dq is None:
            dq = self.samples[(source, channel, power_dbm)] = collections.deque(maxlen=self.max_per_group)
        dq.append(rssi)
        if point is not None:
            self.points[point] += 1

    def status(self, min_samples=30):
        groups = []
        for (s, ch, p), vals in sorted(self.samples.items(), key=lambda kv: tuple(str(x) for x in kv[0])):
            v = list(vals)
            groups.append({
                'source': s, 'channel': ch, 'tx_dbm': p, 'n': len(v),
                'median': statistics.median(v),
                'std': round(statistics.pstdev(v), 2) if len(v) > 1 else 0.0,
                'enough': len(v) >= min_samples,
            })
        end = self.stopped or time.time()
        return {
            'active': self.active,
            'elapsed_sec': round(end - self.started, 1) if self.started else 0,
            'points_seen': dict(self.points),
            'groups': groups,
        }


def _fit_affine(pairs, fit_slope, warn, label):
    """pairs = [(x_ref, y_src), ...] (median RSSI per TX power level).
    Returns (offset, slope, method, resid_std) for y = offset + slope * x."""
    xs = [x for x, _ in pairs]
    ys = [y for _, y in pairs]
    n = len(pairs)
    if fit_slope and n >= 3 and (max(xs) - min(xs)) >= 6.0:
        mx, my = statistics.fmean(xs), statistics.fmean(ys)
        sxx = sum((x - mx) ** 2 for x in xs)
        slope = sum((x - mx) * (y - my) for x, y in pairs) / sxx
        if 0.7 <= slope <= 1.3:
            off = my - slope * mx
            res = [y - (off + slope * x) for x, y in pairs]
            return off, slope, 'linear', statistics.pstdev(res)
        warn('%s: fitted slope %.2f outside 0.7..1.3 (saturation / floor / bad data?) '
             '-> using offset only' % (label, slope))
    elif fit_slope and n < 3:
        warn('%s: only %d common TX power level(s) (need >= 3 spanning >= 6 dB for a slope) '
             '-> offset only' % (label, n))
    elif fit_slope and n >= 3:
        warn('%s: TX power levels span < 6 dB -> offset only' % label)
    diffs = [y - x for x, y in pairs]
    off = statistics.median(diffs)
    res = [d - off for d in diffs]
    return off, 1.0, 'offset', (statistics.pstdev(res) if n > 1 else None)


def fit_calibration(samples, reference=None, ref_channel=None, min_samples=30,
                    rssi_lo=-100.0, rssi_hi=-30.0, fit_slope=True):
    """Fit a Calibration from CalSession.samples.  Returns (Calibration, report).

    All sources are mapped onto the scale of `reference` (default: the source
    with the most samples) on `ref_channel` (default: the reference's busiest
    channel).  If the reference was also heard on other channels, its own
    per-channel offset is fitted against its ref_channel data, and every other
    source on that channel is chained through it, so channel differences are
    captured.
    """
    warnings = []
    warn = warnings.append

    # median per (source, channel) -> {tx_dbm: (median, n)}
    stats = {}
    for (s, ch, p), vals in samples.items():
        v = list(vals)
        if len(v) < min_samples:
            warn('ignored %s ch%s @%+d dBm: only %d samples (< %d)' % (s, ch, p, len(v), min_samples))
            continue
        m = statistics.median(v)
        if not (rssi_lo <= m <= rssi_hi):
            warn('ignored %s ch%s @%+d dBm: median %.1f dBm outside usable range [%g, %g] '
                 '(floor / saturation)' % (s, ch, p, m, rssi_lo, rssi_hi))
            continue
        stats.setdefault((s, ch), {})[p] = (m, len(v))
    if not stats:
        raise CalibrationError('no usable samples (need >= %d per source/channel/power level; '
                               'see warnings: %s)' % (min_samples, '; '.join(warnings) or 'none'))

    totals = collections.Counter()
    for (s, ch), lv in stats.items():
        totals[s] += sum(n for _, n in lv.values())
    if reference is None:
        reference = totals.most_common(1)[0][0]
    elif reference not in totals:
        raise CalibrationError('reference source %r has no usable data; sources with data: %s'
                               % (reference, ', '.join(sorted(totals))))
    ref_chs = {ch: sum(n for _, n in lv.values()) for (s, ch), lv in stats.items() if s == reference}
    if ref_channel is None:
        ref_channel = max(ref_chs, key=ref_chs.get)
    elif ref_channel not in ref_chs:
        raise CalibrationError('reference %s has no usable data on channel %s (has: %s)'
                               % (reference, ref_channel, sorted(ref_chs)))

    def n_samples(lv):
        return sum(n for _, n in lv.values())

    def common(a, b):
        return [(a[p][0], b[p][0]) for p in sorted(a) if p in b]

    entries = {}
    ref_ref = stats[(reference, ref_channel)]
    entries[(reference, ref_channel)] = {
        'offset': 0.0, 'slope': 1.0, 'method': 'reference',
        'levels': len(ref_ref), 'samples': n_samples(ref_ref), 'resid_std': None}

    # reference source on its other channels -> channel offsets
    ref_map = {ref_channel: (0.0, 1.0)}      # channel -> (a, b) of the reference there
    for ch in sorted(ref_chs, key=str):
        if ch == ref_channel:
            continue
        lv = stats[(reference, ch)]
        pairs = common(ref_ref, lv)
        if not pairs:
            warn('reference %s ch%s: no TX power level in common with ch%s -> channel skipped'
                 % (reference, ch, ref_channel))
            continue
        a, b, method, resid = _fit_affine(pairs, fit_slope, warn, 'reference %s ch%s' % (reference, ch))
        ref_map[ch] = (a, b)
        entries[(reference, ch)] = {
            'offset': a, 'slope': b, 'method': method + '(channel)',
            'levels': len(pairs), 'samples': n_samples(lv), 'resid_std': resid}

    # every other source, chained through the reference on the same channel
    for (s, ch), lv in sorted(stats.items(), key=lambda kv: (str(kv[0][0]), str(kv[0][1]))):
        if s == reference:
            continue
        if ch not in ref_map:
            warn('%s ch%s: reference %s has no usable data on this channel -> skipped'
                 % (s, ch, reference))
            continue
        aR, bR = ref_map[ch]
        ref_lv = stats.get((reference, ch))
        pairs = common(ref_lv, lv)
        if not pairs:
            warn('%s ch%s: no TX power level in common with the reference -> skipped' % (s, ch))
            continue
        a1, b1, method, resid = _fit_affine(pairs, fit_slope, warn, '%s ch%s' % (s, ch))
        entries[(s, ch)] = {
            'offset': a1 + b1 * aR, 'slope': b1 * bR, 'method': method,
            'levels': len(pairs), 'samples': n_samples(lv), 'resid_std': resid}

    # per-source fallback (channel '*') = the entry with the most samples
    by_source = {}
    for (s, ch), e in entries.items():
        if ch != CAL_ANY and (s not in by_source or e['samples'] > by_source[s]['samples']):
            by_source[s] = e
    for s, e in by_source.items():
        fb = dict(e)
        fb['method'] = 'fallback'
        entries[(s, CAL_ANY)] = fb

    for s in totals:
        if not any(k[0] == s for k in entries):
            warn('source %s ended up with NO calibration entry' % s)
    for (s, ch), e in entries.items():
        if abs(e['offset']) > 20:
            warn('%s ch%s: offset %.1f dB is very large - check geometry / antenna' % (s, ch, e['offset']))
        if e['resid_std'] is not None and e['resid_std'] > 2.5:
            warn('%s ch%s: residual %.1f dB is high - unstable geometry or nonlinear radio' % (s, ch, e['resid_std']))

    meta = {'created': time.strftime('%Y-%m-%d %H:%M:%S'), 'reference': reference,
            'ref_channel': ref_channel, 'min_samples': min_samples,
            'rssi_range': [rssi_lo, rssi_hi], 'fit_slope': fit_slope}
    cal = Calibration(entries, meta)
    report = {'reference': reference, 'ref_channel': ref_channel,
              'warnings': warnings, 'calibration': cal.to_dict()}
    return cal, report


def format_report(report):
    lines = ['Reference: %s on channel %s' % (report['reference'], report['ref_channel']),
             '%-38s %5s %8s %6s %6s %8s %6s  %s'
             % ('source', 'ch', 'offset', 'slope', 'levels', 'samples', 'resid', 'method')]
    for e in report['calibration']['entries']:
        lines.append('%-38s %5s %+8.2f %6.3f %6s %8s %6s  %s' % (
            e['source'][:38], e['channel'], e['offset'], e['slope'], e.get('levels', ''),
            e.get('samples', ''),
            '-' if e.get('resid_std') is None else '%.2f' % e['resid_std'], e['method']))
    if report['warnings']:
        lines.append('Warnings:')
        lines.extend('  - ' + w for w in report['warnings'])
    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------

# Fields worth remembering about a device even after it has aged out of the
# live view, so that when the same address shows up again (or is only known
# from a CONNECT_REQ) it comes back with its name instead of a bare MAC.
IDENT_KEYS = ('name', 'label', 'vendor', 'device_type', 'frame_types')
IDENTITY_CACHE_MAX = 5000

# A followed connection is shown as "following" while data-channel traffic
# keeps arriving, and as "quiet" once it has been silent for longer than this
# (it is still kept until --followed-ttl runs out).
FOLLOW_ACTIVE_SEC = 5.0


def _norm_aa(aa):
    """Access addresses may arrive as '0x1234ABCD' strings or plain ints."""
    if aa is None:
        return None
    if isinstance(aa, int):
        return '0x%08x' % aa
    return str(aa).strip().lower()


class BleState:
    """In-memory, deduplicated view of everything seen across all sources.

    Connection life-cycle
    ---------------------
    connect_req  -> connection appears ("seen": only the CONNECT_REQ was heard)
    conn_data    -> a Sniffle instance is following it and reports data-channel
                    traffic about once a second ("following"); every heartbeat
                    refreshes the connection AND both endpoint devices, so they
                    stay in the view for as long as the link is being followed
    conn_end     -> Sniffle stopped following it ("ended"); kept greyed-out for
                    --ended-ttl seconds so it doesn't just vanish
    A connection that is never followed falls back to --connection-ttl, and one
    that stops producing heartbeats without a conn_end (dropped message, sniffer
    crash) is dropped after --followed-ttl.
    """

    def __init__(self, device_ttl=10.0, connection_ttl=120.0, scan_ttl=15.0,
                 followed_ttl=20.0, ended_ttl=30.0, calibration=None, cal_path=None,
                 combine='median', rssi_window=5.0, cal_beacon_addr=None, cal_defaults=None):
        self.calibration = calibration or Calibration()
        self.cal_enabled = True
        self.cal_path = cal_path
        self.cal_defaults = cal_defaults or {}
        self.cal_beacon_addr = self._norm_addr(cal_beacon_addr)
        self.session = CalSession()
        self.pending_cal = None
        self.pending_report = None
        self.combine = combine
        self.rssi_window = rssi_window
        self.devices = {}       # adv_addr -> dict
        self.connections = {}   # access_address -> dict
        self.scans = {}         # (scanner_addr, adv_addr) -> dict
        self.scan_ttl = scan_ttl
        self.device_ttl = device_ttl
        self.connection_ttl = connection_ttl
        self.followed_ttl = followed_ttl
        self.ended_ttl = ended_ttl
        # addr -> {name,label,vendor,...}; survives device expiry (LRU-capped)
        self.identity_cache = collections.OrderedDict()
        self._conn_states = {}  # access_address -> last derived state
        self.lock = asyncio.Lock()
        # monotonically increasing counter so the frontend can tell
        # "nothing changed" from "changed but values happen to match"
        self.version = 0

    def _norm_addr(self, addr):
        return addr.strip().upper() if addr else addr

    # -- RSSI calibration ----------------------------------------------------

    def _record_rssi(self, d, source, channel, raw, now):
        """Store one RSSI observation for device d, keep it per source (raw and
        corrected), and refresh d['rssi'] = combined corrected value."""
        if raw is None:
            return
        cal = self.calibration.apply(source, channel, raw) if self.cal_enabled else float(raw)
        tbl = d.setdefault('rssi_by_source', {})
        tbl[source] = {'raw': raw, 'cal': round(cal, 1), 'channel': channel, 'ts': now}
        for k in [k for k, e in tbl.items() if now - e['ts'] > 60.0]:
            del tbl[k]
        d['rssi_raw'] = raw
        d['rssi'] = self._combine_rssi(tbl, now)

    def _combine_rssi(self, tbl, now):
        fresh = [e for e in tbl.values() if now - e['ts'] <= self.rssi_window]
        if not fresh:
            fresh = [max(tbl.values(), key=lambda e: e['ts'])]
        vals = [e['cal'] for e in fresh]
        mode = self.combine
        if mode == 'latest':
            v = max(fresh, key=lambda e: e['ts'])['cal']
        elif mode == 'mean':
            v = statistics.fmean(vals)
        elif mode == 'max':
            v = max(vals)
        else:
            v = statistics.median(vals)
        return round(v, 1)

    def cal_status(self):
        cal = self.calibration
        return {
            'enabled': self.cal_enabled,
            'path': str(self.cal_path) if self.cal_path else None,
            'calibration': cal.to_dict(),
            'session': self.session.status(self.cal_defaults.get('min_samples', 30)),
            'pending': self.pending_report,
            'combine': self.combine, 'rssi_window': self.rssi_window,
        }

    # -- device helpers ------------------------------------------------------

    def _get_device(self, addr, now):
        """Fetch the live device entry for addr, creating it if needed.  A new
        entry is seeded from the identity cache, so a device that expired (or
        that we only know from a CONNECT_REQ) still has its name."""
        d = self.devices.get(addr)
        if d is None:
            d = {'addr': addr, 'name': None, 'first_seen': now, 'last_seen': now}
            cached = self.identity_cache.get(addr)
            if cached:
                d.update(cached)
            self.devices[addr] = d
        return d

    def _remember_identity(self, d):
        ident = {k: d[k] for k in IDENT_KEYS if d.get(k)}
        if not ident:
            return
        addr = d['addr']
        self.identity_cache[addr] = ident
        self.identity_cache.move_to_end(addr)
        while len(self.identity_cache) > IDENTITY_CACHE_MAX:
            self.identity_cache.popitem(last=False)

    def _update_identity(self, d):
        """Re-derive vendor/device type/label from what we know about d.
        A name never disappears once seen, and manufacturer payloads are cheap
        to re-parse every time they arrive since Continuity frame type /
        activity legitimately changes packet to packet."""
        ident = identify_ble(name=d.get('name'), manufacturer=d.get('manufacturer'))
        if ident.get('vendor'):
            d['vendor'] = ident['vendor']
        if ident.get('device_type'):
            d['device_type'] = ident['device_type']
        if ident.get('frame_types'):
            d['frame_types'] = ident['frame_types']
        # what the UI should show in place of the raw MAC: a real advertised
        # name always wins; otherwise fall back to "<device type>(<frame type>)",
        # e.g. "iPhone/iPad(nearby)"; otherwise keep whatever we knew before.
        d['label'] = d.get('name') or ident.get('label') or d.get('label')
        self._remember_identity(d)

    def _ident_for(self, addr):
        """(name, label) for an address, from the live view or the cache."""
        if not addr:
            return None, None
        src = self.devices.get(addr) or self.identity_cache.get(addr) or {}
        return src.get('name'), src.get('label')

    # -- connection helpers --------------------------------------------------

    def _conn_state(self, c, now):
        if c.get('ended'):
            return 'ended'
        if c.get('followed'):
            return 'following' if now - c['last_seen'] <= FOLLOW_ACTIVE_SEC else 'quiet'
        return 'seen'

    def _handle_connection_event(self, event, msg, now):
        """'connect_req' (CONNECT_IND heard on an advertising channel) and
        'conn_data' (heartbeat from the Sniffle instance following it)."""
        c = msg.get('connect') or {}
        aa = _norm_aa(msg.get('access_address') or c.get('access_address'))
        if not aa:
            return

        conn = self.connections.get(aa)
        if conn is not None and conn.get('ended') and event == 'connect_req':
            conn = None   # a brand-new connection that happens to reuse an AA
        if conn is None:
            conn = {'access_address': aa, 'first_seen': now,
                    'init_addr': None, 'adv_addr': None,
                    'followed': False, 'ended': False}
            self.connections[aa] = conn

        fields = dict(c)
        fields['access_address'] = aa
        # Publisher sends addresses lower-case; devices are keyed upper-case.
        # Without this the connection endpoints became separate, nameless
        # duplicates of the devices that had been seen advertising.
        for k in ('init_addr', 'adv_addr'):
            fields[k] = self._norm_addr(fields.get(k))
        conn.update({k: v for k, v in fields.items() if v is not None})
        conn['last_seen'] = now
        conn['source'] = msg.get('source')

        if event == 'conn_data':
            conn['followed'] = True
            conn['ended'] = False
            conn.pop('ended_at', None)
            conn.pop('end_reason', None)
            conn['follow_source'] = msg.get('source')
            conn['stats'] = msg.get('stats') or {}

        # Keep both endpoints alive (and named) while the connection is alive.
        endpoints = (conn.get('init_addr'), conn.get('adv_addr'))
        for addr in endpoints:
            if addr:
                self._get_device(addr, now)['last_seen'] = now

        if event == 'conn_data':
            # The sniffer hears each side of the link separately, so it can
            # give each endpoint its own RSSI (radar position).
            stats = conn['stats']
            for addr, key in zip(endpoints, ('rssi_central', 'rssi_peripheral')):
                if addr and stats.get(key) is not None:
                    self._record_rssi(self.devices[addr], msg.get('source'), None,
                                      stats[key], now)

    def _handle_conn_end(self, msg, now):
        aa = _norm_aa(msg.get('access_address'))
        conn = self.connections.get(aa)
        if not conn or conn.get('ended'):
            return
        conn['ended'] = True
        conn['ended_at'] = now
        conn['last_seen'] = now          # starts the --ended-ttl countdown
        conn['end_reason'] = msg.get('reason')
        if msg.get('stats'):
            conn['stats'] = msg['stats']

    # -- message ingestion ---------------------------------------------------

    async def handle_message(self, msg: dict):
        now = time.time()
        event = msg.get('event')
        # Drop anything with a failed CRC before it touches state at all.
        # A CRC-failed adv/connect_req PDU can have a corrupted address, which
        # otherwise shows up as a brand-new "device" that was never really seen.
        if not msg.get('crc_ok', True):
            return
        async with self.lock:
            if event == 'adv':
                addr = self._norm_addr(msg.get('adv_addr'))
                if not addr:
                    return
                d = self._get_device(addr, now)
                d['last_seen'] = now
                self._record_rssi(d, msg.get('source'), msg.get('channel'), msg.get('rssi'), now)
                d['channel'] = msg.get('channel')
                d['pdu_type'] = msg.get('pdu_type')
                d['tx_addr_random'] = msg.get('tx_addr_random')
                d['source'] = msg.get('source')
                if msg.get('name'):
                    d['name'] = msg['name']
                if msg.get('tx_power') is not None:
                    d['tx_power'] = msg['tx_power']
                if msg.get('manufacturer'):
                    d['manufacturer'] = msg['manufacturer']

                self._update_identity(d)

                # ESP32 reference beacon: tag it, and feed the calibration session
                beacon = parse_cal_beacon(msg.get('manufacturer'))
                if beacon and (not self.cal_beacon_addr or addr == self.cal_beacon_addr):
                    point, dbm = beacon
                    d['cal_beacon'] = True
                    d['cal_point'] = point
                    d['cal_tx_dbm'] = dbm
                    if self.session.active and msg.get('rssi') is not None:
                        self.session.add(msg.get('source'), msg.get('channel'), dbm,
                                         msg['rssi'], point)

                d.setdefault('channels_seen', set()).add(msg.get('channel'))
                if msg.get('service_data'):
                    d['service_data'] = msg['service_data']

            elif event in ('connect_req', 'conn_data'):
                self._handle_connection_event(event, msg, now)

            elif event == 'conn_end':
                self._handle_conn_end(msg, now)

            elif event == 'scan_req':
                scanner = self._norm_addr(msg.get('scanner_addr'))
                target = self._norm_addr(msg.get('adv_addr'))  # who's being scanned
                if not scanner:
                    return
                d = self._get_device(scanner, now)
                d['last_seen'] = now
                self._record_rssi(d, msg.get('source'), msg.get('channel'), msg.get('rssi'), now)
                d['channel'] = msg.get('channel')
                d['pdu_type'] = msg.get('pdu_type')
                d['tx_addr_random'] = msg.get('tx_addr_random')
                d['source'] = msg.get('source')
                d['scanner'] = True

                if target:
                    key = (scanner, target)
                    s = self.scans.setdefault(key, {
                        'scanner_addr': scanner, 'adv_addr': target,
                        'rsp_seen': False, 'first_seen': now,
                    })
                    s['last_seen'] = now

            elif event == 'scan_rsp':
                addr = self._norm_addr(msg.get('adv_addr'))
                if not addr:
                    return
                d = self._get_device(addr, now)
                d['last_seen'] = now
                self._record_rssi(d, msg.get('source'), msg.get('channel'), msg.get('rssi'), now)
                d['channel'] = msg.get('channel')
                d['pdu_type'] = msg.get('pdu_type')       # 'SCAN_RSP' -> green, via existing PDU_STYLE
                d['source'] = msg.get('source')
                if msg.get('name'):
                    d['name'] = msg['name']
                if msg.get('tx_power') is not None:
                    d['tx_power'] = msg['tx_power']
                if msg.get('manufacturer'):
                    d['manufacturer'] = msg['manufacturer']
                if msg.get('service_uuids'):
                    d['service_uuids'] = msg['service_uuids']

                self._update_identity(d)

                if msg.get('service_data'):
                    d['service_data'] = msg['service_data']
                # no scanner_addr on air for SCAN_RSP (it's implicit/broadcast-style per
                # your Wireshark capture) -- mark any pending request aimed at this
                # target as answered, same fallback as before
                for key, s in self.scans.items():
                    if key[1] == addr and now - s['last_seen'] < self.scan_ttl:
                        s['rsp_seen'] = True
                        s['last_seen'] = now

            self.version += 1

    # -- ageing --------------------------------------------------------------

    async def expire_stale(self):
        now = time.time()
        async with self.lock:
            # Connections: the TTL depends on how much we know about them.
            dead_conns = []
            for aa, c in self.connections.items():
                if c.get('ended'):
                    ttl = self.ended_ttl
                elif c.get('followed'):
                    ttl = self.followed_ttl
                else:
                    ttl = self.connection_ttl
                if now - c['last_seen'] > ttl:
                    dead_conns.append(aa)
            for aa in dead_conns:
                del self.connections[aa]
                self._conn_states.pop(aa, None)

            # Never age out the endpoints of a connection that is still on
            # the books, otherwise the connection edge is left dangling.
            protected = set()
            for c in self.connections.values():
                if not c.get('ended'):
                    protected.update(a for a in (c.get('init_addr'), c.get('adv_addr')) if a)

            dead_devices = [a for a, d in self.devices.items()
                            if a not in protected and now - d['last_seen'] > self.device_ttl]
            for a in dead_devices:
                del self.devices[a]

            dead_scans = [k for k, s in self.scans.items() if now - s['last_seen'] > self.scan_ttl]
            for k in dead_scans:
                del self.scans[k]

            # Connection state depends on the clock (following -> quiet), so
            # nudge the version when it flips even though no message arrived.
            state_changed = False
            for aa, c in self.connections.items():
                st = self._conn_state(c, now)
                if self._conn_states.get(aa) != st:
                    self._conn_states[aa] = st
                    state_changed = True

            if dead_devices or dead_conns or dead_scans or state_changed:
                self.version += 1

    async def snapshot(self):
        async with self.lock:
            now = time.time()

            connections = []
            active_endpoints = set()
            for c in self.connections.values():
                cc = dict(c)
                cc['age_sec'] = round(now - cc['last_seen'], 1)
                cc['state'] = self._conn_state(c, now)
                end = c['ended_at'] if c.get('ended') else now
                cc['duration_sec'] = round(end - c['first_seen'], 1)
                cc['init_name'], cc['init_label'] = self._ident_for(c.get('init_addr'))
                cc['adv_name'], cc['adv_label'] = self._ident_for(c.get('adv_addr'))
                connections.append(cc)
                if cc['state'] != 'ended':
                    active_endpoints.update(a for a in (c.get('init_addr'), c.get('adv_addr')) if a)

            devices = []
            for d in self.devices.values():
                dd = dict(d)
                dd['channels_seen'] = sorted(x for x in dd.get('channels_seen', []) if x is not None)
                dd['age_sec'] = round(now - dd['last_seen'], 1)
                # final display string for the UI: advertised name, else
                # our best guess label, else fall back to the MAC itself.
                dd['display'] = dd.get('name') or dd.get('label') or dd['addr']
                # derived from the live connections rather than latched, so
                # the flag clears again once a connection has ended
                dd['connected'] = dd['addr'] in active_endpoints
                devices.append(dd)

            scans = []
            for s in self.scans.values():
                ss = dict(s)
                ss['age_sec'] = round(now - ss['last_seen'], 1)
                scans.append(ss)

            return {
                'type': 'snapshot', 'ts': now, 'version': self.version,
                'devices': devices, 'connections': connections, 'scans': scans,
                'calibration': {'enabled': self.cal_enabled, 'entries': len(self.calibration),
                                'session_active': self.session.active,
                                'combine': self.combine},
            }


# ---------------------------------------------------------------------------
# Debug helpers
# ---------------------------------------------------------------------------

def _debug_log_message(source: str, msg: dict):
    """Log every incoming message and highlight address fields."""
    event = msg.get('event', 'unknown')
    raw = json.dumps(msg, default=str)

    if event == 'adv':
        addr = msg.get('adv_addr')
        name = msg.get('name')
        ch = msg.get('channel')
        logger.debug('[%-20s] ADV  addr=%s  name=%r  ch=%s  raw=%s',
                     source, addr, name, ch, raw)
    elif event == 'connect_req':
        if not msg.get('crc_ok', True):
            logger.debug('[%-20s] CONN (crc_ok=false, discarded) source_ts=%s', source, msg.get('ts'))
            return
        c = msg.get('connect') or {}
        aa = c.get('access_address')
        init = c.get('init_addr')
        adv = c.get('adv_addr')
        logger.debug('[%-20s] CONN aa=%s  init=%s  adv=%s ',
                     source, aa, init, adv)
    elif event == 'conn_data':
        aa = msg.get('access_address') or (msg.get('connect') or {}).get('access_address')
        logger.debug('[%-20s] FOLLOW aa=%s  stats=%s', source, aa, msg.get('stats'))
    elif event == 'conn_end':
        aa = msg.get('access_address')
        logger.debug('[%-20s] CONN_END aa=%s  reason=%s', source, aa, msg.get('reason'))
    else:
        logger.debug('[%-20s] %s  raw=%s', source, event, raw)


# ---------------------------------------------------------------------------
# ZMQ ingestion
# ---------------------------------------------------------------------------

async def zmq_subscriber_task(source: str, state: BleState, debug: bool = False):
    ctx = zmq.asyncio.Context.instance()
    sock = ctx.socket(zmq.SUB)
    sock.setsockopt_string(zmq.SUBSCRIBE, '')
    sock.setsockopt(zmq.RCVHWM, 2000)
    sock.connect(source)
    logger.info('Subscribed to %s', source)

    while True:
        try:
            raw = await sock.recv_string()
            msg = json.loads(raw)
            if not msg.get('source'):
                msg['source'] = source      # calibration is keyed by source
            if debug:
                _debug_log_message(source, msg)
            await state.handle_message(msg)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception('Error handling message from %s (raw=%r)', source, raw if 'raw' in dir() else 'N/A')
            await asyncio.sleep(0.5)


async def expiry_task(state: BleState, interval=2.0):
    while True:
        await asyncio.sleep(interval)
        try:
            await state.expire_stale()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception('Error expiring stale entries')


# ---------------------------------------------------------------------------
# HTTP / WebSocket server
# ---------------------------------------------------------------------------

async def index_handler(request):
    return web.FileResponse(HERE / 'index.html')


async def ws_handler(request):
    ws = web.WebSocketResponse(heartbeat=20)
    await ws.prepare(request)

    state: BleState = request.app['state']
    request.app['clients'].add(ws)
    logger.info('Client connected (%d total)', len(request.app['clients']))

    try:
        # Send an immediate snapshot so the UI isn't empty until the next broadcast tick.
        await ws.send_json(await state.snapshot())
        async for _ in ws:
            pass  # this app doesn't expect messages from the client
    finally:
        request.app['clients'].discard(ws)
        logger.info('Client disconnected (%d total)', len(request.app['clients']))

    return ws


async def broadcast_task(app, interval=0.5):
    state: BleState = app['state']
    last_version = -1
    while True:
        await asyncio.sleep(interval)
        if state.version == last_version:
            continue
        last_version = state.version
        snap = await state.snapshot()
        dead = []
        for ws in app['clients']:
            try:
                await ws.send_json(snap)
            except Exception:
                dead.append(ws)
        for ws in dead:
            app['clients'].discard(ws)


# ---------------------------------------------------------------------------
# Calibration HTTP API   (curl -X POST http://localhost:8000/api/cal/start ...)
# ---------------------------------------------------------------------------

def _jresp(data, status=200):
    return web.json_response(data, status=status, dumps=lambda o: json.dumps(o, default=str))


def _q_num(q, key, default, cast=float):
    v = q.get(key)
    if v is None or v == '':
        return default
    return cast(v)


def _fit_kwargs(q, defaults):
    def ch(v):
        return int(v) if v.lstrip('-').isdigit() else v
    return {
        'reference': q.get('reference') or defaults.get('reference'),
        'ref_channel': _q_num(q, 'ref_channel', defaults.get('ref_channel'), ch),
        'min_samples': _q_num(q, 'min_samples', defaults.get('min_samples', 30), int),
        'rssi_lo': _q_num(q, 'rssi_lo', defaults.get('rssi_lo', -100.0)),
        'rssi_hi': _q_num(q, 'rssi_hi', defaults.get('rssi_hi', -30.0)),
        'fit_slope': (q.get('slope', '1') not in ('0', 'false', 'no'))
                     if 'slope' in q else defaults.get('fit_slope', True),
    }


async def cal_status_handler(request):
    state: BleState = request.app['state']
    async with state.lock:
        return _jresp(state.cal_status())


async def cal_start_handler(request):
    state: BleState = request.app['state']
    async with state.lock:
        state.session.start()
        state.pending_cal = state.pending_report = None
        state.version += 1
    return _jresp({'ok': True, 'msg': 'calibration session started; step the ESP32 through its '
                                      'TX power levels, then POST /api/cal/stop and /api/cal/fit'})


async def cal_stop_handler(request):
    state: BleState = request.app['state']
    async with state.lock:
        state.session.stop()
        state.version += 1
        return _jresp({'ok': True, 'session': state.session.status(
            state.cal_defaults.get('min_samples', 30))})


async def cal_fit_handler(request):
    state: BleState = request.app['state']
    try:
        kw = _fit_kwargs(request.query, state.cal_defaults)
    except ValueError as e:
        return _jresp({'ok': False, 'error': 'bad parameter: %s' % e}, 400)
    async with state.lock:
        try:
            cal, report = fit_calibration(state.session.samples, **kw)
        except CalibrationError as e:
            return _jresp({'ok': False, 'error': str(e)}, 400)
        state.pending_cal, state.pending_report = cal, report
    return _jresp({'ok': True, 'text': format_report(report), **report,
                   'next': 'POST /api/cal/apply to activate and save it'})


async def cal_apply_handler(request):
    state: BleState = request.app['state']
    async with state.lock:
        if state.pending_cal is None:
            return _jresp({'ok': False, 'error': 'nothing to apply; run /api/cal/fit first'}, 400)
        state.calibration = state.pending_cal
        state.cal_enabled = True
        saved = None
        if state.cal_path:
            try:
                state.calibration.save(state.cal_path)
                saved = str(state.cal_path)
            except OSError as e:
                logger.error('Could not save calibration to %s: %s', state.cal_path, e)
        state.version += 1
    return _jresp({'ok': True, 'saved_to': saved, 'entries': len(state.calibration)})


async def cal_enable_handler(request):
    state: BleState = request.app['state']
    on = request.query.get('on', '1') not in ('0', 'false', 'no')
    async with state.lock:
        state.cal_enabled = on
        state.version += 1
    return _jresp({'ok': True, 'enabled': on})


async def cal_clear_handler(request):
    state: BleState = request.app['state']
    async with state.lock:
        state.calibration = Calibration()
        state.version += 1
    return _jresp({'ok': True, 'msg': 'calibration cleared (file on disk untouched)'})


async def start_background_tasks(app):
    debug = app.get('debug', False)
    app['bg_tasks'] = []
    for source in app['sources']:
        app['bg_tasks'].append(asyncio.create_task(zmq_subscriber_task(source, app['state'], debug=debug)))
    app['bg_tasks'].append(asyncio.create_task(expiry_task(app['state'])))
    app['bg_tasks'].append(asyncio.create_task(broadcast_task(app)))


async def cleanup_background_tasks(app):
    for t in app['bg_tasks']:
        t.cancel()
    await asyncio.gather(*app['bg_tasks'], return_exceptions=True)


def build_app(sources, device_ttl, connection_ttl, scan_ttl,
              followed_ttl=20.0, ended_ttl=30.0, debug=False, **state_kwargs):
    app = web.Application()
    app['sources'] = sources
    app['state'] = BleState(device_ttl=device_ttl, connection_ttl=connection_ttl,
                             scan_ttl=scan_ttl, followed_ttl=followed_ttl, ended_ttl=ended_ttl,
                             **state_kwargs)
    app['clients'] = set()
    app['debug'] = debug

    app.router.add_get('/', index_handler)
    app.router.add_get('/ws', ws_handler)
    app.router.add_get('/api/cal', cal_status_handler)
    for name, h in (('start', cal_start_handler), ('stop', cal_stop_handler),
                    ('fit', cal_fit_handler), ('apply', cal_apply_handler),
                    ('enable', cal_enable_handler), ('clear', cal_clear_handler)):
        app.router.add_post('/api/cal/' + name, h)
    app.router.add_static('/static/', HERE, show_index=False)

    app.on_startup.append(start_background_tasks)
    app.on_cleanup.append(cleanup_background_tasks)
    return app


async def run_calibration(args, cal_defaults):
    """--calibrate SECONDS: collect, fit, write the file, print the report."""
    state = BleState(cal_beacon_addr=args.cal_beacon_addr, cal_defaults=cal_defaults)
    state.session.start()
    tasks = [asyncio.create_task(zmq_subscriber_task(src, state)) for src in args.sources]
    logger.info('Calibrating for %.0f s -- keep the sniffers clustered and step the ESP32 '
                'through its TX power levels (BTN_POWER)...', args.calibrate)
    t0 = time.time()
    try:
        while True:
            left = args.calibrate - (time.time() - t0)
            if left <= 0:
                break
            await asyncio.sleep(min(5.0, left))
            st = state.session.status(args.cal_min_samples)
            per = collections.Counter()
            levels = set()
            for g in st['groups']:
                per[(g['source'], g['channel'])] += g['n']
                levels.add(g['tx_dbm'])
            logger.info('%3.0fs left | TX levels seen: %s | packets: %s', max(left - 5, 0),
                        sorted(levels) or '-',
                        ', '.join('%s ch%s=%d' % (s.split(':')[0], c, n) for (s, c), n in sorted(
                            per.items(), key=lambda kv: str(kv[0]))) or 'none yet')
    finally:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    state.session.stop()
    try:
        cal, report = fit_calibration(state.session.samples, **cal_defaults)
    except CalibrationError as e:
        logger.error('Calibration failed: %s', e)
        return 1
    print(format_report(report))
    cal.save(args.calibration)
    logger.info('Wrote %s', args.calibration)
    return 0


def main():
    ap = argparse.ArgumentParser(description='Aggregate several ccsniffpiper_zmq ZMQ feeds into one live BLE dashboard.')
    ap.add_argument('--source', action='append', dest='sources', default=[],
                     help='ZMQ PUB endpoint to subscribe to, e.g. tcp://192.168.1.101:5555. '
                          'Repeat once per sniffer (one per Pi/dongle/channel).')
    ap.add_argument('--http-port', type=int, default=8000)
    ap.add_argument('--device-ttl', type=float, default=60.0,
                     help='Seconds of silence before a device is dropped from the view (default 60)')
    ap.add_argument('--connection-ttl', type=float, default=120.0,
                     help='Seconds of silence before a connection edge is dropped (default 120)')
    ap.add_argument('--scan-ttl', type=float, default=5.0,
                         help='Seconds of silence before a scan edge is dropped (default 5.0)')
    ap.add_argument('--followed-ttl', type=float, default=20.0,
                     help='Seconds without a follow heartbeat before a connection Sniffle is '
                          'actively following is dropped (default 20). Should comfortably '
                          'exceed the connection interval so it survives normal gaps.')
    ap.add_argument('--ended-ttl', type=float, default=30.0,
                     help='Seconds a terminated (conn_end) connection stays visible, greyed '
                          'out, before it is dropped (default 30)')
    ap.add_argument('--debug', '-d', action='store_true',
                     help='Enable debug logging: every incoming ZMQ message is printed '
                          'with extracted addresses and full raw JSON.')
    cg = ap.add_argument_group('RSSI calibration')
    cg.add_argument('--calibration', default=str(HERE / 'ble_calibration.json'), metavar='FILE',
                    help='Calibration file: loaded at start if it exists, written by --calibrate '
                         'and by POST /api/cal/apply (default: ble_calibration.json next to this script)')
    cg.add_argument('--no-calibration', action='store_true',
                    help='Do not load the calibration file (raw RSSI)')
    cg.add_argument('--calibrate', type=float, metavar='SECONDS',
                    help='Calibration run: collect ESP32 beacon samples from all --source feeds '
                         'for SECONDS, fit, write --calibration, and exit (no web server)')
    cg.add_argument('--cal-reference', metavar='SOURCE',
                    help='Source id that defines the common RSSI scale (default: source with most samples)')
    cg.add_argument('--cal-ref-channel', type=int, metavar='CH',
                    help='Channel (as published by the sniffers) that defines the scale (default: reference busiest channel)')
    cg.add_argument('--cal-min-samples', type=int, default=30,
                    help='Minimum packets per source/channel/TX-power to be used (default 30)')
    cg.add_argument('--cal-no-slope', action='store_true', help='Fit offsets only (slope fixed at 1)')
    cg.add_argument('--cal-rssi-range', type=float, nargs=2, default=(-100.0, -30.0), metavar=('LO', 'HI'),
                    help='Ignore levels whose median RSSI is outside LO..HI dBm (floor / saturation) '
                         '(default -100 -30)')
    cg.add_argument('--cal-beacon-addr', metavar='MAC',
                    help='Only accept calibration packets from this beacon address (recommended)')
    cg.add_argument('--combine', choices=('median', 'mean', 'max', 'latest'), default='median',
                    help="How device['rssi'] is derived from the per-source corrected values "
                         "(default median; 'latest' = old behaviour: last packet from any source)")
    cg.add_argument('--rssi-window', type=float, default=5.0,
                    help='Only combine per-source values younger than this many seconds (default 5)')
    args = ap.parse_args()

    if not args.sources:
        ap.error('Provide at least one --source tcp://<pi-ip>:5555')

    cal_defaults = {
        'reference': args.cal_reference, 'ref_channel': args.cal_ref_channel,
        'min_samples': args.cal_min_samples, 'fit_slope': not args.cal_no_slope,
        'rssi_lo': args.cal_rssi_range[0], 'rssi_hi': args.cal_rssi_range[1],
    }

    # Set logging level based on debug flag
    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=level, format='%(asctime)s %(levelname)7s %(message)s')

    if args.calibrate:
        raise SystemExit(asyncio.run(run_calibration(args, cal_defaults)))

    calibration = Calibration()
    if not args.no_calibration and os.path.exists(args.calibration):
        try:
            calibration = Calibration.load(args.calibration)
            logger.info('Loaded RSSI calibration %s (%d entries, reference %s)', args.calibration,
                        len(calibration), calibration.meta.get('reference'))
        except Exception:
            logger.exception('Could not load calibration %s -- continuing with raw RSSI', args.calibration)
    else:
        logger.info('No RSSI calibration loaded (raw RSSI)')

    app = build_app(args.sources, args.device_ttl, args.connection_ttl, args.scan_ttl,
                     followed_ttl=args.followed_ttl, ended_ttl=args.ended_ttl, debug=args.debug,
                     calibration=calibration, cal_path=args.calibration, combine=args.combine,
                     rssi_window=args.rssi_window, cal_beacon_addr=args.cal_beacon_addr,
                     cal_defaults=cal_defaults)
    logger.info('Serving dashboard on http://0.0.0.0:%d  (sources: %s)',
                args.http_port, ', '.join(args.sources))
    web.run_app(app, host='0.0.0.0', port=args.http_port)


if __name__ == '__main__':
    main()