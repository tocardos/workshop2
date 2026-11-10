#!/usr/bin/env python3

"""

   ccsniffpiper - a python module to connect to the CC2540emk USB dongle
                 and pipe the sniffed packets to wireshark!
   Copyright (c) 2013, Andrew Dodd (andrew.john.dodd@gmail.com)

   This is essentially a mashup and extension of two existing sniffers:
   1. ccsniffer
   ------------
   Copyright (c) 2012, George Oikonomou (oikonomou@users.sf.net)

   2. sensniffer
   -------------
   Copyright (C) 2012 Christian Panton <christian@panton.org>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA

   -----------------------------------------------------------------------
   ZMQ / distributed-sniffing extension, 2026
   -----------------------------------------------------------------------
   Adds:
     - Parsing of CONNECT_REQ (access address, hop increment, channel map,
       connection interval/latency/timeout) so a "new connection" event
       carries everything needed to describe it on a dashboard.
     - Local/complete name extraction from AD structures (0x08/0x09).
     - A ZmqPublishHandler that publishes one JSON message per
       advertisement / scan response / connect request to a ZMQ PUB
       socket, so a laptop can subscribe to several of these sniffers
       (e.g. one Raspberry Pi + CC2540 per advertising channel 37/38/39)
       and merge the feeds into a single live view.

   NOTE ON SCOPE: the CC2540 sniffer firmware only ever tunes to the three
   BLE advertising channels (37/38/39). It cannot itself follow a
   connection onto the data channels. What you *do* get from CONNECT_REQ
   is the full recipe an observer would need to compute the hop sequence
   (Access Address, Hop Increment, Channel Map, and connection timing) -
   that's what gets published and drawn as a "new connection" edge. Actually
   following the data-channel hopping live would require additional
   hardware (e.g. an Ubertooth-class sniffer) synced to that recipe.
"""

import argparse
import os
import sys
import select
import time
import stat
import errno
import json
import socket as pysocket
from io import StringIO
import logging.handlers
import struct
import threading
import binascii
import usb.core
import usb.util


try:
    import zmq
except ImportError:
    zmq = None

__version__ = '0.1.0'

defaults = {
    'hex_file': 'ccsniffpiper.hexdump',
    'out_fifo': '/tmp/ccsniffpiper',
    'pcap_file': 'ccsniffpiper.pcap',
    'debug_level': 'WARN',
    'log_level': 'INFO',
    'log_file': 'ccsniffpiper.log',
    'channel': 37,
    'zmq_bind': 'tcp://*:5555',
}

logger = logging.getLogger(__name__)
stats = {}


def hexdump(data) -> str:
    """Return a space-separated hex string for any bytes-like/array of ints."""
    return ' '.join('%02x' % b for b in bytes(data))

class Frame(object):
    PCAP_FRAME_HDR_FMT = '<LLLL'

    def __init__(self, macPDUByteArray, timestampBy32, rssi=None, channel=37, crc_ok=None):
        self.__macPDUByteArray = macPDUByteArray
        self.timestampBy32 = timestampBy32
        self.timestampUsec = timestampBy32 / 32.0
        self.len = len(self.__macPDUByteArray)

        self.rssi = rssi
        self.channel = channel
        self.crc_ok = crc_ok
        phdr = PCAPHelper.build_btle_phdr(channel, rssi, crc_ok)
        self.__payload = phdr + bytes(self.__macPDUByteArray)
        self.len = len(self.__payload)
        self.__pcap_hdr = self.__generate_frame_hdr()
        self.pcap = self.__pcap_hdr + self.__payload
        self.hex = ''.join('%02x ' % c for c in self.__macPDUByteArray).rstrip()

    def __generate_frame_hdr(self):
        total_usec = int(self.timestampUsec)
        sec = total_usec // 1_000_000
        usec = total_usec % 1_000_000
        return struct.pack(Frame.PCAP_FRAME_HDR_FMT,
                           int(sec), int(usec), int(self.len), int(self.len))

    def get_pcap(self):
        return self.pcap

    def get_hex(self):
        return self.hex

    def get_timestamp(self):
        return self.timestampUsec

    def get_macpdu(self):
        return self.__macPDUByteArray

#####################################

class PCAPHelper:
    LINKTYPE_IEEE802_15_4_NOFCS = 230
    LINKTYPE_IEEE802_15_4 = 195
    LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR = 256
    MAGIC_NUMBER = 0xA1B2C3D4
    VERSION_MAJOR = 2
    VERSION_MINOR = 4
    THISZONE = 0
    SIGFIGS = 0
    SNAPLEN = 0xFFFF
    NETWORK = LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR
    BTLE_DEWHITENED = 0x0001
    BTLE_SIGNAL_POWER_VALID = 0x0002
    BTLE_NOISE_POWER_VALID = 0x0004
    BTLE_REF_AA_VALID = 0x0010
    BTLE_CRC_CHECKED = 0x0400
    BTLE_CRC_VALID = 0x0800

    BTLE_PHDR_FMT = '<BbbBIH'
    DEFAULT_ADV_AA = 0x8E89BED6

    PCAP_GLOBAL_HDR_FMT = '<LHHlLLL'

    @staticmethod
    def writeGlobalHeader():
        return struct.pack(
            PCAPHelper.PCAP_GLOBAL_HDR_FMT,
            PCAPHelper.MAGIC_NUMBER,
            PCAPHelper.VERSION_MAJOR,
            PCAPHelper.VERSION_MINOR,
            PCAPHelper.THISZONE,
            PCAPHelper.SIGFIGS,
            PCAPHelper.SNAPLEN,
            PCAPHelper.NETWORK)

    @staticmethod
    def build_btle_phdr(channel, rssi=None, crc_ok=None):
        flags = PCAPHelper.BTLE_DEWHITENED | PCAPHelper.BTLE_REF_AA_VALID

        signal_power = 127
        if rssi is not None:
            signal_power = max(-128, min(127, int(rssi)))
            flags |= PCAPHelper.BTLE_SIGNAL_POWER_VALID

        if crc_ok is not None:
            flags |= PCAPHelper.BTLE_CRC_CHECKED
            if crc_ok:
                flags |= PCAPHelper.BTLE_CRC_VALID

        return struct.pack(PCAPHelper.BTLE_PHDR_FMT,
                            channel & 0xFF,
                            signal_power,
                            127,
                            0,
                            PCAPHelper.DEFAULT_ADV_AA,
                            flags)

class FifoHandler(object):
    def __init__(self, out_fifo):
        self.out_fifo = out_fifo
        self.of = None
        self.needs_pcap_hdr = True
        self.thread = None
        self.running = False
        stats['Piped'] = 0
        stats['Not Piped'] = 0
        self.__create_fifo()
        self.__start()

    def __del__(self):
        self.__stop()

    def __start(self):
        logger.debug("start FIFO watcher thread")
        self.running = True
        self.thread = threading.Thread(target=self.__fifo_watcher)
        self.thread.daemon = True
        self.thread.start()

    def __stop(self):
        logger.debug("stop FIFO watcher thread")
        self.running = False
        if self.thread:
            self.thread.join()

    def __fifo_watcher(self):
        while self.running:
            self.__open_fifo(keepalive=True)
            time.sleep(0.01)

    def __create_fifo(self):
        try:
            os.mkfifo(self.out_fifo)
            logger.info('Opened FIFO %s' % (self.out_fifo,))
        except OSError as e:
            if e.errno == errno.EEXIST:
                if stat.S_ISFIFO(os.stat(self.out_fifo).st_mode) is False:
                    logger.error('File %s exists and is not a FIFO'
                                 % (self.out_fifo,))
                    sys.exit(1)
                else:
                    logger.warning('FIFO %s exists. Using it' % (self.out_fifo,))
            else:
                raise

    def __open_fifo(self, keepalive=False):
        try:
            fd = os.open(self.out_fifo, os.O_NONBLOCK | os.O_WRONLY)
            self.of = os.fdopen(fd, 'wb')
        except OSError as e:
            if e.errno == errno.ENXIO:
                if not keepalive:
                    stats['Not Piped'] += 1
                self.of = None
                self.needs_pcap_hdr = True
            else:
                raise

    def triggerNewGlobalHeader(self):
        self.needs_pcap_hdr = True

    def handle(self, data, rssi=None):
        if self.of is None:
            self.__open_fifo()

        if self.of is not None:
            try:
                if self.needs_pcap_hdr is True:
                    logger.info('Write global PCAP header')
                    self.of.write(PCAPHelper.writeGlobalHeader())
                    self.needs_pcap_hdr = False
                self.of.write(data.pcap)
                self.of.flush()
                logger.debug('Wrote a frame of size %d bytes' % (data.len))
                stats['Piped'] += 1
            except IOError as e:
                if e.errno == errno.EPIPE:
                    logger.info('Remote end stopped reading')
                    stats['Not Piped'] += 1
                    self.of = None
                    self.needs_pcap_hdr = True
                else:
                    raise
#####################################
class PcapDumpHandler(object):
    def __init__(self, filename):
        self.filename = filename
        stats['Dumped to PCAP'] = 0

        try:
            self.of = open(self.filename, 'wb')
            self.of.write(PCAPHelper.writeGlobalHeader())
            logger.info("Dumping PCAP to %s" % (self.filename,))
        except IOError as e:
            self.of = None
            logger.warning("Error opening %s to save pcap. Skipping"
                         % (self.filename))
            logger.warning("The error was: %s" % (e,))

    def handle(self, frame, rssi=None):
        if self.of is None:
            return
        self.of.write(frame.get_pcap())
        self.of.flush()
        logger.info('PcapDumpHandler: Dumped a frame of size %d bytes'
                     % (frame.len))
        stats['Dumped to PCAP'] += 1

class HexdumpHandler(object):
    def __init__(self, filename):
        self.filename = filename
        stats['Dumped as Hex'] = 0
        try:
            self.of = open(self.filename, 'w')
            logger.info("Dumping hex to %s" % (self.filename,))
        except IOError as e:
            logger.warning("Error opening %s for hex dumps. Skipping"
                         % (self.filename))
            logger.warning("The error was: %s" % (e,))
            self.of = None

    def handle(self, frame, rssi=None):
        if self.of is None:
            return

        try:
            self.of.write(binascii.hexlify(struct.pack(">I", int(frame.get_timestamp() * 32))).decode())
            self.of.write("  ")
            self.of.write(frame.get_hex())
            self.of.write('\n')
            self.of.flush()
            stats['Dumped as Hex'] += 1
            logger.info('HexdumpHandler: Dumped a frame of size %d bytes'
                         % (frame.len))
        except IOError as e:
            logger.warning("Error writing hex to %s for hex dumps. Skipping"
                     % (self.of,))
            logger.warning("The error was: %s" % (e,))

#####################################
# BLE advertising / connection-request parser
#####################################
class BLEAdvParserHandler(object):
    """Handler that parses incoming MAC PDU bytes for BLE advertising
    and CONNECT_REQ fields, and stashes the result on frame.parsed."""

    PDU_TYPE_NAMES = {
        0x0: 'ADV_IND',
        0x1: 'ADV_DIRECT_IND',
        0x2: 'ADV_NONCONN_IND',
        0x3: 'SCAN_REQ',
        0x4: 'SCAN_RSP',
        0x5: 'CONNECT_REQ',
        0x6: 'ADV_SCAN_IND',
        0x7: 'ADV_EXT_IND',
        0x8: 'AUX_CONNECT_RSP',
    }

    ADV_TYPES_WITH_ADDR_AND_DATA = (0x0, 0x1, 0x2, 0x6,0x7)
    def __init__(self, callback=None):
        self.callback = callback

    @staticmethod
    def _format_addr(addr_bytes: bytes) -> str:
        return ':'.join('%02x' % b for b in addr_bytes[::-1])

    @staticmethod
    def _parse_tlvs(ad_payload: bytes):
        i = 0
        while i < len(ad_payload):
            length = ad_payload[i]
            if length == 0:
                break
            if i + 1 + length > len(ad_payload):
                break
            atype = ad_payload[i + 1]
            data = ad_payload[i + 2: i + 1 + length]
            yield atype, data
            i += 1 + length

    @staticmethod
    def _parse_connect_req(payload: bytes):
        """Parse the InitA/AdvA/LLData block of a CONNECT_REQ PDU body.
        Returns None if the payload is too short to be a real CONNECT_REQ."""
        if len(payload) < 34:
            return None

        init_a = payload[0:6]
        adv_a = payload[6:12]
        lldata = payload[12:34]

        aa = struct.unpack('<I', lldata[0:4])[0]
        crc_init = int.from_bytes(lldata[4:7], 'little')
        win_size = lldata[7]
        win_offset = struct.unpack('<H', lldata[8:10])[0]
        interval = struct.unpack('<H', lldata[10:12])[0]
        latency = struct.unpack('<H', lldata[12:14])[0]
        timeout = struct.unpack('<H', lldata[14:16])[0]
        chan_map_raw = lldata[16:21]
        chan_map_int = int.from_bytes(chan_map_raw, 'little')
        hop_sca = lldata[21]
        hop = hop_sca & 0x1F
        sca = (hop_sca >> 5) & 0x07

        used_channels = [ch for ch in range(37) if (chan_map_int >> ch) & 1]

        return {
            'init_addr': BLEAdvParserHandler._format_addr(init_a),
            'adv_addr': BLEAdvParserHandler._format_addr(adv_a),
            'access_address': '0x%08x' % aa,
            'crc_init': '0x%06x' % crc_init,
            'win_size': win_size,
            'win_offset': win_offset,
            'interval_ms': interval * 1.25,
            'latency': latency,
            'timeout_ms': timeout * 10,
            'channel_map_hex': '0x%010x' % chan_map_int,
            'used_data_channels': used_channels,
            'num_used_channels': len(used_channels),
            'hop_increment': hop,
            'sleep_clock_accuracy_index': sca,
        }
    @staticmethod
    def _parse_ad_structures(res: dict, ad_payload: bytes):
        """Fills res['name']/res['tx_power']/res['manufacturer']/res['service_uuids']/
        res['service_data'] from a block of AD structures (works for ADV payloads
        and ScanRspData alike)."""
        service_uuids = []
        service_data = []
        for atype, data in BLEAdvParserHandler._parse_tlvs(ad_payload):
            res['tlvs'].append((atype, data))
            if atype == 0x0A and len(data) >= 1:  # TX Power Level
                res['tx_power'] = struct.unpack('b', data[0:1])[0]
            elif atype in (0x08, 0x09) and len(data) >= 1:  # Shortened/Complete Local Name
                try:
                    res['name'] = data.decode('utf-8', errors='replace')
                except Exception:
                    pass
            elif atype == 0xFF and len(data) >= 2:  # Manufacturer Specific Data
                res['manufacturer'] = data.hex()
            elif atype in (0x02, 0x03) and len(data) >= 2:  # 16-bit Service UUIDs
                for i in range(0, len(data) - 1, 2):
                    service_uuids.append('0x%04x' % struct.unpack_from('<H', data, i)[0])
            elif atype in (0x04, 0x05) and len(data) >= 4:  # 32-bit Service UUIDs
                for i in range(0, len(data) - 3, 4):
                    service_uuids.append('0x%08x' % struct.unpack_from('<I', data, i)[0])
            elif atype in (0x06, 0x07) and len(data) >= 16:  # 128-bit Service UUIDs
                for i in range(0, len(data) - 15, 16):
                    u = data[i:i + 16][::-1]
                    service_uuids.append(
                        '%08x-%04x-%04x-%04x-%012x' % (
                            int.from_bytes(u[0:4], 'big'), int.from_bytes(u[4:6], 'big'),
                            int.from_bytes(u[6:8], 'big'), int.from_bytes(u[8:10], 'big'),
                            int.from_bytes(u[10:16], 'big')))
            elif atype == 0x16 and len(data) >= 2:  # Service Data - 16-bit UUID
                uuid16 = '0x%04x' % struct.unpack_from('<H', data, 0)[0]
                service_data.append({'uuid': uuid16, 'data': data[2:].hex()})
            elif atype == 0x20 and len(data) >= 4:  # Service Data - 32-bit UUID
                uuid32 = '0x%08x' % struct.unpack_from('<I', data, 0)[0]
                service_data.append({'uuid': uuid32, 'data': data[4:].hex()})
            elif atype == 0x21 and len(data) >= 16:  # Service Data - 128-bit UUID
                u = data[0:16][::-1]
                uuid128 = '%08x-%04x-%04x-%04x-%012x' % (
                    int.from_bytes(u[0:4], 'big'), int.from_bytes(u[4:6], 'big'),
                    int.from_bytes(u[6:8], 'big'), int.from_bytes(u[8:10], 'big'),
                    int.from_bytes(u[10:16], 'big'))
                service_data.append({'uuid': uuid128, 'data': data[16:].hex()})
        if service_uuids:
            res.setdefault('service_uuids', [])
            res['service_uuids'].extend(service_uuids)
        if service_data:
            res.setdefault('service_data', [])
            res['service_data'].extend(service_data)

    def parse(self, macPDU: bytes) -> dict:
        res = {
            'is_adv': False,
            'is_connect_req': False,
            'is_scan_req': False,
            'is_scan_rsp': False,
            'pdu_type': None,
            'pdu_type_name': None,
            'tx_addr_random': None,
            'adv_addr': None,
            'tx_power': None,
            'name': None,
            'manufacturer': None,
            'tlvs': [],
            'connect': None,
            'raw_payload': b'',
            'service_uuids': [],
            'service_data': [],
        }
        if not macPDU or len(macPDU) < 2:
            return res

        # Some captures include the 4-byte BLE advertising access address
        # (0x8E89BED6, on-air bytes d6 be 89 8e) before the Link Layer PDU.
        if len(macPDU) >= 4 and macPDU[0:4] == b'\xd6\xbe\x89\x8e':
            macPDU = macPDU[4:]

        if len(macPDU) < 2:
            return res

        hdr0 = macPDU[0]
        hdr1 = macPDU[1]
        pdu_type = hdr0 & 0x0F
        res['pdu_type'] = pdu_type
        res['pdu_type_name'] = self.PDU_TYPE_NAMES.get(pdu_type, 'UNKNOWN')
        res['tx_addr_random'] = bool(hdr0 & 0x40)  # TxAdd bit
        length = hdr1 & 0x3F
        payload = macPDU[2:2 + length]
        res['raw_payload'] = payload

        if pdu_type in self.ADV_TYPES_WITH_ADDR_AND_DATA:
            res['is_adv'] = True
            if len(payload) >= 6:
                adv_addr = payload[0:6]
                res['adv_addr'] = self._format_addr(adv_addr)
                adv_data = payload[6:]
            else:
                adv_data = b''
            self._parse_ad_structures(res, adv_data)
            """
            for atype, data in self._parse_tlvs(adv_data):
                res['tlvs'].append((atype, data))
                if atype == 0x0A and len(data) >= 1:  # TX Power Level
                    res['tx_power'] = struct.unpack('b', data[0:1])[0]
                elif atype in (0x08, 0x09) and len(data) >= 1:  # Shortened/Complete Local Name
                    try:
                        res['name'] = data.decode('utf-8', errors='replace')
                    except Exception:
                        pass
                elif atype == 0xFF and len(data) >= 2:  # Manufacturer Specific Data
                    # Keep the raw bytes (company ID + payload) as hex so a
                    # downstream consumer (e.g. ble_identify.py on the
                    # aggregator) can decode it. Do NOT collapse this into a
                    # summary dict - that throws away the very bytes needed
                    # for identification and is why nothing showed up
                    # downstream before.
                    res['manufacturer'] = data.hex()
            """
        elif pdu_type == 0x5:  # CONNECT_REQ
            res['is_connect_req'] = True
            connect = self._parse_connect_req(payload)
            res['connect'] = connect
            if connect:
                res['adv_addr'] = connect['adv_addr']

        elif pdu_type == 0x3:  # SCAN_REQ
            
            if len(payload) >= 12:
                res['is_scan_req'] = True
                
                res['scanner_addr'] = self._format_addr(payload[0:6])
                res['adv_addr'] = self._format_addr(payload[6:12])
        elif pdu_type == 0x4:  # SCAN_RSP
                    
            if len(payload) >= 6:
                res['is_scan_rsp'] = True
                res['adv_addr'] = self._format_addr(payload[0:6])   # <-- the fix
                self._parse_ad_structures(res, payload[6:])
        return res

    def handle(self, frame, rssi=None):
        mac = frame.get_macpdu()
        if mac is None:
            return
        mac = bytes(mac)
        parsed = self.parse(mac)
        setattr(frame, 'parsed', parsed)

        if parsed.get('is_connect_req') and parsed.get('connect'):
            c = parsed['connect']
            logger.info("CONNECT_REQ init=%s -> adv=%s AA=%s hop=%d chans=%d" %
                        (c['init_addr'], c['adv_addr'], c['access_address'],
                         c['hop_increment'], c['num_used_channels']))
        elif parsed.get('is_adv'):
            logger.debug("ADV %s addr=%s name=%s rssi=%s" %
                        (parsed.get('pdu_type_name'), parsed.get('adv_addr'),
                         parsed.get('name'), rssi))

        if self.callback:
            try:
                self.callback(parsed, frame, rssi)
            except Exception:
                logger.exception("BLEAdvParserHandler callback failed")


#####################################
# ZMQ publisher
#####################################
class ZmqPublishHandler(object):
    """Publishes parsed BLE frames as JSON on a ZMQ PUB socket.

    Only frames that BLEAdvParserHandler successfully tagged with
    `frame.parsed` are published (register this handler *after*
    BLEAdvParserHandler in the handler list).
    """

    def __init__(self, bind_addr, source_id=None):
        if zmq is None:
            raise RuntimeError(
                "pyzmq is not installed. Install it with: "
                "pip install pyzmq --break-system-packages")

        self.bind_addr = bind_addr
        self.source_id = source_id or ('%s:%s' % (pysocket.gethostname(), bind_addr))

        self.ctx = zmq.Context.instance()
        self.sock = self.ctx.socket(zmq.PUB)
        # Don't let a slow/absent subscriber build up unbounded memory.
        self.sock.setsockopt(zmq.SNDHWM, 1000)
        self.sock.setsockopt(zmq.LINGER, 0)
        self.sock.bind(bind_addr)

        stats['Published to ZMQ'] = 0
        stats['ZMQ Send Dropped'] = 0

        # PUB sockets drop messages sent before a SUB has connected and
        # completed its subscription handshake ("slow joiner" problem).
        # A short sleep here just gives an already-running subscriber a
        # moment to (re)connect after this process (re)starts.
        time.sleep(0.2)

        logger.info("ZMQ publisher bound to %s (source_id=%s)" %
                    (bind_addr, self.source_id))

    def handle(self, frame, rssi=None):
        parsed = getattr(frame, 'parsed', None)
        if parsed is None:
            return

        # Only publish things worth showing on the dashboard.
        if not parsed.get('is_adv') and not parsed.get('is_connect_req') and not parsed.get('is_scan_req') and not parsed.get('is_scan_rsp'):
            return

        msg = {
            'source': self.source_id,
            'ts': frame.get_timestamp(),          # sniffer-reported usec timestamp
            'recv_ts': time.time(),               # wall-clock time on this host
            'channel': frame.channel,              # RF channel index (0-39)
            'rssi': rssi,
            'crc_ok': frame.crc_ok,
            'pdu_type': parsed.get('pdu_type_name'),
        }

        if parsed.get('is_connect_req'):
            msg['event'] = 'connect_req'
            msg['connect'] = parsed.get('connect')
        elif parsed.get('is_adv'):
            
            msg['event'] = 'adv'
            msg['adv_addr'] = parsed.get('adv_addr')
            msg['tx_addr_random'] = parsed.get('tx_addr_random')
            msg['tx_power'] = parsed.get('tx_power')
            msg['name'] = parsed.get('name')
            msg['manufacturer'] = parsed.get('manufacturer')
            msg['service_uuids'] = parsed.get('service_uuids')
            msg['service_data'] = parsed.get('service_data')
        elif parsed.get('is_scan_req'):
            msg['event'] = 'scan_req'
            
            msg['scanner_addr'] = parsed.get('scanner_addr')
            msg['adv_addr'] = parsed.get('adv_addr')
        elif parsed.get('is_scan_rsp'):
            msg['event'] = 'scan_rsp'
                    
            #msg['scanner_addr'] = parsed.get('scanner_addr')
            msg['adv_addr'] = parsed.get('adv_addr')
            msg['service_uuids'] = parsed.get('service_uuids')
            msg['service_data'] = parsed.get('service_data')

        try:
            self.sock.send_string(json.dumps(msg), flags=zmq.NOBLOCK)
            stats['Published to ZMQ'] += 1
        except zmq.Again:
            stats['ZMQ Send Dropped'] += 1
        except Exception:
            logger.exception("Failed to publish frame over ZMQ")

    def close(self):
        try:
            self.sock.close(linger=0)
        except Exception:
            pass
#####################################
# class CC2540
#####################################

class CC2540:

    DEFAULT_CHANNEL = 0x0B  # 11

    DATA_EP = 0x83
    DATA_TIMEOUT = 2500

    DIR_OUT = 0x40
    DIR_IN = 0xc0

    GET_IDENT = 0xc0
    SET_POWER = 0xc5
    GET_POWER = 0xc6

    SET_START = 0xd0
    SET_STOP = 0xd1
    SET_CHAN = 0xd2

    COMMAND_FRAME = 0x00
    COMMAND_KEEPALIVE = 0x01
    COMMAND_UNKNOWN = 0X02 # has 69 bytes to be investigated

    # Off by default: we haven't verified this against real hardware. Turn on
    # with --trailing-byte-is-channel once you've confirmed (via -D DEBUG logs)
    # that the trailing byte(s) logged in recv() really do track the current
    # data channel (0-36) while a connection is being followed.
    TRAILING_BYTE_IS_CHANNEL = False

    def __init__(self, callback, channel=DEFAULT_CHANNEL, usb_address=None):
        """usb_address: optional (bus, address) tuple to select a specific
        dongle when more than one CC2540 is plugged into the same host."""

        stats['Captured'] = 0
        stats['Non-Frame'] = 0

        self.dev = None
        self.channel = channel
        self.callback = callback
        self.thread = None
        self.running = False

        try:
            if usb_address is not None:
                bus, address = usb_address
                for d in usb.core.find(find_all=True, idVendor=0x0451, idProduct=0x16b3):
                    if d.bus == bus and d.address == address:
                        self.dev = d
                        break
            else:
                self.dev = usb.core.find(idVendor=0x0451, idProduct=0x16b3)
        except usb.core.USBError:
            raise OSError(errno.EACCES,
                          "Permission denied, you need to add an udev rule for this device")

        if self.dev is None:
            raise IOError("Device not found")

        self.dev.set_configuration()
        self.name = self.dev.product or "CC2540 Sniffer Dongle"
        self.ident = self.dev.ctrl_transfer(CC2540.DIR_IN, CC2540.GET_IDENT, 0, 0, 256)

        self.dev.ctrl_transfer(CC2540.DIR_OUT, CC2540.SET_POWER, wIndex=4)

        while True:
            power_status = self.dev.ctrl_transfer(CC2540.DIR_IN, CC2540.GET_POWER, 0, 0, 1)
            if power_status[0] == 4:
                break
            time.sleep(0.1)

        self.set_channel(channel)
        self._rxbuf = bytearray()   # add this: leftover partial bytes across reads

    def __del__(self):
        if self.dev:
            try:
                self.dev.ctrl_transfer(self.DIR_OUT, self.SET_POWER, wIndex=0)
            except Exception:
                pass

    def start(self):
        self.running = True
        self.dev.ctrl_transfer(CC2540.DIR_OUT, CC2540.SET_START)
        self.thread = threading.Thread(target=self.recv)
        self.thread.daemon = True
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join()
        self.dev.ctrl_transfer(CC2540.DIR_OUT, CC2540.SET_STOP)

    def isRunning(self):
        return self.running

    def _handle_command_frame(self, body: bytes):
        if len(body) < 5:
            logger.warning("Frame body too short for header: %s", hexdump(body))
            return
        (timestamp, pktLen) = struct.unpack_from("<IB", body)
        frame_buf = body[5:]
    
        if len(frame_buf) < pktLen:
            logger.warning(
                "Received a frame with incorrect length, pktLen:%d, len(frame_buf):%d, frame_buf=%s",
                pktLen, len(frame_buf), hexdump(frame_buf))
            return
    
        pdu_with_fcs = frame_buf[:pktLen]
        trailing = frame_buf[pktLen:]
    
        if len(pdu_with_fcs) >= 2:
            fcs1, fcs2 = pdu_with_fcs[-2:]
        else:
            fcs1, fcs2 = 0, 0
    
        rssi = (fcs1 + 2**7) % 2**8 - 2**7 - 73
        crc_ok = fcs2 & (1 << 7) > 0
        channel = fcs2 & 0x7F
        pdu = pdu_with_fcs[:-2] if len(pdu_with_fcs) >= 2 else pdu_with_fcs
    
        if trailing:
            logger.debug('Trailing bytes after PDU (possible channel/follow metadata): %s',
                        binascii.hexlify(bytes(trailing)).decode())
    
        observed_channel = channel
        if CC2540.TRAILING_BYTE_IS_CHANNEL and len(trailing) >= 1:
            observed_channel = trailing[0]
    
        self.callback(timestamp, bytes(pdu), rssi, self.channel, crc_ok, observed_channel)
    

    def recv(self):
        while self.running:
            try:
                bytesteam = self.dev.read(CC2540.DATA_EP, 4096, timeout=CC2540.DATA_TIMEOUT)
            except usb.core.USBError as e:
                if e.errno == 110:
                    continue
                else:
                    raise e
    
            self._rxbuf.extend(bytesteam)
    
            # Consume as many complete commands as are currently available;
            # leave any trailing partial command in self._rxbuf for the next read.
            while len(self._rxbuf) >= 3:
                cmd, cmdLen = struct.unpack_from("<BH", self._rxbuf, 0)
                total = 3 + cmdLen
                if len(self._rxbuf) < total:
                    logger.debug(
                        "Waiting for more data: cmd=%02x cmdLen=%d, have %d/%d bytes so far",
                        cmd, cmdLen, len(self._rxbuf), total)
                    break  # not enough yet -- wait for the next dev.read()
    
                body = bytes(self._rxbuf[3:total])
                del self._rxbuf[:total]  # consume this command, keep any remainder
    
                if cmd == CC2540.COMMAND_FRAME:
                    logger.debug('Read a frame of size %d' % (cmdLen,))
                    stats['Captured'] += 1
                    self._handle_command_frame(body)
                elif cmd == CC2540.COMMAND_KEEPALIVE and cmdLen == 1:
                    logger.debug("Received keepalive")
                    def _reset():
                        try:
                            self.set_channel(self.channel)
                        except Exception:
                            logger.exception("Keepalive channel reset failed")
                    threading.Thread(target=_reset, daemon=True).start()
                else:
                    logger.warning(
                        "Unknown command code CMD:%02x cmdLen:%d, body=%s",
                        cmd, cmdLen, hexdump(body))
                    

    def set_channel(self, channel):
        was_running = self.running

        if 37 <= channel <= 39:
            if self.running:
                self.stop()

            self.channel = channel
            self.dev.ctrl_transfer(CC2540.DIR_OUT, CC2540.SET_CHAN, 0, 0, [channel])
            self.dev.ctrl_transfer(CC2540.DIR_OUT, CC2540.SET_CHAN, 0, 1, [0x00])
            self.get_channel()

            if was_running:
                self.start()
        else:
            raise ValueError("Channel must be between 37 and 39")

    def get_channel(self):
        return self.channel

    def __repr__(self):
        if self.dev:
            return "%s <Channel: %d>" % (self.name, self.channel)
        else:
            return "Not connected"


def arg_parser():
    debug_choices = ('DEBUG', 'INFO', 'WARN', 'ERROR')

    parser = argparse.ArgumentParser(add_help=False,
                                     description='Read IEEE802.15.4/BLE frames \
    from a CC2540 packet sniffer device, convert them to pcap, pipe them \
    into wireshark, and/or publish parsed events over ZMQ for a live \
    dashboard.')

    in_group = parser.add_argument_group('Input Options')
    in_group.add_argument('-c', '--channel', type=int, action='store',
                          choices=range(37, 40),
                          default=defaults['channel'],
                          help='Set the sniffer\'s CHANNEL. Valid range: 37-39. \
                                  (Default: %s)' % (defaults['channel'],))
    in_group.add_argument('--usb-bus-address', action='store', default=None,
                          help='Select a specific dongle when more than one CC2540 \
                                  is plugged into this host, as "bus:address" \
                                  (see `lsusb`). If omitted, the first CC2540 found is used.')

    out_group = parser.add_argument_group('Output Options')
    out_group.add_argument('-f', '--fifo', action='store',
                           default=defaults['out_fifo'],
                           help='Set FIFO as the named pipe for sending to wireshark. \
                                   (Default: %s)' % (defaults['out_fifo'],))
    out_group.add_argument('-o', '--offline', action='store_true',
                           default=False,
                           help='Disables sending the capture to the named pipe.')
    out_group.add_argument('-x', '--hex-file', action='store', nargs='?',
                           const=defaults['hex_file'], default=False,
                           help='Save the capture (hexdump) in HEX_FILE.')
    out_group.add_argument('-p', '--pcap-file', action='store', nargs='?',
                           const=defaults['pcap_file'], default=False,
                           help='Save the capture (pcap format) in PCAP_FILE.')
    out_group.add_argument('-z', '--zmq-pub', action='store', nargs='?',
                           const=defaults['zmq_bind'], default=False,
                           help='Publish parsed BLE events as JSON on a ZMQ PUB socket \
                                   bound to ZMQ_PUB (e.g. tcp://*:5555). If -z is given \
                                   without a value, %s is used.' % (defaults['zmq_bind'],))
    out_group.add_argument('--zmq-source-id', action='store', default=None,
                           help='Identifier included in every published message \
                                   (e.g. "pi-ch37"). Defaults to "<hostname>:<zmq-bind>".')
    out_group.add_argument('--trailing-byte-is-channel', action='store_true',
                           default=False,
                           help='EXPERIMENTAL: interpret a byte found after the PDU in the raw \
                                   USB frame as the real per-packet data channel (0-36) reported \
                                   by firmware that auto-follows connections. Verify with \
                                   -D DEBUG first (look for "Trailing bytes..." log lines) before \
                                   trusting this - see README.')

    mon_group = parser.add_argument_group('Monitoring-only Options')
    mon_group.add_argument('--anti-follow', action='store_true', default=False,
                           help='EXPERIMENTAL: if the dongle firmware auto-follows a connection \
                                   onto the data channels after a CONNECT_REQ, immediately re-issue \
                                   SET_CHAN back to the configured advertising channel to try to pull \
                                   it back to advertising-only monitoring. There is no documented \
                                   "disable follow" command for this firmware, so this is a \
                                   best-effort workaround, not a guarantee.')
    mon_group.add_argument('--anti-follow-cooldown', type=float, default=0.5,
                           help='Minimum seconds between anti-follow retunes (default 0.5), to \
                                   avoid hammering the USB control endpoint if several CONNECT_REQ \
                                   frames arrive in a burst.')

    log_group = parser.add_argument_group('Verbosity and Logging')
    log_group.add_argument('-d', '--headless', action='store_true',
                           default=False,
                           help='Run in non-interactive/headless mode. (Default Disabled)')
    log_group.add_argument('-D', '--debug-level', action='store',
                           choices=debug_choices,
                           default=defaults['debug_level'],
                           help='Console verbosity (Default %s)' % (defaults['debug_level'],))
    log_group.add_argument('-L', '--log-file', action='store', nargs='?',
                           const=defaults['log_file'], default=False,
                           help='Log output in LOG_FILE.')
    log_group.add_argument('-l', '--log-level', action='store',
                           choices=debug_choices,
                           default=defaults['log_level'],
                           help='Log verbosity (Default %s)' % (defaults['log_level'],))

    gen_group = parser.add_argument_group('General Options')
    gen_group.add_argument('-v', '--version', action='version',
                           version='ccsniffpiper v%s' % (__version__))
    gen_group.add_argument('-h', '--help', action='help',
                           help='Shows this message and exits')

    return parser.parse_args()

def dump_stats():
    s = StringIO()
    s.write('Frame Stats:\n')
    for k, v in stats.items():
        s.write('%20s: %d\n' % (k, v))
    print(s.getvalue())

def log_init(args):
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(getattr(logging, args.debug_level))
    cf = logging.Formatter('%(message)s')
    ch.setFormatter(cf)
    logger.addHandler(ch)

    if args.log_file is not False:
        fh = logging.handlers.RotatingFileHandler(filename=args.log_file, maxBytes=5000000)
        fh.setLevel(getattr(logging, args.log_level))
        ff = logging.Formatter('%(asctime)s - %(levelname)8s - %(message)s')
        fh.setFormatter(ff)
        logger.addHandler(fh)


if __name__ == '__main__':
    args = arg_parser()
    log_init(args)

    logger.info('Started logging')

    CC2540.TRAILING_BYTE_IS_CHANNEL = args.trailing_byte_is_channel
    if args.trailing_byte_is_channel:
        logger.warning('--trailing-byte-is-channel is enabled: per-packet channel will be taken '
                      'from an unverified trailing byte. Watch for "Ignoring implausible observed '
                      'channel byte" warnings, which mean the hypothesis is wrong for your firmware.')

    handlers = []
    zmq_handler = None
    sniffer_holder = {'dev': None}
    last_anti_follow = {'ts': 0.0}

    def maybe_anti_follow(parsed):
        """Best-effort: if the firmware just followed a CONNECT_REQ onto the
        data channels, retune it straight back to the configured advertising
        channel. There's no documented "disable follow" command for this
        firmware, so this works by interrupting/undoing the follow rather
        than preventing it outright - see README for caveats."""
        if not args.anti_follow or not parsed or not parsed.get('is_connect_req'):
            return
        now = time.time()
        if now - last_anti_follow['ts'] < args.anti_follow_cooldown:
            return
        last_anti_follow['ts'] = now
        dev = sniffer_holder['dev']
        if dev is None:
            return

        def _retune():
            try:
                ch = dev.get_channel()
                logger.warning('CONNECT_REQ seen - retuning back to advertising channel %d (anti-follow)', ch)
                dev.set_channel(ch)
            except Exception:
                logger.exception('anti-follow retune failed')

        # Must run on a separate thread: set_channel() -> stop() joins the
        # CC2540 recv thread, and we are currently *being called from* that
        # same recv thread (via the USB read callback chain), so calling it
        # inline here would deadlock.
        threading.Thread(target=_retune, daemon=True).start()

    # Parser handler must run before ZmqPublishHandler / anything that
    # depends on frame.parsed being populated.
    parser_handler = BLEAdvParserHandler()
    handlers.append(parser_handler)

    def ble_to_rf_channel(ch):
        if ch == 37:
            return 0
        elif ch == 38:
            return 12
        elif ch == 39:
            return 39
        elif 0 <= ch <= 10:
            return ch + 1
        elif 11 <= ch <= 36:
            return ch + 2
        else:
            raise ValueError("Invalid BLE channel %d" % ch)

    def handlerDispatcher(timestamp, macPDU, rssi=None, channel=37, crc_ok=None, observed_channel=None):
        if len(macPDU) > 0:
            # observed_channel (0-36) comes from the trailing byte in the raw
            # USB frame when CC2540.TRAILING_BYTE_IS_CHANNEL is enabled - i.e.
            # the actual data channel the firmware was on when it captured this
            # specific packet, which can differ from the last channel *we*
            # commanded once the firmware starts following a connection.
            # ble_to_rf_channel() already handles both ranges (37-39 adv, or
            # 0-36 data) using the real BLE channel-index formula.
            effective_ble_channel = observed_channel if observed_channel is not None else channel
            try:
                rf_channel = ble_to_rf_channel(effective_ble_channel)
            except ValueError:
                logger.warning("Ignoring implausible observed channel byte %r, falling back to commanded channel %d",
                              observed_channel, channel)
                rf_channel = ble_to_rf_channel(channel)
            frame = Frame(macPDU, timestamp, rssi, rf_channel, crc_ok)
            for h in handlers:
                h.handle(frame, rssi)
            maybe_anti_follow(getattr(frame, 'parsed', None))

    if args.offline is not True:
        f = FifoHandler(out_fifo=args.fifo)
        handlers.append(f)
    if args.hex_file is not False:
        handlers.append(HexdumpHandler(args.hex_file))
    if args.pcap_file is not False:
        handlers.append(PcapDumpHandler(args.pcap_file))
    if args.zmq_pub is not False:
        zmq_handler = ZmqPublishHandler(args.zmq_pub, source_id=args.zmq_source_id)
        handlers.append(zmq_handler)

    if args.headless is False:
        h = StringIO()
        h.write('Commands:\n')
        h.write('c: Print current RF Channel\n')
        h.write('n: Trigger new pcap header before the next frame\n')
        h.write('h,?: Print this message\n')
        h.write('[37,39]: Change BLE advertising channel\n')
        h.write('s: Start/stop the packet capture\n')
        h.write('q: Quit')
        h = h.getvalue()
        print(h)

    usb_address = None
    if args.usb_bus_address:
        b, a = args.usb_bus_address.split(':')
        usb_address = (int(b), int(a))

    snifferDev = CC2540(handlerDispatcher, args.channel, usb_address=usb_address)
    sniffer_holder['dev'] = snifferDev
    try:
        while 1:
            if args.headless is True:
                if not snifferDev.isRunning():
                    snifferDev.start()
                snifferDev.thread.join()
            else:
                try:
                    if select.select([sys.stdin, ], [], [], 10.0)[0]:
                        cmd = sys.stdin.readline().rstrip()
                        logger.debug('User input: "%s"' % (cmd,))
                        if cmd in ('h', '?'):
                            print(h)
                        elif cmd == 'c':
                            print('Sniffing in channel: %d' % (snifferDev.get_channel(),))
                        elif cmd == 'n':
                            if 'f' in dir() and hasattr(f, 'triggerNewGlobalHeader'):
                                f.triggerNewGlobalHeader()
                        elif cmd == 'q':
                            logger.info('User requested shutdown')
                            sys.exit(0)
                        elif cmd == 's':
                            if snifferDev.isRunning():
                                snifferDev.stop()
                            else:
                                snifferDev.start()
                        elif cmd.isdigit() and int(cmd) in range(37, 40):
                            snifferDev.set_channel(int(cmd))
                        else:
                            raise ValueError('Unknown Command. Type h or ? for help')
                except select.error:
                    logger.warning('Error while trying to read stdin')
                except ValueError as e:
                    print(e)

    except (KeyboardInterrupt, SystemExit):
        logger.info('Shutting down')
        if snifferDev.isRunning():
            snifferDev.stop()
        if zmq_handler:
            zmq_handler.close()
        dump_stats()
        sys.exit(0)