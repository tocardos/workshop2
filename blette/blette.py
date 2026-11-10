#!/usr/bin/env python3
"""
Multi-dongle BLE PCAP capture with ZMQ deduplicated forwarding.
Captures on channels 37, 38, 39 (hci0, hci1, hci2) and forwards unique packets via ZMQ.
"""
# Copyright (c) 2026, Vincent Demanet
#
# Licensed under the EUPL, Version 1.2 or - as soon they will be approved
# by the European Commission - subsequent versions of the EUPL (the "Licence");
# You may not use this work except in compliance with the Licence.
# You may obtain a copy of the Licence at:
#
#     https://joinup.ec.europa.eu/software/page/eupl
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the Licence is distributed on an "AS IS" basis,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the Licence for the specific language governing permissions and
# limitations under the Licence.
import asyncio
import aioblescan as aiobs
import zmq
import zmq.asyncio
import json
import struct
import time
import hashlib
import logging
from datetime import datetime
from collections import OrderedDict
from dataclasses import dataclass
from typing import Optional, Set, Dict, List
from contextlib import asynccontextmanager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger('ble_capture')

def hci_index(name: str) -> int:
    # "hci0" -> 0, "hci1" -> 1, etc.
    return int(name.replace("hci", ""))


PDU_TYPE_NAMES = {
    0: 'ADV_IND', 1: 'ADV_DIRECT_IND', 2: 'ADV_NONCONN_IND',
    3: 'SCAN_REQ', 4: 'SCAN_RSP', 5: 'CONNECT_REQ',
    6: 'ADV_SCAN_IND', 7: 'ADV_IND (legacy scan request)',
}


def parse_le_advertising_report(data: bytes) -> Optional[dict]:
    """
    Parse a raw HCI LE Advertising Report event (0x3E / subevent 0x02)
    and pull out the fields ble_aggregator.py expects.

    Returns None if `data` is not a well-formed advertising report.
    """
    # HCI packet: [0]=0x04 (event), [1]=0x3E (LE meta), [2]=len,
    # [3]=0x02 (adv report subevent), [4]=num_reports, then per report:
    # evt_type(1) addr_type(1) addr(6) data_len(1) data(n) rssi(1)
    if len(data) < 12 or data[0] != 0x04 or data[1] != 0x3E or data[3] != 0x02:
        return None

    evt_type = data[5]
    addr_type = data[6]                      # 0 = public, 1 = random
    addr = data[7:13]
    data_len = data[13]
    adv_data = data[14:14 + data_len]
    rssi = data[14 + data_len] if len(data) > 14 + data_len else None

    out = {
        'pdu_type': PDU_TYPE_NAMES.get(evt_type, f'0x{evt_type:02x}'),
        'tx_addr_random': addr_type == 1,
        # ble_aggregator normalizes to upper-case for its own keys, but the
        # convention from its publisher side is lower-case addresses.
        'adv_addr': ':'.join(f'{b:02x}' for b in addr),
        'rssi': struct.unpack('b', bytes([rssi]))[0] if rssi is not None else None,
        'name': None,
        'manufacturer': None,
        'tx_power': None,
        'service_data': None,
        'service_uuids': None,
    }

    if evt_type == 3:  # SCAN_REQ: bytes 7:13 are the scanner, not the target
        out['scanner_addr'] = out.pop('adv_addr')
        out['target_addr'] = ':'.join(f'{b:02x}' for b in adv_data[:6])
        return out

    # Walk the AD structures for name / manufacturer data / tx power /
    # service data / service UUIDs.
    uuids = []
    i = 0
    while i + 1 < len(adv_data):
        ad_len = adv_data[i]
        if ad_len == 0 or i + 1 + ad_len > len(adv_data):
            break
        ad_type = adv_data[i + 1]
        payload = adv_data[i + 2:i + 1 + ad_len]
        if ad_type in (0x08, 0x09) and not out['name']:
            try:
                out['name'] = payload.decode('utf-8', errors='replace').rstrip('\x00')
            except Exception:
                pass
        elif ad_type == 0xFF and not out['manufacturer']:
            # Manufacturer Specific Data: company ID (2 bytes LE) + payload.
            # Aggregator wants the hex of the whole AD *value*.
            out['manufacturer'] = payload.hex()
        elif ad_type == 0x0A:
            out['tx_power'] = struct.unpack('b', payload[:1])[0] if payload else None
        elif ad_type == 0x16 and not out['service_data']:
            out['service_data'] = payload.hex()
        elif ad_type in (0x02, 0x03, 0x04, 0x05, 0x06, 0x07):
            for j in range(0, len(payload) - 1, 2):
                uuids.append(payload[j:j + 2].hex())
        i += 1 + ad_len
    if uuids:
        out['service_uuids'] = uuids

    return out

@dataclass
class BLEPacket:
    """Represents a deduplicated BLE packet."""
    timestamp: float
    channel: int
    hci_device: str
    raw_data: bytes
    rssi: Optional[int] = None
    address: Optional[str] = None
    packet_type: Optional[str] = None
    
    @property
    def fingerprint(self) -> str:
        """Generate a fingerprint for deduplication (ignores RSSI and channel)."""
        # Use MAC address + payload for deduplication key
        # This catches same packet broadcast on multiple channels
        if self.address:
            # Hash address + payload (excluding RSSI which varies by channel/distance)
            # raw_data is a full HCI event packet whose last byte is the RSSI,
            # so strip it or the same packet heard on ch37/38/39 never matches.
            data_to_hash = f"{self.address}:{self.raw_data[:-1].hex()}"
        else:
            # Fallback: hash the raw packet data
            data_to_hash = self.raw_data.hex()
        return hashlib.sha256(data_to_hash.encode()).hexdigest()[:32]
    
    def to_pcap_record_orig(self) -> bytes:
        """Convert to PCAP record format."""
        ts_sec = int(self.timestamp)
        ts_usec = int((self.timestamp - ts_sec) * 1_000_000)
        
        # PCAP packet header: ts_sec, ts_usec, incl_len, orig_len
        pcap_header = struct.pack(
            '<IIII',
            ts_sec,
            ts_usec,
            len(self.raw_data),
            len(self.raw_data)
        )
        return pcap_header + self.raw_data
    def to_pcap_record(self) -> bytes:
        """Convert to PCAP record format."""
        ts_sec = int(self.timestamp)
        ts_usec = int((self.timestamp - ts_sec) * 1_000_000)

        # 4-byte direction pseudo-header required by BLUETOOTH_HCI_H4_WITH_PHDR:
        # 0x00000000 = sent (host->controller), 0x00000001 = received (controller->host)
        direction = struct.pack('>I', 1)  # all our packets are controller->host
        frame = direction + self.raw_data

        pcap_header = struct.pack(
            '<IIII',
            ts_sec,
            ts_usec,
            len(frame),
            len(frame)
        )
        return pcap_header + frame


class PacketDeduplicator:
    """
    Sliding window deduplicator for BLE packets.
    Removes duplicates that appear across different channels.
    """
    
    def __init__(self, window_seconds: float = 2.0, max_size: int = 10000):
        self.window_seconds = window_seconds
        self.max_size = max_size
        self.seen_packets: OrderedDict[str, float] = OrderedDict()
        self.lock = asyncio.Lock()
    
    async def is_unique(self, packet: BLEPacket) -> bool:
        """Check if packet is unique within the time window."""
        async with self.lock:
            now = time.time()
            fingerprint = packet.fingerprint
            
            # Clean old entries
            self._cleanup_old(now)
            
            if fingerprint in self.seen_packets:
                # Update timestamp to extend window (sliding window)
                self.seen_packets.move_to_end(fingerprint)
                self.seen_packets[fingerprint] = now
                return False
            
            self.seen_packets[fingerprint] = now
            return True
    
    def _cleanup_old(self, now: float):
        """Remove entries older than window."""
        cutoff = now - self.window_seconds
        # Remove from the beginning (oldest)
        while self.seen_packets and next(iter(self.seen_packets.values())) < cutoff:
            self.seen_packets.popitem(last=False)
        
        # Hard limit on size
        while len(self.seen_packets) > self.max_size:
            self.seen_packets.popitem(last=False)


class PCAPWriter:
    """Handles PCAP file writing with proper headers."""
    """
    PCAP_GLOBAL_HEADER = struct.pack(
        '<IHHiIII',
        0xa1b2c3d4,  # Magic number (little endian)
        2,           # Major version
        4,           # Minor version
        0,           # Timezone (GMT)
        0,           # Sigfigs
        65535,       # Snaplen
        251          # Link type: BLUETOOTH_LE_LL (251)
    )
    """
    PCAP_GLOBAL_HEADER = struct.pack(
    '<IHHiIII',
    0xa1b2c3d4,  # Magic number (little endian)
    2,           # Major version
    4,           # Minor version
    0,           # Timezone (GMT)
    0,           # Sigfigs
    65535,       # Snaplen
    #187          # Link type: BLUETOOTH_HCI_H4 (was 251/LE_LL â wrong, caused the corruption)
    201             # BLUETOOTH_HCI_H4_WITH_PHDR
    )
    
    def __init__(self, filename: str):
        self.filename = filename
        self.file = None
        self.lock = asyncio.Lock()
        self.packet_count = 0
    
    async def open(self):
        """Open PCAP file and write global header."""
        self.file = open(self.filename, 'wb')
        self.file.write(self.PCAP_GLOBAL_HEADER)
        logger.info(f"PCAP file opened: {self.filename}")
    
    async def write_packet(self, packet: BLEPacket):
        """Write a single packet to PCAP."""
        async with self.lock:
            if self.file:
                self.file.write(packet.to_pcap_record())
                self.packet_count += 1
                # Flush periodically
                if self.packet_count % 100 == 0:
                    self.file.flush()
    
    async def close(self):
        """Close PCAP file."""
        if self.file:
            self.file.close()
            logger.info(f"PCAP file closed. Total packets: {self.packet_count}")


class BLECapture:
    """
    BLE capture manager for multiple HCI devices.
    Each device captures on a specific advertising channel.
    """
    
    # BLE Advertising channels mapping
    CHANNELS = {
        37: 2402,  # Channel 37
        38: 2426,  # Channel 38
        39: 2480,  # Channel 39
    }
    
    def __init__(
        self,
        hci_devices: List[str],
        pcap_file: str,
        zmq_endpoint: str = "tcp://127.0.0.1:5555",
        dedup_window: float = 2.0
    ):
        self.hci_devices = hci_devices
        self.pcap = PCAPWriter(pcap_file)
        self.deduplicator = PacketDeduplicator(window_seconds=dedup_window)
        self.zmq_context = zmq.asyncio.Context()
        self.zmq_socket = self.zmq_context.socket(zmq.PUB)
        self.zmq_endpoint = zmq_endpoint
        self.capture_tasks: List[asyncio.Task] = []
        self.running = False
        
        # Statistics
        self.stats = {
            'total_received': 0,
            'unique_forwarded': 0,
            'duplicates_dropped': 0,
            'per_device': {dev: {'received': 0, 'unique': 0} for dev in hci_devices}
        }
    
    async def start(self):
        """Start capture on all devices."""
        await self.pcap.open()
        self.zmq_socket.bind(self.zmq_endpoint)
        logger.info(f"ZMQ publisher bound to {self.zmq_endpoint}")
        
        self.running = True
        
        # Start capture task for each HCI device
        for idx, hci in enumerate(self.hci_devices):
            channel = list(self.CHANNELS.keys())[idx % len(self.CHANNELS)]
            task = asyncio.create_task(
                self._capture_loop(hci, channel),
                name=f"capture_{hci}_ch{channel}"
            )
            self.capture_tasks.append(task)
            logger.info(f"Started capture on {hci} -> Channel {channel}")
        
        # Start stats reporter
        stats_task = asyncio.create_task(self._stats_reporter(), name="stats")
        self.capture_tasks.append(stats_task)
    
    async def stop(self):
        """Stop all captures gracefully."""
        self.running = False
        
        # Cancel all tasks
        for task in self.capture_tasks:
            task.cancel()
        
        await asyncio.gather(*self.capture_tasks, return_exceptions=True)
        await self.pcap.close()
        self.zmq_socket.close()
        self.zmq_context.term()
        logger.info("Capture stopped")
    
    async def _capture_loop(self, hci_device: str, channel: int):
        """
        Main capture loop for a single HCI device.
        Sets up BLE scanning on specific channel and processes packets.
        """
        try:
            # Create event loop for this device
            event_loop = asyncio.get_event_loop()
            
            # Create BT socket
            bt_socket = aiobs.create_bt_socket(hci_index(hci_device))
            
            # Create message processor
            fac = event_loop._create_connection_transport(
                bt_socket,
                aiobs.BLEScanRequester,
                None,
                None
            )
            conn, bt_ctrl = await fac
            
            # Configure scan parameters
            # Set scan type to active (0x01) or passive (0x00)
            bt_ctrl.send_scan_request()
            
            # Set channel (this requires specific HCI commands)
            # Note: aioblescan handles channel hopping, but we want fixed channel per dongle
            # We use the passive scan approach
            
            logger.info(f"{hci_device}: Scanning started on channel {channel}")
            
            while self.running:
                try:
                    # Process received packet
                    # aioblescan uses a callback approach, we need to adapt it
                    packet = await self._get_packet(bt_ctrl, hci_device, channel)
                    if packet:
                        await self._process_packet(packet)
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    logger.error(f"{hci_device}: Error processing packet: {e}")
                    await asyncio.sleep(0.1)
            
            conn.close()
            
        except asyncio.CancelledError:
            logger.info(f"{hci_device}: Capture task cancelled")
        except Exception as e:
            logger.error(f"{hci_device}: Fatal error: {e}")
    
    async def _get_packet(self, bt_ctrl, hci_device: str, channel: int) -> Optional[BLEPacket]:
        """
        Extract packet from aioblescan controller.
        This is a simplified version - in practice you'd hook into aioblescan's callback.
        """
        # aioblescan processes packets via its internal mechanism
        # We need to access the raw packet data
        
        # For this implementation, we'll use a queue-based approach
        # In practice, you'd modify aioblescan or use its callback system
        
        # Placeholder: In real implementation, this would come from aioblescan's packet callback
        # The actual implementation depends on aioblescan's API version
        
        # Here's how you'd typically extract it:
        if hasattr(bt_ctrl, 'last_packet') and bt_ctrl.last_packet:
            raw_data = bt_ctrl.last_packet
            bt_ctrl.last_packet = None
            
            # Parse basic info from packet
            rssi = None
            address = None
            
            # Try to extract RSSI and address from raw data
            if len(raw_data) >= 10:
                # Simple parsing - adjust based on actual packet format
                address = raw_data[3:9].hex(':')
                rssi = struct.unpack('b', raw_data[-1:])[0] if len(raw_data) > 10 else None
            
            return BLEPacket(
                timestamp=time.time(),
                channel=channel,
                hci_device=hci_device,
                raw_data=raw_data,
                rssi=rssi,
                address=address
            )
        
        await asyncio.sleep(0.001)  # Small yield
        return None
    
    async def _process_packet(self, packet: BLEPacket):
        """Process a captured packet: deduplicate, write to PCAP, forward via ZMQ."""
        self.stats['total_received'] += 1
        self.stats['per_device'][packet.hci_device]['received'] += 1
        
        # Check uniqueness
        is_unique = await self.deduplicator.is_unique(packet)
        
        if is_unique:
            self.stats['unique_forwarded'] += 1
            self.stats['per_device'][packet.hci_device]['unique'] += 1
            
            # Write to PCAP
            await self.pcap.write_packet(packet)
            
            # Forward via ZMQ
            await self._zmq_forward(packet)
        else:
            self.stats['duplicates_dropped'] += 1
    
    async def _zmq_forward(self, packet: BLEPacket):
        """Forward unique packet via ZMQ."""
        try:
            # Create JSON-like message
            message = {
                'timestamp': packet.timestamp,
                'channel': packet.channel,
                'hci_device': packet.hci_device,
                'rssi': packet.rssi,
                'address': packet.address,
                'raw_hex': packet.raw_data.hex(),
                'pcap_record': packet.to_pcap_record().hex()
            }
            
            # Send as multipart: topic + data
            topic = f"ble.ch{packet.channel}".encode()
            data = str(message).encode()
            
            await self.zmq_socket.send_multipart([topic, data])
            
        except Exception as e:
            logger.error(f"ZMQ forward error: {e}")
    
    async def _stats_reporter(self):
        """Periodically report capture statistics."""
        while self.running:
            await asyncio.sleep(10)
            total = self.stats['total_received']
            unique = self.stats['unique_forwarded']
            dupes = self.stats['duplicates_dropped']
            
            if total > 0:
                dedup_rate = (dupes / total) * 100
                logger.info(
                    f"Stats: Total={total}, Unique={unique}, "
                    f"Duplicates={dupes} ({dedup_rate:.1f}%), "
                    f"Dedup savings={dupes}"
                )
                for dev, dev_stats in self.stats['per_device'].items():
                    logger.info(
                        f"  {dev}: recv={dev_stats['received']}, "
                        f"unique={dev_stats['unique']}"
                    )


class AioblescanCapture(BLECapture):
    """
    Improved implementation using aioblescan's actual API.
    Hooks into aioblescan's packet processing callbacks.
    """
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.packet_queues: Dict[str, asyncio.Queue] = {
            dev: asyncio.Queue(maxsize=1000) for dev in self.hci_devices
        }
    
    async def _capture_loop(self, hci_device: str, channel: int):
        """
        Capture loop using aioblescan's proper API.
        """
        try:
            # Create event loop
            event_loop = asyncio.get_event_loop()
            
            # Create socket
            bt_socket = aiobs.create_bt_socket(hci_index(hci_device))
            
            # Create transport and protocol
            transport, protocol = await event_loop._create_connection_transport(
                bt_socket,
                lambda: self._create_scanner(hci_device, channel),
                None,
                None
            )
            
            # Start scanning
            if hasattr(protocol, 'send_scan_request'):
                protocol.send_scan_request()
            
            logger.info(f"{hci_device}: Started scanning on channel {channel}")
            
            # Keep connection alive
            while self.running:
                await asyncio.sleep(1)
            
            transport.close()
            
        except asyncio.CancelledError:
            logger.info(f"{hci_device}: Capture stopped")
        except Exception as e:
            logger.error(f"{hci_device}: Error: {e}")
    
    def _create_scanner(self, hci_device: str, channel: int):
        """Create a custom BLEScanRequester that forwards packets to our queue."""
        scanner = aiobs.BLEScanRequester()
        
        # Hook into packet processing
        original_process = scanner.process_packet if hasattr(scanner, 'process_packet') else None
        
        def custom_process(data):
            """Custom packet processor that queues packets for deduplication."""
            # Create packet object
            packet = BLEPacket(
                timestamp=time.time(),
                channel=channel,
                hci_device=hci_device,
                raw_data=data,
                rssi=getattr(scanner, 'last_rssi', None),
                address=getattr(scanner, 'last_address', None)
            )
            
            # Try to put in queue (drop if full to avoid memory issues)
            try:
                self.packet_queues[hci_device].put_nowait(packet)
            except asyncio.QueueFull:
                logger.warning(f"{hci_device}: Queue full, dropping packet")
            
            # Call original processor if exists
            if original_process:
                original_process(data)
        
        # Replace processor
        if hasattr(scanner, 'process_packet'):
            scanner.process_packet = custom_process
        
        # Also hook data_received if needed
        return scanner
    
    async def start(self):
        """Override start to also start queue processors."""
        await super().start()
        
        # Start queue processor tasks
        for dev in self.hci_devices:
            task = asyncio.create_task(
                self._queue_processor(dev),
                name=f"processor_{dev}"
            )
            self.capture_tasks.append(task)
    
    async def _queue_processor(self, hci_device: str):
        """Process packets from device queue."""
        queue = self.packet_queues[hci_device]
        
        while self.running:
            try:
                packet = await asyncio.wait_for(queue.get(), timeout=1.0)
                await self._process_packet(packet)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break


# ============== PRODUCTION-READY IMPLEMENTATION ==============

class ProductionBLECapture:
    """
    Production-ready BLE capture using aioblescan with proper event handling.
    This is the recommended implementation.
    """
    
    def __init__(
        self,
        hci_devices: List[str] = ["hci0", "hci1", "hci2"],
        pcap_file: Optional[str] = None,
        zmq_endpoint: str = "tcp://127.0.0.1:5555",
        dedup_window: float = 2.0,
        channel_map: Optional[Dict[str, int]] = None
    ):
        self.hci_devices = hci_devices
        self.pcap_file = pcap_file or f"ble_capture_{datetime.now():%Y%m%d_%H%M%S}.pcap"
        self.zmq_endpoint = zmq_endpoint
        self.dedup_window = dedup_window
        
        # Map devices to channels (default: hci0->37, hci1->38, hci2->39)
        self.channel_map = channel_map or {
            hci: 37 + (i % 3) for i, hci in enumerate(hci_devices)
        }
        
        # Deduplication
        self.deduplicator = PacketDeduplicator(window_seconds=dedup_window)
        
        # ZMQ
        self.zmq_context = zmq.asyncio.Context()
        self.zmq_socket: Optional[zmq.asyncio.Socket] = None
        
        # PCAP
        self.pcap: Optional[PCAPWriter] = None
        
        # Packet queues from devices
        self.queues: Dict[str, asyncio.Queue] = {
            dev: asyncio.Queue(maxsize=5000) for dev in hci_devices
        }
        
        # Tasks
        self.tasks: List[asyncio.Task] = []
        self.running = False
        
        # Stats
        self.stats = {
            'total': 0,
            'unique': 0,
            'dropped': 0,
            'by_device': {dev: 0 for dev in hci_devices}
        }
    
    async def run(self):
        """Main entry point."""
        self.running = True
        
        # Initialize outputs
        self.pcap = PCAPWriter(self.pcap_file)
        await self.pcap.open()
        
        self.zmq_socket = self.zmq_context.socket(zmq.PUB)
        self.zmq_socket.bind(self.zmq_endpoint)
        self.zmq_socket.setsockopt(zmq.SNDHWM, 1000)
        logger.info(f"ZMQ bound to {self.zmq_endpoint}")
        
        # Start device captures
        for dev in self.hci_devices:
            task = asyncio.create_task(self._device_capture(dev), name=f"cap_{dev}")
            self.tasks.append(task)
        
        # Start queue processors
        for dev in self.hci_devices:
            task = asyncio.create_task(self._process_queue(dev), name=f"proc_{dev}")
            self.tasks.append(task)
        
        # Start stats
        self.tasks.append(asyncio.create_task(self._stats_loop(), name="stats"))
        
        # Wait for all tasks
        try:
            await asyncio.gather(*self.tasks, return_exceptions=True)
        except asyncio.CancelledError:
            pass
        finally:
            await self.shutdown()
    
    async def shutdown(self):
        """Graceful shutdown."""
        self.running = False
        
        for task in self.tasks:
            if not task.done():
                task.cancel()
        
        await asyncio.gather(*self.tasks, return_exceptions=True)
        
        if self.pcap:
            await self.pcap.close()
        
        if self.zmq_socket:
            self.zmq_socket.close()
        
        self.zmq_context.term()
        logger.info("Shutdown complete")
    
    async def _device_capture(self, hci_device: str):
        """
        Capture packets from a single HCI device using aioblescan.
        """
        channel = self.channel_map.get(hci_device, 37)
        queue = self.queues[hci_device]
        
        try:
            loop = asyncio.get_event_loop()
            
            # Create Bluetooth socket
            logger.info(f"{hci_device}: creating socket...")
            bt_socket = aiobs.create_bt_socket(hci_index(hci_device))
            #print(f"btsocket {bt_socket}")
            # Create protocol instance with custom callback
            protocol = BLECaptureProtocol(
                device=hci_device,
                channel=channel,
                queue=queue
            )
            
            # Create transport
            logger.info(f"{hci_device}: creating transport...")
            transport, _ = await loop._create_connection_transport(
                bt_socket,
                lambda: protocol,
                None,
                None
            )
            logger.info(f"{hci_device}: transport created")
            # Send scan enable command
            await protocol.send_scan_request()
            
            logger.info(f"{hci_device}: Scanning on channel {channel}")
            
            # Keep alive
            while self.running:
                await asyncio.sleep(1)
            
            transport.close()
            
        except asyncio.CancelledError:
            logger.info(f"{hci_device}: Capture cancelled")
        except Exception as e:
            logger.error(f"{hci_device}: Capture error: {e}")
    
    async def _process_queue(self, hci_device: str):
        """Process packets from a device's queue."""
        queue = self.queues[hci_device]
        
        while self.running:
            try:
                packet: BLEPacket = await asyncio.wait_for(queue.get(), timeout=0.5)
                await self._handle_packet(packet)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
    
    async def _handle_packet(self, packet: BLEPacket):
        """Deduplicate and forward packet."""
        self.stats['total'] += 1
        self.stats['by_device'][packet.hci_device] += 1
        
        # Deduplicate
        is_unique = await self.deduplicator.is_unique(packet)
        
        if not is_unique:
            self.stats['dropped'] += 1
            return
        
        self.stats['unique'] += 1
        
        # Write to PCAP
        if self.pcap:
            await self.pcap.write_packet(packet)
        
        # Forward via ZMQ
        await self._zmq_send(packet)
    
    async def _zmq_send(self, packet: BLEPacket):
        """Send packet via ZMQ as a single JSON frame that matches the
        ble_aggregator.py message schema."""
        if not self.zmq_socket:
            return

        rep = parse_le_advertising_report(packet.raw_data)
        if rep is None:
            # Not an advertising report (e.g. some other HCI event) -- skip.
            return

        pdu_type = rep['pdu_type']

        if pdu_type == 'SCAN_REQ':
            msg = {
                'event': 'scan_req',
                'ts': packet.timestamp,
                'source': packet.hci_device,
                'channel': packet.channel,
                'scanner_addr': rep['scanner_addr'],
                'adv_addr': rep['target_addr'],
                'rssi': rep['rssi'],
                'tx_addr_random': rep['tx_addr_random'],
            }
        elif pdu_type == 'SCAN_RSP':
            msg = {
                'event': 'scan_rsp',
                'ts': packet.timestamp,
                'source': packet.hci_device,
                'channel': packet.channel,
                'adv_addr': rep['adv_addr'],
                'rssi': rep['rssi'],
                'pdu_type': 'SCAN_RSP',
            }
            if rep['name']:
                msg['name'] = rep['name']
            if rep['manufacturer']:
                msg['manufacturer'] = rep['manufacturer']
            if rep['service_uuids']:
                msg['service_uuids'] = rep['service_uuids']
            if rep['service_data']:
                msg['service_data'] = rep['service_data']
        elif pdu_type == 'CONNECT_REQ':
            msg = {
                'event': 'connect_req',
                'ts': packet.timestamp,
                'source': packet.hci_device,
                'channel': packet.channel,
                'adv_addr': rep['adv_addr'],
                'rssi': rep['rssi'],
            }
        else:
            msg = {
                'event': 'adv',
                'ts': packet.timestamp,
                'source': packet.hci_device,
                'channel': packet.channel,
                'adv_addr': rep['adv_addr'],
                'rssi': rep['rssi'],
                'pdu_type': rep['pdu_type'],
                'tx_addr_random': rep['tx_addr_random'],
                'crc_ok': True,  # the kernel already drops CRC-failed frames
            }
            if rep['name']:
                msg['name'] = rep['name']
            if rep['manufacturer']:
                # hex string of company ID + payload -- this is what lets the
                # aggregator identify vendor / device type / Continuity frames
                msg['manufacturer'] = rep['manufacturer']
            if rep['tx_power'] is not None:
                msg['tx_power'] = rep['tx_power']
            if rep['service_data']:
                msg['service_data'] = rep['service_data']
            if rep['service_uuids']:
                msg['service_uuids'] = rep['service_uuids']

        try:
            # Single-frame JSON string: ble_aggregator does
            # sock.recv_string() + json.loads() on the whole message.
            # (No topic prefix, no multipart, no Python str(dict) repr.)
            await self.zmq_socket.send_string(
                json.dumps(msg), flags=zmq.NOBLOCK
            )
        except zmq.Again:
            logger.warning("ZMQ send buffer full")
        except Exception as e:
            logger.error(f"ZMQ send error: {e}")
    
    async def _stats_loop(self):
        """Print periodic statistics."""
        while self.running:
            await asyncio.sleep(30)
            
            total = self.stats['total']
            unique = self.stats['unique']
            dropped = self.stats['dropped']
            
            if total > 0:
                rate = (unique / total) * 100
                logger.info(
                    f"[STATS] Total: {total}, Unique: {unique} ({rate:.1f}%), "
                    f"Dropped: {dropped}, Per-device: {self.stats['by_device']}"
                )


class BLECaptureProtocol(aiobs.BLEScanRequester):
    """
    Custom aioblescan protocol that captures raw packets and queues them.
    """
    
    def __init__(self, device: str, channel: int, queue: asyncio.Queue):
        super().__init__()
        self.device = device
        self.channel = channel
        self.queue = queue
        self.last_rssi = None
        self.process = self.handle_packet
    
    def process_packet1(self, data):
        """
        Override to capture raw packet data.
        aioblescan calls this when a BLE packet is received.
        """
        # Extract RSSI if available in data
        self.last_rssi = self._extract_rssi(data)
        
        # Extract address
        address = self._extract_address(data)
        
        # Create packet
        packet = BLEPacket(
            timestamp=time.time(),
            channel=self.channel,
            hci_device=self.device,
            raw_data=data,
            rssi=self.last_rssi,
            address=address
        )
        
        # Queue it (drop if full)
        try:
            self.queue.put_nowait(packet)
        except asyncio.QueueFull:
            pass
        
        # Call parent for normal processing
        #super().process_packet(data)
    def handle_packet(self, data): 
        #print("handle packet")
        ev = aiobs.HCI_Event()
        toto=ev.decode(data) 
        rssi = ev.retrieve("rssi")
        if rssi:
            self.last_rssi = rssi[0].val         
        #self.last_rssi = ev.retrieve("rssi")
        peer = ev.retrieve("peer")
        address=None
        if peer:
            address = peer[0].val
        else:
            print(f"error: no peer address in packet from {toto}")
        #address = self._extract_address(data)
        packet = BLEPacket(
            timestamp=time.time(),
            channel=self.channel,
            hci_device=self.device,
            raw_data=data,
            rssi=self.last_rssi,
            address=address,
        )
        try:
            self.queue.put_nowait(packet)
        except asyncio.QueueFull:
            pass
    
    
    def _extract_rssi(self, data: bytes) -> Optional[int]:
        """Try to extract RSSI from HCI event."""
        if len(data) >= 14:
            # RSSI is typically last byte of LE Advertising Report
            try:
                return struct.unpack('b', data[-1:])[0]
            except:
                pass
        return None
    
    def _extract_address(self, data: bytes) -> Optional[str]:
        """Try to extract BD_ADDR from packet."""
        # This is a simplified extraction
        # Real implementation depends on packet type
        if len(data) >= 12:
            # Address usually starts at offset 3-9 for advertising packets
            try:
                addr_bytes = data[3:9]
                return ':'.join(f'{b:02x}' for b in addr_bytes)
            except:
                pass
        return None


# ============== ZMQ SUBSCRIBER EXAMPLE ==============

class ZMQSubscriber:
    """
    Example ZMQ subscriber to receive deduplicated BLE packets.
    """
    
    def __init__(self, endpoint: str = "tcp://127.0.0.1:5555"):
        self.endpoint = endpoint
        self.context = zmq.asyncio.Context()
        self.socket = self.context.socket(zmq.SUB)
        self.socket.setsockopt_string(zmq.SUBSCRIBE, "")
    
    async def receive(self):
        """Receive packets."""
        self.socket.connect(self.endpoint)
        logger.info(f"Subscriber connected to {self.endpoint}")
        
        try:
            while True:
                data = await self.socket.recv_string()
                msg = json.loads(data)

                print(f"[{msg['ts']:.3f}] {msg['event'].upper()} "
                      f"CH{msg.get('channel')} RSSI:{msg.get('rssi')} "
                      f"ADDR:{msg.get('adv_addr') or msg.get('scanner_addr')} "
                      f"NAME:{msg.get('name')}")
        except asyncio.CancelledError:
            pass
        finally:
            self.socket.close()
            self.context.term()


# ============== MAIN ==============

async def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Multi-dongle BLE capture')
    parser.add_argument('--devices', nargs='+', default=['hci0', 'hci1', 'hci2'],
                       help='HCI devices to use')
    parser.add_argument('--pcap', default=None,
                       help='Output PCAP file')
    parser.add_argument('--zmq', default='tcp://127.0.0.1:5555',
                       help='ZMQ endpoint')
    parser.add_argument('--window', type=float, default=2.0,
                       help='Deduplication window in seconds')
    parser.add_argument('--subscribe', action='store_true',
                       help='Run as ZMQ subscriber only')
    
    args = parser.parse_args()
    
    if args.subscribe:
        sub = ZMQSubscriber(args.zmq)
        await sub.receive()
    else:
        capture = ProductionBLECapture(
            hci_devices=args.devices,
            pcap_file=args.pcap,
            zmq_endpoint=args.zmq,
            dedup_window=args.window
        )
        
        # Handle shutdown signals
        loop = asyncio.get_event_loop()
        for sig in ('SIGINT', 'SIGTERM'):
            loop.add_signal_handler(
                getattr(__import__('signal'), sig),
                lambda: asyncio.create_task(capture.shutdown())
            )
        
        await capture.run()


if __name__ == '__main__':
    asyncio.run(main())