import asyncio
from bleak import BleakScanner

# The beacon's demo manufacturer ID (0xFF 0xFF in little-endian = 0xFFFF)
DEMO_COMPANY_ID = 0xFFFF
# Bleak strips the 2-byte company ID from manufacturer_data,
# so the value starts directly at the chunk header (no FF FF prefix).
HEADER_LEN = 3  # total(1) + index(1) + checksum(1)

document_chunks = {}
document_total = None


def xor_checksum(data):
    c = 0
    for b in data:
        c ^= b
    return c


def show_short_message(message, device, rssi):

    print()
    print("=" * 70)
    print("BLE BUILDING BEACON")
    print("=" * 70)
    print(f"Beacon : {device.name}")
    print(f"Address: {device.address}")
    print(f"RSSI   : {rssi} dBm")
    print()
    print("PAYLOAD:")
    print(message)
    print("=" * 70)


def handle_document_chunk(
    chunk_number,
    total,
    payload,
    device,
    rssi
):

    global document_chunks
    global document_total

    document_total = total

    document_chunks[chunk_number] = payload

    received = len(document_chunks)

    print()
    print(
        f"DOCUMENT SECURITY: "
        f"chunk {chunk_number}/{total}"
    )

    print(
        f"Received: {received}/{total}"
    )

    percentage = int(
        received * 100 / total
    )

    bar_length = 40
    filled = int(
        bar_length * received / total
    )

    bar = (
        "#" * filled +
        "-" * (bar_length - filled)
    )

    print(
        f"[{bar}] {percentage}%"
    )

    if received == total:

        print()
        print("=" * 70)
        print("DOCUMENT RECONSTRUCTED")
        print("=" * 70)

        missing = [
            i
            for i in range(total)
            if i not in document_chunks
        ]

        if missing:
            print("Missing chunks:", missing)
            return

        document = "".join(
            document_chunks[i]
            for i in range(total)
        )

        print()
        print(document)
        print()
        print("=" * 70)

        document_chunks.clear()
        document_total = None


def handle_binary_chunk(data, device, rssi):
    """
    Parse the beacon's frame as delivered by Bleak.

    On the air the frame is:

        byte 0-1 : 0xFF 0xFF  (demo manufacturer ID)
        byte 2   : total number of chunks
        byte 3   : index of this chunk (0 .. total-1)
        byte 4   : XOR checksum of the text bytes
        byte 5.. : chunk text (utf-8)

    but Bleak already parsed and removed the company ID,
    so here the data starts at "total":

        byte 0 : total
        byte 1 : index
        byte 2 : checksum
        byte 3.. : chunk text
    """

    if len(data) < HEADER_LEN:
        return

    total = data[0]
    index = data[1]
    checksum = data[2]
    text_bytes = data[HEADER_LEN:]

    if total == 0 or index >= total:
        return

    # Integrity check: recompute the XOR checksum.
    if xor_checksum(text_bytes) != checksum:
        print(
            f"INTEGRITY FAIL on chunk {index}: "
            f"expected {checksum:02X}, "
            f"computed {xor_checksum(text_bytes):02X}"
        )
        return

    try:
        payload = text_bytes.decode("utf-8", errors="replace")
    except Exception:
        return

    handle_document_chunk(
        index,
        total,
        payload,
        device,
        rssi
    )


def detection_callback(device, advertisement_data):

    for company_id, data in (
        advertisement_data
        .manufacturer_data
        .items()
    ):

        #
        # Binary beacon frame (our ESP32 sketch).
        #
        # Note: we match on the manufacturer ID, not the device
        # name, because the beacon fills its 31-byte legacy
        # payload with manufacturer data and has no room for a name.
        #
        if company_id == DEMO_COMPANY_ID:
            handle_binary_chunk(
                data,
                device,
                advertisement_data.rssi
            )
            continue

        #
        # Legacy text formats kept from the original script.
        #
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            continue

        rssi = advertisement_data.rssi

        #
        # Normal beacon message
        #
        if text.startswith("B|"):

            fields = text.split("|", 2)

            if len(fields) == 3:

                _, beacon_id, message = fields

                show_short_message(
                    message,
                    device,
                    rssi
                )

        #
        # Document chunk
        #
        elif text.startswith("D|"):

            fields = text.split("|", 4)

            if len(fields) != 5:
                return

            _, document_id, chunk, total, payload = fields

            try:
                chunk_number = int(chunk)
                total_chunks = int(total)
            except ValueError:
                return

            handle_document_chunk(
                chunk_number,
                total_chunks,
                payload,
                device,
                rssi
            )


async def main():

    print(
        "Scanning for BLE awareness beacons..."
    )

    print(
        "Press Ctrl-C to stop."
    )

    scanner = BleakScanner(
        detection_callback=detection_callback
    )

    await scanner.start()

    try:
        while True:
            await asyncio.sleep(1)

    except KeyboardInterrupt:
        pass

    finally:
        await scanner.stop()


asyncio.run(main())