import asyncio
from bleak import BleakScanner


def detection_callback(device, advertisement_data):
    print()
    print("-" * 70)

    print("ADDRESS :", device.address)
    print("NAME    :", device.name)
    print("RSSI    :", advertisement_data.rssi)

    print("LOCAL   :", advertisement_data.local_name)

    print("MFG DATA:")
    for company_id, data in advertisement_data.manufacturer_data.items():
        print(
            f"  company=0x{company_id:04X} "
            f"length={len(data)} "
            f"hex={data.hex(' ')}"
        )

        # Try to decode as text
        try:
            print("  text  :", data.decode("utf-8", errors="replace"))
        except Exception:
            pass

    print("SERVICE DATA:")
    for uuid, data in advertisement_data.service_data.items():
        print(
            f"  uuid={uuid} "
            f"data={data.hex(' ')}"
        )


async def main():

    print("Starting BLE scan...")
    print("Press Ctrl-C to stop.")
    print()

    scanner = BleakScanner(
        detection_callback=detection_callback
    )

    await scanner.start()

    try:
        while True:
            await asyncio.sleep(1)

    except KeyboardInterrupt:
        print("\nStopping...")

    finally:
        await scanner.stop()


asyncio.run(main())