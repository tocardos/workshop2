#include <NimBLEDevice.h>

/*
 * Awareness-session demo beacon.
 *
 * A long message is split into numbered chunks. Each chunk is
 * advertised in sequence; a sniffer that collects the frames can
 * reassemble the full message from the (index / total) header.
 *
 * Manufacturer data layout per frame:
 *
 *   byte 0-1 : 0xFF 0xFF  (demo/private manufacturer ID)
 *   byte 2   : total number of chunks
 *   byte 3   : index of this chunk (0 .. total-1)
 *   byte 4   : XOR checksum of the chunk bytes (integrity demo)
 *   byte 5.. : up to CHUNK_PAYLOAD bytes of message text
 *
 * IMPORTANT: this version uses LEGACY advertising
 * (NimBLEAdvertising, 31-byte payload). Extended advertising
 * frames are invisible to many phone apps / scan filters
 * (nRF Connect for Mobile shows nothing), while legacy adverts
 * are displayed everywhere. The cost: no device name in the
 * frame (mfg data fills the payload).
 */

static const char *MESSAGE =
    "EAVESDROPPING DEMO: THIS TEXT IS TOO LONG FOR ONE BLE FRAME. "
    "A SNIFFER CAN REASSEMBLE IT BY COLLECTING ALL CHUNKS. "
    "BE MINDFUL OF WHAT YOUR DEVICES BROADCAST.";

#define MFG_ID      0xFF
#define HEADER_LEN  5          // id(2) + total(1) + index(1) + checksum(1)
#define CHUNK_PAYLOAD  20      // 5 + 20 = 25 bytes, fits the 31-byte legacy payload

static uint8_t chunkCount = 0;
static uint8_t currentChunk = 0;

static uint8_t frame[HEADER_LEN + CHUNK_PAYLOAD];

static uint8_t xorChecksum(const uint8_t *data, size_t len)
{
    uint8_t c = 0;
    for (size_t i = 0; i < len; i++)
        c ^= data[i];
    return c;
}

void setup()
{
    Serial.begin(115200);
    delay(500);

    Serial.println();
    Serial.println("Starting BLE awareness beacon (sequenced payload, legacy adv)...");

    NimBLEDevice::init("");

    size_t msgLen = strlen(MESSAGE);
    chunkCount = (msgLen + CHUNK_PAYLOAD - 1) / CHUNK_PAYLOAD;

    Serial.print("Message length: ");
    Serial.println(msgLen);
    Serial.print("Chunks: ");
    Serial.println(chunkCount);

    Serial.println();
    Serial.println("========================================");
    Serial.println("BLE AWARENESS BEACON ACTIVE");
    Serial.println("========================================");
    Serial.println("Frame layout: FF FF | total | index | checksum | data");
    Serial.println();
}

void loop()
{
    size_t offset = (size_t)currentChunk * CHUNK_PAYLOAD;
    size_t len = strlen(MESSAGE + offset);
    if (len > CHUNK_PAYLOAD)
        len = CHUNK_PAYLOAD;

    /*
     * Build the manufacturer-specific payload.
     */
    frame[0] = MFG_ID;
    frame[1] = MFG_ID;
    frame[2] = chunkCount;
    frame[3] = currentChunk;
    frame[4] = xorChecksum((const uint8_t *)(MESSAGE + offset), len);

    memcpy(&frame[HEADER_LEN], MESSAGE + offset, len);

    size_t frameLen = HEADER_LEN + len;

    /*
     * Rebuild the legacy advertisement with this chunk.
     * (A 31-byte legacy payload needs no name; scan-response
     *  data would eat another 31 bytes if you ever need more.)
     */
    NimBLEAdvertisementData advData;
    advData.setManufacturerData(std::string((char *)frame, frameLen));

    NimBLEAdvertising *advertising = NimBLEDevice::getAdvertising();
    advertising->stop();
    advertising->setAdvertisementData(advData);
    advertising->setMinInterval(48);   // ~30 ms
    advertising->setMaxInterval(80);   // ~50 ms

    if (!advertising->start())
    {
        Serial.println("ERROR: advertising start failed");
        return;
    }

    Serial.print("Chunk ");
    Serial.print(currentChunk + 1);
    Serial.print("/");
    Serial.print(chunkCount);
    Serial.print(" -> ");
    for (size_t i = 0; i < frameLen; i++)
    {
        if (frame[i] < 16) Serial.print("0");
        Serial.print(frame[i], HEX);
        Serial.print(" ");
    }
    Serial.println();

    currentChunk = (currentChunk + 1) % chunkCount;

    /*
     * Advertise each chunk for ~1.5 s so that any sniffer in
     * range reliably catches every frame of the sequence.
     */
    delay(1500);
}