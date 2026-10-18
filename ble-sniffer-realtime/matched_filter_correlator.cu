//
// matched_filter_correlator.cu
//
// Drop-in replacement for the burst-qualification step currently done by
// the "8 alternating transitions" heuristic in bfscan_channel() /
// detect_ble_packets() (bleprocessor_float.cu). Correlates the hard-bit
// stream against the KNOWN preamble+AccessAddress bit pattern using
// Hamming distance, which is far more selective and far more tolerant
// of noise/CFO than transition counting -- important once srate drops
// to 1 sample/bit (1 MHz PFB bins).
//
// Usage pattern: call ble_preamble_match<<<>>>() BEFORE
// detect_ble_packets<<<>>>() to produce a candidate mask; only run the
// expensive header/CRC extraction on candidates that pass here. This
// keeps the overall kernel cost profile similar to today (still one
// pass over the bit buffer per candidate check) while cutting false
// positives that would otherwise feed CRC-doomed extractions.
//
// BLE preamble+AA framing (LE 1M / LE 2M, uncoded PHY):
//   - Preamble: 8 bits, fixed pattern. Value is 0xAA if the LSB of the
//     Access Address is 1, else 0x55 (per BT Core spec, Vol 6, Part B,
//     2.1) -- this keeps the transition into the AA's own edge smooth.
//   - Access Address: 32 bits. For primary advertising channels this
//     is the fixed public value 0x8E89BED6. For data channels it's the
//     per-connection AA already tracked in conn_list[] (aa_is_known()).
//   - Preamble and AA are transmitted least-significant-bit first and
//     are NOT whitened (only PDU+CRC are whitened) -- so this is a
//     literal, fixed 40-bit target pattern per AA, safe to hardcode
//     or compute once on the host and pass in as a kernel arg.
//

#include <cstdint>
#include <cuda_runtime_api.h>

#define PREAMBLE_LEN 8
#define AA_LEN 32
#define TEMPLATE_LEN (PREAMBLE_LEN + AA_LEN)   // 40 bits total

// Tune based on observed noise floor / CFO. At srate=1 (Nyquist) start
// around 4-6 out of 40 bits (~10-15% BER tolerance) and tighten once you
// see real CRC-pass statistics; too loose re-admits the false-positive
// flood you were trying to avoid, too tight rejects real bursts under CFO.
#ifndef MAX_HAMMING_DIST
#define MAX_HAMMING_DIST 5
#endif

// ---------------------------------------------------------------------
// Host-side helper: build the 40-bit reference pattern for a given AA.
// Call once per known AA (advertising AA is fixed; per-connection AAs
// come from conn_list and change only when clean_aa_table() updates it).
// Bit ordering matches how detect_ble_packets() already reads bits[]:
// LSB-first per byte, byte 0 = preamble, bytes 1-4 = AA.
// ---------------------------------------------------------------------
__host__ inline void build_reference_pattern(uint32_t access_address,
                                              uint8_t out_bits[TEMPLATE_LEN])
{
    uint8_t preamble = (access_address & 0x1) ? 0xAA : 0x55;

    for (int b = 0; b < PREAMBLE_LEN; ++b)
        out_bits[b] = (preamble >> b) & 0x1;   // LSB first

    for (int b = 0; b < AA_LEN; ++b)
        out_bits[PREAMBLE_LEN + b] = (access_address >> b) & 0x1;
}

// Pack a 40-bit reference into two uint32_t words for fast device-side
// compare (avoids a 40-entry constant-memory array + branchy loop).
__host__ inline void pack_reference(const uint8_t bits[TEMPLATE_LEN],
                                     uint32_t* lo40, uint32_t* hi40 /* only 8 bits used */)
{
    uint32_t lo = 0, hi = 0;
    for (int b = 0; b < 32; ++b) lo |= (uint32_t)bits[b] << b;
    for (int b = 0; b < 8; ++b)  hi |= (uint32_t)bits[32 + b] << b;
    *lo40 = lo;
    *hi40 = hi;
}

// ---------------------------------------------------------------------
// Device kernel: sliding Hamming-distance correlator.
//
// bits[]      : hard-bit array (1 bit stored per byte, LSB), same layout
//               detect_ble_packets() already consumes.
// buflen      : samples in this channel's slice.
// srate       : samples per bit (1 for 1 MHz bins / LE1M, 2 for the old
//               2 MHz-bin layout, etc).
// ref_lo/hi   : packed reference pattern from pack_reference().
// out_mask    : output, one byte per candidate start index; nonzero
//               means "passed the correlator, run full extraction here".
//               Reuses the same bits[i] |= flag convention as today if
//               you'd rather OR a bit into the existing array instead
//               of a separate buffer -- see commented alternative below.
// ---------------------------------------------------------------------
__global__
void ble_preamble_match(const uint8_t* __restrict__ bits,
                         size_t buflen,
                         size_t srate,
                         uint32_t ref_lo, uint32_t ref_hi,
                         uint8_t* __restrict__ out_mask)
{
    unsigned int i = (blockIdx.x * blockDim.x) + threadIdx.x;

    // Need TEMPLATE_LEN bit-periods of headroom past this index.
    if (i >= buflen - (TEMPLATE_LEN + 1) * srate) {
        if (i < buflen) out_mask[i] = 0;
        return;
    }

    int mismatches = 0;

    // First 32 bits (preamble + first 24 bits of AA) via packed word.
    #pragma unroll
    for (int b = 0; b < 32; ++b) {
        uint8_t observed = bits[i + b * srate] & 0x1;
        uint8_t expected = (ref_lo >> b) & 0x1;
        mismatches += (observed != expected);
        // Early-exit: bail once we've blown the budget. This keeps the
        // common case (random noise, most windows) cheap -- most threads
        // exit within the first 8-12 bits.
        if (mismatches > MAX_HAMMING_DIST) {
            out_mask[i] = 0;
            return;
        }
    }

    // Remaining 8 bits of AA.
    #pragma unroll
    for (int b = 0; b < 8; ++b) {
        uint8_t observed = bits[i + (32 + b) * srate] & 0x1;
        uint8_t expected = (ref_hi >> b) & 0x1;
        mismatches += (observed != expected);
        if (mismatches > MAX_HAMMING_DIST) {
            out_mask[i] = 0;
            return;
        }
    }

    out_mask[i] = 1;   // candidate burst -- caller runs full header/CRC extraction
}

// ---------------------------------------------------------------------
// Host-side dispatch sketch: how this slots into chan_processing().
// Replaces the "run detect_ble_packets on every index" pattern with
// "correlate first, then extract only on matches" -- same kernel launch
// shape, but detect_ble_packets' own internal work only needs to run
// its full header+CRC path where out_mask[i] is nonzero, which you can
// implement either as an early-return guard inside detect_ble_packets
// itself (simplest: pass out_mask in and `if (!out_mask[i]) return;`
// as the first line) or as a stream-compaction pass if you want to
// avoid launching threads for the ~99% of indices that never match.
// ---------------------------------------------------------------------
/*
void chan_processing_with_correlator(...)
{
    // Advertising AA is fixed -- build/pack once at startup, not per-frame.
    static uint32_t adv_ref_lo, adv_ref_hi;
    static bool adv_ref_built = false;
    if (!adv_ref_built) {
        uint8_t pat[TEMPLATE_LEN];
        build_reference_pattern(0x8E89BED6, pat);
        pack_reference(pat, &adv_ref_lo, &adv_ref_hi);
        adv_ref_built = true;
    }

    for (int ch = 0; ch < DECFACTOR; ch++) {
        if (is_adv_chan(blechan)) {
            ble_preamble_match<<<nblocks, nthreads>>>(
                binbuf + ..., samps_per_chan, LE1M_SRATE,
                adv_ref_lo, adv_ref_hi, candidate_mask + ...);

            detect_ble_packets<<<nblocks, nthreads>>>(
                binbuf + ..., samps_per_chan, blechan, conn_list, LE1M_SRATE);
                // ^ add `if (!candidate_mask[i]) return;` as its first line
        }
        // For data channels with per-connection AAs, either loop known
        // AAs from conn_list (small MAX_NUM_CONN=128, cheap to iterate
        // on host and launch one correlator pass per known AA), or keep
        // the existing bfscan_channel() approach for *discovering* new
        // AAs (it can't use this correlator since the AA is, by
        // definition, unknown at that point) and only switch already-
        // known connections over to the matched-filter path.
    }
}
*/
