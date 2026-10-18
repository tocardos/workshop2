//
// cfo_correction.cu
//
// Data-aided carrier frequency offset (CFO) estimation and correction
// for BLE GFSK bursts, triggered by a confirmed hit from
// ble_preamble_match() (matched_filter_correlator.cu). Operates on the
// complex baseband samples (chanbuf, cuFloatComplex) BEFORE demod()'s
// hard bit-slicing -- CFO correction is meaningless after that point,
// the phase information is already gone.
//
// Pipeline change:
//   filter<<<>>> / dft<<<>>>  ->  chanbuf (complex, per channel)
//        |
//        v
//   demod<<<>>>  ->  bits[]  (existing, uncorrected -- CFO-tolerant
//        |                     enough for ble_preamble_match() to find
//        v                     candidates via Hamming distance)
//   ble_preamble_match<<<>>>  ->  candidate index i
//        |
//        v  (NEW, only at confirmed candidates -- cheap, sparse)
//   estimate_cfo_burst<<<>>>   -> cfo_hz per candidate
//        |
//        v
//   derotate_and_redemod<<<>>> -> corrected bits[] over header+payload
//        |
//        v
//   detect_ble_packets<<<>>>  (existing, now fed cleaner bits)
//
// Method: average instantaneous frequency error over the known
// preamble+AA bits. For BLE GFSK (BT Core Vol 6 Part B, modulation
// index h=0.5, nominal peak deviation Fdev ~= 250 kHz for LE 1M), each
// transmitted bit b in {0,1} maps to a nominal frequency deviation
// +Fdev (b=1) or -Fdev (b=0) around the channel center. The measured
// instantaneous frequency at bit n is:
//
//     f_meas[n] = angle(x[n] * conj(x[n-1])) / (2*pi*Ts)
//
// which equals f_dev(b[n]) + f_cfo + noise. Since b[n] is known for
// preamble+AA, averaging (f_meas[n] - f_dev(b[n])) over those bits
// isolates f_cfo with the modulation term cancelled out.
//

#include <cstdint>
#include <cmath>
#include <cuda_runtime_api.h>
#include <cuComplex.h>

#ifndef BLE_FDEV_HZ
#define BLE_FDEV_HZ 250000.0f     // nominal LE 1M peak frequency deviation
#endif

#define TEMPLATE_LEN 40            // 8 preamble + 32 AA bits, must match
                                    // matched_filter_correlator.cu

// ---------------------------------------------------------------------
// estimate_cfo_burst
//
// One thread block per candidate burst (candidates are sparse -- this
// is NOT run over every sample, only at confirmed matched-filter hits,
// so launch with one block per entry in a compacted candidate list).
//
// samplebuf   : complex baseband for this channel (chanbuf slice),
//               indexed at raw sample resolution.
// cand_idx    : starting sample index of this candidate burst (start
//               of preamble), from ble_preamble_match()'s output.
// srate       : samples per bit.
// samp_rate_hz: this channel's sample rate (1e6 for 1 MHz bins).
// ref_bits    : TEMPLATE_LEN known bit values (0/1), same pattern used
//               to build the matched-filter reference -- pass the
//               unpacked uint8_t[TEMPLATE_LEN] array here (small, cheap
//               to keep both a packed and unpacked copy).
// out_cfo_hz  : one float per candidate, the estimated CFO in Hz.
//               Positive = signal is high of expected center, so
//               correction rotates by -cfo.
// ---------------------------------------------------------------------
__global__
void estimate_cfo_burst(const cuFloatComplex* __restrict__ samplebuf,
                         const size_t* __restrict__ cand_idx,
                         size_t srate,
                         float samp_rate_hz,
                         const uint8_t* __restrict__ ref_bits,
                         float* __restrict__ out_cfo_hz)
{
    // One block per candidate; use a small number of threads (e.g. 39,
    // one per bit transition) with a block-wide reduction. Simpler and
    // plenty fast given how sparse candidates are (this is not a
    // per-sample kernel).
    unsigned int cand = blockIdx.x;
    unsigned int tid = threadIdx.x;          // 0 .. TEMPLATE_LEN-2 (39 transitions)

    __shared__ float partial_sum[TEMPLATE_LEN];
    __shared__ int   partial_cnt[TEMPLATE_LEN];

    partial_sum[tid] = 0.0f;
    partial_cnt[tid] = 0;

    if (tid < TEMPLATE_LEN - 1) {
        size_t base = cand_idx[cand];
        size_t n0 = base + (size_t)tid * srate;
        size_t n1 = base + (size_t)(tid + 1) * srate;

        cuFloatComplex x0 = samplebuf[n0];
        cuFloatComplex x1 = samplebuf[n1];

        // Instantaneous phase change over one bit period.
        cuFloatComplex prod = cuCmulf(x1, cuConjf(x0));
        float phase = atan2f(cuCimagf(prod), cuCrealf(prod));   // radians

        float ts_bit = (float)srate / samp_rate_hz;             // seconds/bit
        float f_meas = phase / (2.0f * (float)M_PI * ts_bit);   // Hz

        // Expected deviation for the *transition into* bit (tid+1),
        // per known reference pattern -- this is the modulation term
        // we subtract out.
        float f_expected = (ref_bits[tid + 1] ? BLE_FDEV_HZ : -BLE_FDEV_HZ);

        partial_sum[tid] = f_meas - f_expected;
        partial_cnt[tid] = 1;
    }
    __syncthreads();

    // Simple block reduction (TEMPLATE_LEN-1 = 39 elements -- small,
    // no need for a fancy tree reduction).
    if (tid == 0) {
        float sum = 0.0f;
        int cnt = 0;
        for (int k = 0; k < TEMPLATE_LEN - 1; ++k) {
            sum += partial_sum[k];
            cnt += partial_cnt[k];
        }
        out_cfo_hz[cand] = (cnt > 0) ? (sum / cnt) : 0.0f;
    }
}

// ---------------------------------------------------------------------
// derotate_and_redemod
//
// Applies an NCO correction of -cfo_hz to the complex samples spanning
// the REST of the burst (from end of AA through end of max PDU length),
// then re-demodulates (same sign-of-cross-product rule as demod()) into
// a corrected bits[] region ready for detect_ble_packets().
//
// Only the header+payload region needs this -- preamble+AA were only
// ever used to estimate CFO, and detect_ble_packets() re-reads them
// from the original bits[] for the AA correlation check, which is fine
// since that used the already-CFO-tolerant matched filter to get here.
//
// One thread per output sample, same launch shape as demod().
// ---------------------------------------------------------------------
__global__
void derotate_and_redemod(const cuFloatComplex* __restrict__ samplebuf,
                           uint8_t* __restrict__ binbuf,
                           size_t cand_start,     // start of preamble for this burst
                           size_t region_start,   // first sample to correct (e.g. end of AA)
                           size_t region_len,      // how many samples to correct
                           float cfo_hz,
                           float samp_rate_hz)
{
    unsigned int j = (blockIdx.x * blockDim.x) + threadIdx.x;   // 0..region_len-1
    if (j >= region_len) return;

    size_t n = region_start + j;                 // absolute sample index
    size_t n_rel = n - cand_start;                // samples since burst start, for NCO phase

    float theta = -2.0f * (float)M_PI * cfo_hz * ((float)n_rel / samp_rate_hz);
    cuFloatComplex rot = make_cuFloatComplex(cosf(theta), sinf(theta));

    cuFloatComplex x_corrected = cuCmulf(samplebuf[n], rot);

    if (j == 0) {
        // Need one sample of history for the phase-difference demod;
        // correct the previous sample too (n-1) for a clean first bit.
        size_t n_prev = n - 1;
        size_t n_prev_rel = n_prev - cand_start;
        float theta_prev = -2.0f * (float)M_PI * cfo_hz * ((float)n_prev_rel / samp_rate_hz);
        cuFloatComplex rot_prev = make_cuFloatComplex(cosf(theta_prev), sinf(theta_prev));
        cuFloatComplex x_prev_corrected = cuCmulf(samplebuf[n_prev], rot_prev);

        float phasediff_sign = cuCimagf(x_corrected) * cuCrealf(x_prev_corrected)
                              - cuCrealf(x_corrected) * cuCimagf(x_prev_corrected);
        binbuf[n] = (phasediff_sign > 0.0f) ? 0x1 : 0x0;
        return;
    }

    // Standard case: previous sample also needs correction to be
    // consistent -- recompute it here rather than relying on a
    // neighboring thread having written it (avoids a race/ordering
    // dependency across threads).
    size_t n_prev = n - 1;
    size_t n_prev_rel = n_prev - cand_start;
    float theta_prev = -2.0f * (float)M_PI * cfo_hz * ((float)n_prev_rel / samp_rate_hz);
    cuFloatComplex rot_prev = make_cuFloatComplex(cosf(theta_prev), sinf(theta_prev));
    cuFloatComplex x_prev_corrected = cuCmulf(samplebuf[n_prev], rot_prev);

    float phasediff_sign = cuCimagf(x_corrected) * cuCrealf(x_prev_corrected)
                          - cuCrealf(x_corrected) * cuCimagf(x_prev_corrected);
    binbuf[n] = (phasediff_sign > 0.0f) ? 0x1 : 0x0;
}

// ---------------------------------------------------------------------
// Host-side integration sketch
// ---------------------------------------------------------------------
#ifdef TOTO
void process_candidates(cuFloatComplex* d_chanbuf, uint8_t* d_binbuf,
                         size_t* d_candidate_indices, size_t num_candidates,
                         size_t srate, float samp_rate_hz,
                         uint8_t* d_ref_bits_unpacked)
{
    if (num_candidates == 0) return;

    float* d_cfo_hz;
    cudaMalloc(&d_cfo_hz, num_candidates * sizeof(float));

    // One block per candidate, TEMPLATE_LEN threads (only 39 active).
    estimate_cfo_burst<<<num_candidates, TEMPLATE_LEN>>>(
        d_chanbuf, d_candidate_indices, srate, samp_rate_hz,
        d_ref_bits_unpacked, d_cfo_hz);

    // Sanity-clamp CFO estimates before using them -- BLE LO tolerance
    // is generally within +/-150-250 kHz; anything wildly outside that
    // (e.g. from a false-positive matched-filter hit that slipped
    // through) likely means this candidate should be dropped rather
    // than "corrected" with a nonsense rotation. Do this clamp/reject
    // on the host after copying d_cfo_hz back, or fold it into
    // derotate_and_redemod as an early-return guard.

    // Region to correct: from end of AA to a fixed max-PDU-length
    // horizon (260 bytes payload + header + CRC, per bleprocessor's
    // own MAX_NUM_CONN/pdu sizing) -- same header_size/pdu[260]
    // budget already used in detect_ble_packets().
    const size_t aa_end_offset = TEMPLATE_LEN * srate;
    const size_t max_region_len = (2 + 260 + 3) * 8 * srate;  // header+pdu+crc, bits->samples

    for (size_t c = 0; c < num_candidates; ++c) {
        size_t region_start = /* candidate_indices[c] */ 0 + aa_end_offset;  // fill in per-candidate
        size_t nthreads = 256;
        size_t nblocks = (max_region_len + nthreads - 1) / nthreads;

        derotate_and_redemod<<<nblocks, nthreads>>>(
            d_chanbuf, d_binbuf,
            0 /* candidate_indices[c] */, region_start, max_region_len,
            0.0f /* d_cfo_hz[c], after host-side clamp check */,
            samp_rate_hz);
    }

    cudaFree(d_cfo_hz);

    // detect_ble_packets<<<>>>() now runs as before, reading the
    // corrected bits in binbuf for header/payload while still reading
    // the original (uncorrected but already-validated-by-correlator)
    // preamble+AA region for its own AA check.
}
#endif
