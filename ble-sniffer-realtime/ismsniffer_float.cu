//
// Copyright 2020 Marco Cominelli
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//

#include <iostream>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>
#include <csignal>
#include <complex>
#include <cmath>
#include <cstring>
#include <algorithm>
#include <unordered_map>

#include <cuda.h>
#include <cuda_runtime_api.h>

#include <boost/format.hpp>
#include <boost/program_options.hpp>
#include <boost/thread.hpp>

#include <uhd/device.hpp>
#include <uhd/exception.hpp>
#include <uhd/utils/safe_main.hpp>
#include <uhd/utils/thread.hpp>

#include "usrpcluster_float.hpp"
#include "doublebuffer.hpp"
#include "bleprocessor_float.h"
#include "pcapsaver.h"

//#include <thread>
#include <atomic>
#include <queue>
#include <mutex>
#include <condition_variable>
// for profiling
#include <chrono>
#include <zmq.h>
#include <assert.h>
// combination of samp_rate and num_rep to avoid overflows,
// needs to be adapated based on GPU
// next settings are for GTX 1070


// for 40MHz num_rep at 5000 provides no overflow
//#define SAMP_RATE 40e6
#if (SAMP_RATE==40000000UL)
 static const size_t num_rep = 5000;
 #elif (SAMP_RATE==320000000UL)
static const size_t num_rep = 4000; // working fine with 16MHz
#endif


//static const size_t num_rep = SAMP_RATE/8e3;

// used for threading packet processing
struct PacketWork {
    uint8_t* bits;
    size_t num_samps_rx;
    uint8_t* rssi;          // per-sample RSSI codes, same layout as bits
};
std::queue<PacketWork> work_queue;
std::mutex work_mutex;
std::condition_variable work_cv;
std::atomic<bool> worker_running{true};
//profiling code
// Add global counter
std::atomic<size_t> g_overflow_count(0);
std::atomic<size_t> g_success_count(0);
// Timing statistics
double total_h2d_time = 0, total_kernel_time = 0;
double total_d2h_time = 0, total_packet_time = 0;
size_t timing_samples = 0;
// NEW: Variance tracking
double min_total_time = 1e9;
double max_total_time = 0;
const int HISTORY_SIZE = 1000;
double time_history[HISTORY_SIZE];
int history_idx = 0;
static const double timeout = 3.0;

// Global ZMQ context and publisher socket
void *zmq_context;
//extern void *zmq_publisher;
void *zmq_publisher;
//typedef std::complex<double> iqsamp_t;
typedef std::complex<float> iqsamp_t;

namespace po = boost::program_options; 

// RSSI estimate, implemented in bleprocessor_float.cu (move these to the header if you prefer)
uint8_t* get_rssi_devbuf();
float rssi_code_to_db(uint8_t code);          // NAN when no measurement
double g_rssi_offset_db = 0.0;                // --rssi-offset: added to the dBFS value

static inline float rssi_at(const uint8_t* rssi, size_t i)
{
    return rssi_code_to_db(rssi[i]) + (float)g_rssi_offset_db;   // NAN stays NAN
}


volatile bool stopsig = false;
void sigint_handler(int) {stopsig = true;}

void init_zmq_publisher() {
    zmq_context = zmq_ctx_new();
    zmq_publisher = zmq_socket(zmq_context, ZMQ_PUB);
    int rc = zmq_bind(zmq_publisher, "tcp://*:5556");
    assert(rc == 0);
}

// ===========================================================================
// JSON publisher for ble_aggregator.py
//
// Every decoded packet goes through send_ble_packet(), which classifies it and
// publishes ONE JSON string per ZMQ message (no trailing NUL), using the event
// names ble_aggregator.py understands:
//
//   adv          ADV_IND / ADV_DIRECT_IND / ADV_NONCONN_IND / ADV_SCAN_IND
//   scan_req     SCAN_REQ
//   scan_rsp     SCAN_RSP
//   connect_req  CONNECT_IND heard on an advertising channel (a NEW connection)
//   conn_data    heartbeat (<= 1/s per connection) while data-channel traffic is
//                seen for an access address.  Also how a connection that was
//                ALREADY RUNNING when the sniffer started is announced: it is
//                only known by its access address (no init/adv address).
//   conn_end     LL_TERMINATE_IND seen, or no traffic for the link timeout
//
// Not available in this decode path (so not sent): RSSI.  If you can compute
// one from the IQ data, pass it as rssi_dbm and it is added to the message.
// Called only from the packet worker thread -> the tracking tables need no lock.
// ===========================================================================
static const uint32_t BLE_ADV_AA            = 0x8E89BED6;
static const bool     PUBLISH_BAD_CRC       = false; // aggregator drops crc_ok=false anyway
static const int      NEW_AA_MIN_HITS       = 2;     // hits needed before a "from start" AA is announced
static const double   NEW_AA_WINDOW_SEC     = 10.0;  //   ... within this window (filters noise)
static const double   CONN_HEARTBEAT_SEC    = 1.0;
static const double   CONN_TIMEOUT_DEF_SEC  = 6.0;   // used when the supervision timeout is unknown
static const double   CONN_ENDED_HOLD_SEC   = 10.0;  // ignore an AA for this long after conn_end

// ---- tiny JSON writer ------------------------------------------------------
static std::string json_escape(const std::string &in)
{
    std::string out;
    out.reserve(in.size() + 2);
    for (unsigned char c : in) {
        if (c == '"' || c == '\\') { out += '\\'; out += (char)c; }
        else if (c < 0x20)         { char t[8]; snprintf(t, sizeof t, "\\u%04x", c); out += t; }
        else if (c >= 0x7f)        out += '?';   // keep the stream valid UTF-8
        else                       out += (char)c;
    }
    return out;
}

struct Json {
    std::string s{"{"};
    bool first = true;
    void key(const char *k) { if (!first) s += ','; first = false; s += '"'; s += k; s += "\":"; }
    Json &str(const char *k, const std::string &v) { key(k); s += '"'; s += json_escape(v); s += '"'; return *this; }
    Json &num(const char *k, long long v)          { key(k); s += std::to_string(v); return *this; }
    Json &flt(const char *k, double v, int prec)   { char t[48]; snprintf(t, sizeof t, "%.*f", prec, v); key(k); s += t; return *this; }
    Json &boolean(const char *k, bool v)           { key(k); s += v ? "true" : "false"; return *this; }
    Json &raw(const char *k, const std::string &v) { key(k); s += v; return *this; }
    std::string done() const { return s + "}"; }
};

static std::string hex_str(const uint8_t *p, size_t n)
{
    static const char *d = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; i++) { s += d[p[i] >> 4]; s += d[p[i] & 15]; }
    return s;
}

// BLE addresses are on air LSB first; print them MSB first, aa:bb:cc:dd:ee:ff
static std::string addr_str(const uint8_t *a)
{
    char t[20];
    snprintf(t, sizeof t, "%02x:%02x:%02x:%02x:%02x:%02x", a[5], a[4], a[3], a[2], a[1], a[0]);
    return t;
}

static std::string aa_str(uint32_t aa)
{
    char t[16];
    snprintf(t, sizeof t, "0x%08x", aa);
    return t;
}

static double steady_sec()
{
    using namespace std::chrono;
    return duration<double>(steady_clock::now().time_since_epoch()).count();
}

static double epoch_sec()
{
    using namespace std::chrono;
    return duration<double>(system_clock::now().time_since_epoch()).count();
}

static void publish_json(const std::string &msg)
{
    int rc = zmq_send(zmq_publisher, msg.data(), msg.size(), 0);
    // Don't assert hard - a missed packet is better than a crash
    if (rc < 0)
        std::cerr << "[zmq] send error: " << zmq_strerror(errno) << std::endl;
}

// CRC24 trailer (3 bytes after the PDU), same bit order as register_new_packets()
static uint32_t crc_from_trailer(const uint8_t *pdu, size_t pdu_size)
{
    uint32_t crc = 0;
    int shift = 23;
    for (int byte = 0; byte < 3; ++byte)
        for (int b = 0x80; b; b >>= 1) {
            if (pdu[pdu_size + byte] & b) crc |= 0x1u << shift;
            shift--;
        }
    return crc;
}

// ---- advertising-channel PDUs -----------------------------------------------
struct AdInfo {
    std::string name;
    bool have_name = false, name_complete = false;
    bool have_tx_power = false; int tx_power = 0;
    std::string manufacturer;               // hex: company ID (2 bytes, on-air order) + payload
    std::string service_data;               // hex of the first Service Data AD value
    std::vector<std::string> uuids;
};

static void parse_ad(const uint8_t *ad, size_t len, AdInfo &o)
{
    size_t i = 0;
    while (i + 1 < len) {
        size_t l = ad[i];
        if (l == 0 || i + 1 + l > len) break;       // padding / truncated structure
        uint8_t type = ad[i + 1];
        const uint8_t *v = ad + i + 2;
        size_t vl = l - 1;
        switch (type) {
        case 0x08: case 0x09:                       // shortened / complete local name
            if (type == 0x09 || !o.name_complete) {
                o.name.assign((const char *)v, vl);
                o.have_name = true;
                o.name_complete = (type == 0x09);
            }
            break;
        case 0x0A:
            if (vl >= 1) { o.have_tx_power = true; o.tx_power = (int8_t)v[0]; }
            break;
        case 0xFF:
            if (o.manufacturer.empty()) o.manufacturer = hex_str(v, vl);
            break;
        case 0x16:                                  // service data, 16-bit UUID
        case 0x20:                                  // service data, 32-bit UUID
        case 0x21:                                  // service data, 128-bit UUID
            if (o.service_data.empty()) o.service_data = hex_str(v, vl);
            break;
        case 0x02: case 0x03:                       // 16-bit service UUIDs
            for (size_t k = 0; k + 2 <= vl; k += 2) {
                char t[8]; snprintf(t, sizeof t, "%02x%02x", v[k + 1], v[k]); o.uuids.push_back(t);
            }
            break;
        case 0x04: case 0x05:                       // 32-bit service UUIDs
            for (size_t k = 0; k + 4 <= vl; k += 4) {
                char t[12]; snprintf(t, sizeof t, "%02x%02x%02x%02x", v[k + 3], v[k + 2], v[k + 1], v[k]);
                o.uuids.push_back(t);
            }
            break;
        case 0x06: case 0x07:                       // 128-bit service UUIDs
            for (size_t k = 0; k + 16 <= vl; k += 16) {
                char t[40];
                snprintf(t, sizeof t, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                         v[k+15], v[k+14], v[k+13], v[k+12], v[k+11], v[k+10], v[k+9], v[k+8],
                         v[k+7],  v[k+6],  v[k+5],  v[k+4],  v[k+3],  v[k+2],  v[k+1], v[k]);
                o.uuids.push_back(t);
            }
            break;
        }
        i += 1 + l;
    }
}

static void add_ad_fields(Json &j, const AdInfo &ad)
{
    if (ad.have_name)           j.str("name", ad.name);
    if (ad.have_tx_power)       j.num("tx_power", ad.tx_power);
    if (!ad.manufacturer.empty()) j.str("manufacturer", ad.manufacturer);
    if (!ad.service_data.empty()) j.str("service_data", ad.service_data);
    if (!ad.uuids.empty()) {
        std::string arr = "[";
        for (size_t k = 0; k < ad.uuids.size(); k++) {
            if (k) arr += ',';
            arr += '"' + ad.uuids[k] + '"';
        }
        j.raw("service_uuids", arr + "]");
    }
}

// ---- connection tracking ------------------------------------------------------
struct ConnTrack {
    uint32_t aa = 0;
    bool from_start = true;        // true: only seen on data channels (no CONNECT_IND heard)
    bool have_connect = false;     // CONNECT_IND parameters known
    std::string init_addr, adv_addr;
    bool init_random = false, adv_random = false, ch_sel2 = false;
    uint32_t crc_init = 0;
    unsigned win_size = 0, win_offset = 0, interval = 0, latency = 0, timeout = 0;
    uint8_t chmap[5] = {0};
    unsigned hop = 0, sca = 0;
    double first_seen = 0, last_seen = 0, last_hb = 0;
    bool seen_data = false;
    uint64_t packets = 0, packets_hb = 0;
    int last_channel = -1;
    double rssi_acc = 0; int rssi_n = 0;   // dB values since the last heartbeat
};

struct AaCandidate { int hits; double first; };

static std::unordered_map<uint32_t, ConnTrack>   g_conns;
static std::unordered_map<uint32_t, AaCandidate> g_aa_candidates;
static std::unordered_map<uint32_t, double>      g_aa_ended;   // aa -> time of conn_end

static std::string connect_json(const ConnTrack &c)
{
    Json j;
    j.str("access_address", aa_str(c.aa));
    j.boolean("from_start", c.from_start);
    if (c.have_connect) {
        j.str("init_addr", c.init_addr).str("adv_addr", c.adv_addr);
        j.boolean("init_addr_random", c.init_random).boolean("adv_addr_random", c.adv_random);
        char crc[12]; snprintf(crc, sizeof crc, "0x%06x", c.crc_init);
        j.str("crc_init", crc);
        j.num("win_size", c.win_size).num("win_offset", c.win_offset);
        j.num("interval", c.interval).flt("interval_ms", c.interval * 1.25, 2);
        j.num("latency", c.latency).num("timeout", c.timeout);   // interval: 1.25 ms units, timeout: 10 ms units
        j.str("channel_map", hex_str(c.chmap, 5));
        j.num("hop", c.hop).num("sca", c.sca).boolean("chsel2", c.ch_sel2);
    }
    return j.done();
}

static std::string stats_json(const ConnTrack &c)
{
    Json j;
    j.num("packets", (long long)c.packets);
    j.num("packets_since_last", (long long)c.packets_hb);
    j.num("last_channel", c.last_channel);
    if (c.rssi_n > 0) j.flt("rssi_avg", c.rssi_acc / c.rssi_n, 1);
    return j.done();
}

static void publish_conn_data(ConnTrack &c, double now)
{
    Json j;
    j.str("event", "conn_data").flt("ts", epoch_sec(), 6).boolean("crc_ok", true);
    j.str("access_address", aa_str(c.aa));
    j.raw("connect", connect_json(c));
    j.raw("stats", stats_json(c));
    publish_json(j.done());
    c.last_hb = now;
    c.packets_hb = 0;
    c.rssi_acc = 0; c.rssi_n = 0;
}

static void publish_conn_end(ConnTrack &c, const std::string &reason, double now)
{
    Json j;
    j.str("event", "conn_end").flt("ts", epoch_sec(), 6).boolean("crc_ok", true);
    j.str("access_address", aa_str(c.aa));
    j.str("reason", reason);
    j.raw("stats", stats_json(c));
    publish_json(j.done());
    std::cout << boost::format("CONN_END: AA:%08X reason:%s") % c.aa % reason << std::endl;
    g_aa_ended[c.aa] = now;
}

static double conn_timeout_sec(const ConnTrack &c)
{
    if (c.have_connect && c.timeout > 0)
        return std::max(2.0, c.timeout * 0.010);     // supervision timeout
    return CONN_TIMEOUT_DEF_SEC;
}

// Call once per processed buffer: ends silent connections, expires bookkeeping.
static void ble_publish_tick()
{
    const double now = steady_sec();
    for (auto it = g_conns.begin(); it != g_conns.end(); ) {
        ConnTrack &c = it->second;
        if (c.seen_data && now - c.last_seen > conn_timeout_sec(c)) {
            publish_conn_end(c, "timeout", now);
            it = g_conns.erase(it);
        } else if (!c.seen_data && now - c.last_seen > 120.0) {
            it = g_conns.erase(it);                  // CONNECT_IND never followed by data
        } else {
            ++it;
        }
    }
    for (auto it = g_aa_candidates.begin(); it != g_aa_candidates.end(); )
        it = (now - it->second.first > NEW_AA_WINDOW_SEC) ? g_aa_candidates.erase(it) : std::next(it);
    for (auto it = g_aa_ended.begin(); it != g_aa_ended.end(); )
        it = (now - it->second > CONN_ENDED_HOLD_SEC) ? g_aa_ended.erase(it) : std::next(it);
}

static void handle_connect_ind(uint8_t *pdu, size_t pdu_size, uint8_t channel, bool crc_ok, float rssi)
{
    const uint8_t *p = pdu + 2;                      // payload: InitA(6) AdvA(6) AA(4) CRCInit(3) WinSize(1)
    if (pdu[1] < 34) return;                         //   WinOffset(2) Interval(2) Latency(2) Timeout(2) ChM(5) Hop/SCA(1)
    const double now = steady_sec();

    ConnTrack c;
    c.have_connect = true;
    c.from_start = false;
    c.init_addr = addr_str(p);
    c.adv_addr  = addr_str(p + 6);
    c.init_random = (pdu[0] >> 6) & 1;               // TxAdd
    c.adv_random  = (pdu[0] >> 7) & 1;               // RxAdd
    c.ch_sel2 = (pdu[0] >> 5) & 1;
    for (int k = 0; k < 4; k++) c.aa       |= (uint32_t)p[12 + k] << (8 * k);
    for (int k = 0; k < 3; k++) c.crc_init |= (uint32_t)p[16 + k] << (8 * k);
    c.win_size   = p[19];
    c.win_offset = p[20] | (p[21] << 8);
    c.interval   = p[22] | (p[23] << 8);
    c.latency    = p[24] | (p[25] << 8);
    c.timeout    = p[26] | (p[27] << 8);
    std::memcpy(c.chmap, p + 28, 5);
    c.hop = p[33] & 0x1F;
    c.sca = p[33] >> 5;
    c.first_seen = c.last_seen = now;

    Json j;
    j.str("event", "connect_req").flt("ts", epoch_sec(), 6).num("channel", channel);
    j.str("pdu_type", "CONNECT_IND").boolean("crc_ok", crc_ok);
    j.str("access_address", aa_str(c.aa));
    j.boolean("tx_addr_random", c.init_random);
    if (std::isfinite(rssi)) j.flt("rssi", rssi, 1);
    j.raw("connect", connect_json(c));
    publish_json(j.done());

    if (crc_ok) {
        g_aa_ended.erase(c.aa);
        g_aa_candidates.erase(c.aa);
        g_conns[c.aa] = c;                           // a reused AA starts a fresh connection
    }
}

static void publish_adv_channel_packet(uint8_t *pdu, size_t pdu_len, uint8_t channel, float rssi)
{
    if (pdu_len < 5) return;
    const uint8_t type  = pdu[0] & 0x0F;
    const bool    txadd = (pdu[0] >> 6) & 1;
    const size_t  plen  = pdu[1];
    if (2 + plen + 3 > pdu_len) return;              // truncated
    const size_t pdu_size = 2 + plen;

    const bool crc_ok = (crc_from_trailer(pdu, pdu_size) == compute_crc(pdu, pdu_size, 0x555555));
    if (!crc_ok && !PUBLISH_BAD_CRC) return;

    const uint8_t *p = pdu + 2;
    const char *tname = nullptr;
    switch (type) {
    case 0: tname = "ADV_IND";          break;
    case 1: tname = "ADV_DIRECT_IND";   break;
    case 2: tname = "ADV_NONCONN_IND";  break;
    case 3: tname = "SCAN_REQ";         break;
    case 4: tname = "SCAN_RSP";         break;
    case 5: handle_connect_ind(pdu, pdu_size, channel, crc_ok, rssi); return;
    case 6: tname = "ADV_SCAN_IND";     break;
    default: return;                                 // extended advertising etc: not handled
    }

    Json j;
    if (type == 3) {                                 // SCAN_REQ: ScanA(6) AdvA(6)
        if (plen < 12) return;
        j.str("event", "scan_req").flt("ts", epoch_sec(), 6).num("channel", channel);
        j.str("pdu_type", tname).boolean("crc_ok", crc_ok);
        j.str("scanner_addr", addr_str(p)).str("adv_addr", addr_str(p + 6));
        j.boolean("tx_addr_random", txadd);
    } else {                                         // everything else starts with AdvA(6)
        if (plen < 6) return;
        j.str("event", type == 4 ? "scan_rsp" : "adv").flt("ts", epoch_sec(), 6).num("channel", channel);
        j.str("pdu_type", tname).boolean("crc_ok", crc_ok);
        j.str("adv_addr", addr_str(p)).boolean("tx_addr_random", txadd);
        if (type == 1) {
            if (plen >= 12) j.str("target_addr", addr_str(p + 6));
        } else {
            AdInfo ad;
            parse_ad(p + 6, plen - 6, ad);
            add_ad_fields(j, ad);
        }
    }
    if (std::isfinite(rssi)) j.flt("rssi", rssi, 1);
    publish_json(j.done());
}

// ---- data-channel PDUs ------------------------------------------------------
static void track_data_channel_packet(const uint8_t *pdu, size_t pdu_len, uint8_t channel, uint32_t aa, float rssi)
{
    const double now = steady_sec();
    auto it = g_conns.find(aa);

    if (it == g_conns.end()) {
        // Unknown AA: either a connection that was already running when the
        // sniffer started, or noise.  Announce it only after a few hits.
        auto e = g_aa_ended.find(aa);
        if (e != g_aa_ended.end() && now - e->second < CONN_ENDED_HOLD_SEC) return;
        AaCandidate &cand = g_aa_candidates[aa];
        if (cand.hits == 0) cand.first = now;
        if (now - cand.first > NEW_AA_WINDOW_SEC) { cand.hits = 0; cand.first = now; }
        if (++cand.hits < NEW_AA_MIN_HITS) return;
        g_aa_candidates.erase(aa);

        ConnTrack c;
        c.aa = aa;
        c.from_start = true;
        c.first_seen = now;
        it = g_conns.emplace(aa, c).first;
        std::cout << boost::format("CONN (already running): AA:%08X Ch:%02d") % aa % (int)channel << std::endl;
    }

    ConnTrack &c = it->second;
    c.last_seen = now;
    c.seen_data = true;
    c.packets++;
    c.packets_hb++;
    c.last_channel = channel;
    if (std::isfinite(rssi)) { c.rssi_acc += rssi; c.rssi_n++; }

    // LL_TERMINATE_IND: LLID=3 (control), length 2, opcode 0x02, error code
    if (pdu_len >= 5 && (pdu[0] & 0x03) == 0x03 && pdu[1] == 2 && pdu[2] == 0x02) {
        char r[40]; snprintf(r, sizeof r, "terminate_ind(0x%02x)", pdu[3]);
        publish_conn_data(c, now);                   // flush the last counters first
        publish_conn_end(c, r, now);
        g_conns.erase(it);
        return;
    }
    if (now - c.last_hb >= CONN_HEARTBEAT_SEC)
        publish_conn_data(c, now);
}

void send_ble_packet(uint8_t *pdu, size_t pdu_len, uint8_t channel, uint32_t aa = 0,
                     float rssi_dbm = NAN)
{
    if (pdu == nullptr || pdu_len < 2) return;
    if (aa == 0 && channel >= 37) aa = BLE_ADV_AA;   // default arg: assume advertising

    if (aa == BLE_ADV_AA) {
        if (channel >= 37) publish_adv_channel_packet(pdu, pdu_len, channel, rssi_dbm);
        // BLE_ADV_AA on a data channel = noise, ignore
    } else if (channel < 37) {
        track_data_channel_packet(pdu, pdu_len, channel, aa, rssi_dbm);
    }
    // else: non-advertising AA on an advertising channel = noise, ignore
}

void cleanup_zmq() {
    zmq_close(zmq_publisher);
    zmq_ctx_destroy(zmq_context);
}



void streaming(uhd::rx_streamer::sptr rxstream,
               DoubleBuffer<iqsamp_t*> *const buf_ctrl,
               const size_t samps_per_buf)
{
    uhd::set_thread_priority_safe(1);

    iqsamp_t* buf_ptr;
    iqsamp_t* old_buf_ptr=nullptr;

    uhd::rx_metadata_t md;
    size_t num_rx_samps = 0;

    while (stopsig == false) {
        // Select buffer(s) to write.
        buf_ptr = *(buf_ctrl->start_writing());

        // Receive samples
        num_rx_samps = rxstream->recv(buf_ptr, samps_per_buf, md, timeout);

        // Release buffer and check for overflows
        buf_ctrl->end_writing();
        
        if (buf_ptr == old_buf_ptr){
             g_overflow_count++;
            std::cerr << "An overflow has occurred" << std::endl;
        }else {
            g_success_count++;
            //for debug purposes
            //std::cout << "Received " << num_rx_samps << " samples" << std::endl;
        }
        
        old_buf_ptr = buf_ptr;
        
        // Throw exception if errors occur
        if (md.error_code == uhd::rx_metadata_t::ERROR_CODE_OVERFLOW)
            std::cerr << std::endl << "OVERFLOW DETECTED" << std::endl;
        else if (md.error_code != uhd::rx_metadata_t::ERROR_CODE_NONE)
            throw std::runtime_error(md.strerror());
        // Every 1000 buffers, report stats
        if ((g_overflow_count + g_success_count) % 1000 == 0) {
            std::cout << boost::format("STAT : Received %d samples") % num_rx_samps << std::endl;
        }
    }
}


void register_new_packets(uint8_t* bits,
                          const uint8_t* rssi,
                          pcapmerger& pc,
                          size_t nsamps_per_mboard,
                          size_t samps_per_chan,
                          size_t num_mboards,
                          size_t num_samps_rx,
                          size_t* pktcount)
{
    const size_t header_size = 2;
    const size_t aa_length = 32;

    // Iterate over BLE channels looking for packets.
    for (size_t n = 0; n < num_mboards; n++) {
        for (size_t ch = 0; ch < DECFACTOR; ch++) {
            size_t base_idx = n*nsamps_per_mboard + ch*samps_per_chan;
            for (size_t j = 0; j < samps_per_chan; j++) {
                size_t i = base_idx + j;

                //size_t i = n*nsamps_per_mboard + ch*samps_per_chan + j;
                uint8_t flag = bits[i];
                // Quick rejection - check if any flags are set
                if ((flag & 0xF0) == 0) continue;
                if (bits[i] & 0xc0) {
                    // Found a new packet, check LE PHY.
                    size_t srate = (bits[i] & 0x80) ? LE1M_SRATE : LE2M_SRATE;
                    pktcount[n * DECFACTOR + ch]++;
                    
                    uint32_t blefreq = 0, blechan = 0;

                    int central_freq_int = (int) (usrp_tune_freqs[n]/1e6);
                    int freqidx = (i%nsamps_per_mboard)/samps_per_chan;
                    if (freqidx <= DECFACTOR/2)
                        blefreq = central_freq_int + freqidx*2;
                    else
                        blefreq = central_freq_int + (-DECFACTOR + freqidx)*2;
                    blechan = freq2chan(blefreq);

                    // Extract access address
                    size_t offset = i + 8*srate;
                    uint32_t aa = 0x00;
                    for (size_t c = 0; c < aa_length; ++c)
                        aa |= (bits[offset+c*srate] & 0x1) << c;

                    offset += aa_length*srate;
                    size_t payload_size = 0;
                    uint8_t header[header_size] = {0};
                    uint8_t pdu[260] = {0};
    
                    // Extract header and read payload length.
                    for (int byte = 0; byte < header_size; ++byte)
                        for (int b = 0; b < 8; ++b)
                            header[byte] |=
                                (bits[offset+(byte*8+b)*srate] & 0x1) << (7-b);
                    ble_dewhiten(header, blechan, header_size);
                    swap_nbytes(header, header_size);
                    // mod to avoid overflow add & 0x3F     
                    payload_size = header[1] & 0x3F; // from AI check

                    // Extract BLE frame without checking CRC validity again.
                    size_t pdu_size = header_size + payload_size;
                    for (int byte = 0; byte < pdu_size+3; ++byte)
                        for (int b = 0; b < 8; ++b)
                            pdu[byte] |=
                                (bits[offset + (byte*8+b)*srate] & 0x1) << (7-b);
                    ble_dewhiten(pdu, blechan, pdu_size+3);
                    swap_nbytes(pdu, pdu_size);
                    // vde test to keep crc_init upon CONNECT_IND (0x05)
                    if ((header[0] & 0x0F) == 0x05 && is_adv_chan(blechan)) {
                        // Recompute CRC over the payload and compare with the trailer
                        uint32_t crc_packet = 0;
                        int shift = 23;
                        for (int byte = 0; byte < 3; ++byte) {
                            for (int b = 0x80; b; b >>= 1) {
                                if (pdu[pdu_size + byte] & b) crc_packet |= 0x1 << shift;
                                shift--;
                            }
                        }
                        uint32_t crc_computed = compute_crc(pdu, pdu_size, 0x555555); // fixed adv-channel init
                        if (crc_computed == crc_packet) {
                            
                        
                            uint32_t new_aa  = 0, new_crc = 0;
                            // InitA=6, AdvA=6, then AA at offset 12
                            // should it be 14 and 18 ? instead of 12 and 16?
                            for (int c = 0; c < 4; c++) new_aa  |= pdu[14 + c] << (c * 8);
                                for (int c = 0; c < 3; c++) new_crc |= pdu[18 + c] << (c * 8);
    
                                // Push to GPU conn_list 
                                add_new_conn(new_aa, new_crc);
                                std::cout << boost::format("CONNECT_IND: Ch:%02d AA:%08X crc_init:%06X")  
							    %  blechan % new_aa % new_crc << std::endl;
                        }
                    }

                    uint32_t timenow_us = (num_samps_rx + j) / srate;
                    uint32_t timeusec = ((uint32_t) timenow_us) % 1000000;
                    uint32_t timesec = ((uint32_t) timenow_us - timeusec) / 1000000;
                    struct timeval ts = {timesec, timeusec};
                    //std::cout << boost::format("%u.%06u broadcast: Ch:%02d AA:%08X Payload:%d bytes") 
					//		% timesec % timeusec % blechan % aa % payload_size << std::endl;
                    pc.addpacket(&ts, blechan, aa, pdu_size+3, pdu, 0);
                    send_ble_packet(pdu, pdu_size+3, (uint8_t)blechan, aa, rssi_at(rssi, i));
                    // Ensure duplicate packets are discarded
                    //for (int kk = 0; kk < srate; kk++) bits[i+1] &= 0x1;
                    //for (int kk = 0; kk < srate; kk++) bits[kk+i] &= 0x1;
                    // Clear enough bit-periods to cover the preamble (8 bits)
                    // so the detector can't re-fire on the same preamble
                    for (int kk = 1; kk < 10; kk++) {
                        if (i + kk * srate < nsamps_per_mboard)   // bounds guard
                            bits[i + kk * srate] &= ~0xF0;        // clear flag bits only
                    }
                }
                else if (bits[i] & 0x10) {
                    size_t srate = LE1M_SRATE;
                    pktcount[n * DECFACTOR + ch]++;
                    
                    uint32_t blefreq = 0, blechan = 0;

                    int central_freq_int = (int) (usrp_tune_freqs[n]/1e6);
                    int freqidx = (i%nsamps_per_mboard)/samps_per_chan;
                    if (freqidx <= DECFACTOR/2)
                        blefreq = central_freq_int + freqidx*2;
                    else
                        blefreq = central_freq_int + (-DECFACTOR + freqidx)*2;
                    blechan = freq2chan(blefreq);

                    // Extract access address
                    size_t offset = i + 8*srate;
                    uint32_t aa = 0x00;
                    for (size_t c = 0; c < aa_length; ++c)
                        aa |= (bits[offset+c*srate] & 0x1) << c;

                    offset += aa_length*srate;
                    size_t payload_size = 0;
                    uint8_t header[header_size] = {0};
                    uint8_t pdu[260] = {0};
    
                    // Extract header and read payload length.
                    for (int byte = 0; byte < header_size; ++byte)
                        for (int b = 0; b < 8; ++b)
                            header[byte] |=
                                (bits[offset+(byte*8+b)*srate] & 0x1) << (7-b);
                    ble_dewhiten(header, blechan, header_size);
                    swap_nbytes(header, header_size);
                    payload_size = header[1];

                    if (payload_size != 0) 
                    {
						//#if 0
						// added vde as test
						size_t pdu_size = header_size + payload_size;
						for (int byte = 0; byte < pdu_size+3; ++byte)
							for (int b = 0; b < 8; ++b)
								pdu[byte] |=(bits[offset + (byte*8+b)*srate] & 0x1) << (7-b);
						ble_dewhiten(pdu, blechan, pdu_size+3);
						swap_nbytes(pdu, pdu_size);
                        // vde compare crc to avoid wrong packets
                        uint32_t crc_packet = 0;
                        int shift = 23;
                        for (int byte = 0; byte < 3; ++byte) {
                            for (int b = 0x80; b; b >>= 1) {
                                if (pdu[pdu_size + byte] & b) crc_packet |= 0x1 << shift;
                                shift--;
                            }
                        }
                        uint32_t crc_computed = compute_crc(pdu, pdu_size, aa);
                        if (crc_computed != crc_packet) {
                            std::cout << boost::format("CRC MISMATCH: Ch:%02d AA:%08X Payload:%d bytes")
                                % blechan % aa % payload_size << std::endl;
                                //continue;
                        }
						uint32_t timenow_us = (num_samps_rx + j) / srate;
						uint32_t timeusec = ((uint32_t) timenow_us) % 1000000;
						uint32_t timesec = ((uint32_t) timenow_us - timeusec) / 1000000;
						struct timeval ts = {timesec, timeusec};
						pc.addpacket(&ts, blechan, aa, pdu_size+3, pdu, 0);
                        send_ble_packet(pdu, pdu_size+3, (uint8_t)blechan, aa, rssi_at(rssi, i));
						// DEBUG: Print packet info
                        /*
						std::cout << boost::format("%u.%06u payload not empty: Ch:%02d AA:%08X Payload:%d bytes") 
							% timesec % timeusec % blechan % aa % payload_size << std::endl;
						// end of vde mod
                        */
						//#endif

						continue;
					}

                    // Extract BLE frame without checking CRC validity again.
                    size_t pdu_size = header_size;
                    for (int byte = 0; byte < pdu_size+3; ++byte)
                        for (int b = 0; b < 8; ++b)
                            pdu[byte] |=
                                (bits[offset + (byte*8+b)*srate] & 0x1) << (7-b);
                    ble_dewhiten(pdu, blechan, pdu_size+3);
                    swap_nbytes(pdu, pdu_size);

                    uint32_t timenow_us = (num_samps_rx + j) / srate;
                    uint32_t timeusec = ((uint32_t) timenow_us) % 1000000;
                    uint32_t timesec = ((uint32_t) timenow_us - timeusec) / 1000000;
                    /*
                    std::cout << boost::format("%u%06u NewAA: %08X") % timesec % timeusec % aa;
                    std::cout << std::endl;
                    */
                    struct timeval ts = {timesec, timeusec};
                    pc.addpacket(&ts, blechan, aa, pdu_size+3, pdu, 0);
                    send_ble_packet(pdu, pdu_size+3, (uint8_t)blechan, aa, rssi_at(rssi, i));
                    // Ensure duplicate packets are discarded
                    //for (int kk = 0; kk < srate; kk++) bits[i+1] &= 0x1;
                    //for (int kk = 0; kk < srate; kk++) bits[kk+i] &= 0x1;
                    // Clear enough bit-periods to cover the preamble (8 bits)
                    // so the detector can't re-fire on the same preamble
                    for (int kk = 1; kk < 10; kk++) {
                        if (i + kk * srate < nsamps_per_mboard)   // bounds guard
                            bits[i + kk * srate] &= ~0xF0;        // clear flag bits only
                    }
                }
            }
        }
    }
    ble_publish_tick();   // end silent connections, expire bookkeeping
}

void packet_worker_thread(pcapmerger& pc,
                          size_t nsamps_per_mboard,
                          size_t samps_per_chan,
                          size_t num_mboards,
                          size_t* pktcount)
{
    
    while (worker_running) {
        PacketWork work;

        {
            std::unique_lock<std::mutex> lock(work_mutex);
            work_cv.wait(lock, [] {
                return !work_queue.empty() || !worker_running;
            });

            if (!worker_running) break;

            work = work_queue.front();
            work_queue.pop();
        }

        register_new_packets(
            work.bits,
            work.rssi,
            pc,
            nsamps_per_mboard,
            samps_per_chan,
            num_mboards,
            work.num_samps_rx,
            pktcount
        );
    }
}
int UHD_SAFE_MAIN(int argc, char *argv[])
{
    // Set thread priority and escape signal.
    uhd::set_thread_priority_safe(1);
    signal(SIGINT, &sigint_handler);

    // Variables to be set by command line options.
    std::string usrp_args, fname, subdev, channel_string, antenna;
    double gain;
    bool sync_request, debug;

    // Set up program options.
    po::options_description desc("Allowed options");
    desc.add_options()
        ("help", "Display this help message")
        ("usrp-args", po::value<std::string>(&usrp_args),
            "USRP device arguments in a comma-separated list")
        ("gain", po::value<double>(&gain)->default_value(40),
            "rx gain (in dB)")
        ("subdev", po::value<std::string>(&subdev)->default_value("A:A"),
            "USRP subdevice (eg. \"A:A\" or \"A:A A:B\")")
        ("chan", po::value<std::string>(&channel_string)->default_value("0"),
            "rx channels (eg. \"0\" or \"0,1\")")
        ("antenna", po::value<std::string>(&antenna)->default_value("TX/RX"),
            "rx antenna (eg. \"TX/RX\" or \"RX2\")")
        ("file", po::value<std::string>(&fname)->default_value("trace.pcap"),
            "name of output pcap file")
        ("sync", po::value<bool>(&sync_request)->default_value(false),
            "use common clock for synchronization")
        ("debug", po::value<bool>(&debug)->default_value(false),
            "print info on recvd pkts per channel")
        ("rssi-offset", po::value<double>(&g_rssi_offset_db)->default_value(0.0),
            "dB added to the RSSI estimate (dBFS at the USRP input) to move it towards dBm; "
            "the aggregator's calibration makes this optional");
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    // Display program info.
    std::cout << "Bluetooth Low Energy Wide-band sniffer\n" << std::endl;

    // Print the help message.
    if (vm.count("help")) {
        std::cout << desc << std::endl;
        return ~0;
    }
    //std::string enhanced_args = usrp_args + 
    //",recv_buff_size=10000000" +  // 100 MB buffer (was ~2-8 MB)
    //",num_recv_frames=512";
    // settings num_recv_frames to 512 gets rid of OVERFLOW from ettus b200 mini
    std::string enhanced_args = "num_recv_frames=512";
    UsrpCluster usrp(enhanced_args, subdev, sync_request);
    // Create a new USRP cluster
    //UsrpCluster usrp(usrp_args, subdev, sync_request);
    const size_t num_mboards = usrp.get_num_mboards();
    std::cout << boost::format("\nDetected %u mboards\n") % num_mboards
              << std::endl;

    const double sampling_rate =(double) SAMP_RATE;

    // SDR front-end configuration.
    usrp.set_chan(channel_string);
    usrp.set_freq(usrp_tune_freqs);
    usrp.set_rate(sampling_rate);
    usrp.set_gain(gain);
    usrp.set_ant(antenna);

    // Initialize receving streamer
    //const std::string cpu_fmt = "fc64"; // cpu: double
    const std::string cpu_fmt = "fc32"; // cpu: float (CHANGED from fc64)
    // compression over the wire reduces significantly the ble detection

    //const std::string otw_fmt = "sc8";   // Reduce over-the-wire to 8-bit
    const std::string otw_fmt = "sc16"; // otw: int16
    usrp.init_rx_streamer(cpu_fmt, otw_fmt);

    // Check if all USRPs are locked to the 10 MHz reference signal
    if (sync_request == false) {
        std::cerr
            << "[WARNING] Not using ref clock; timestamps will be misaligned."
            << std::endl;
    } else if (usrp.all_mboards_locked() == false) {
        // sync_request is true in this case
        std::cerr
            << "[ERROR] Some mboards are not locked to the ref clock!"
            << std::endl;
        return ~0;
    }
    
    // Allocate data buffers
    const size_t nsamps_per_mboard = num_rep * usrp.get_max_num_samps();
    const size_t nsamps_overall = nsamps_per_mboard * num_mboards;
    iqsamp_t* h_iqbuffer_a;
    iqsamp_t* h_iqbuffer_b;
    iqsamp_t* d_iqbuffer;
    uint8_t* h_binbuffer;
    uint8_t* d_binbuffer;

uint8_t* h_binbuffer_1[2];
uint8_t* h_rssibuffer_1[2];
size_t bin_buf_idx = 0;

    cudaMallocHost((void**)&h_iqbuffer_a, nsamps_overall * sizeof(iqsamp_t));
    cudaMallocHost((void**)&h_iqbuffer_b, nsamps_overall * sizeof(iqsamp_t));
    cudaMallocHost((void**)&h_binbuffer, nsamps_overall * sizeof(uint8_t));
    cudaMallocHost((void**)&h_binbuffer_1[0], nsamps_overall * sizeof(uint8_t));
    cudaMallocHost((void**)&h_binbuffer_1[1], nsamps_overall * sizeof(uint8_t));
    cudaMallocHost((void**)&h_rssibuffer_1[0], nsamps_overall * sizeof(uint8_t));
    cudaMallocHost((void**)&h_rssibuffer_1[1], nsamps_overall * sizeof(uint8_t));

    cudaMalloc((void**)&d_iqbuffer, nsamps_overall * sizeof(iqsamp_t));
    cudaMalloc((void**)&d_binbuffer, nsamps_overall * sizeof(uint8_t));

    // Access control for the double buffer
    std::vector<DoubleBuffer<iqsamp_t*>> buf_ctrl(num_mboards);
    for (size_t i = 0; i < num_mboards; ++i) {
        buf_ctrl[i].m_buf[0] = h_iqbuffer_a + i*nsamps_per_mboard;
        buf_ctrl[i].m_buf[1] = h_iqbuffer_b + i*nsamps_per_mboard;
    }

    // Initialize data structures on the GPU
    init_decoder(nsamps_overall);

    // Reset timer on all the boards
    usrp.set_time_next_pps(0.0);

    // Setup streaming parameters
    const double t_start = 2.0;
    uhd::stream_cmd_t stream_start(uhd::stream_cmd_t::STREAM_MODE_START_CONTINUOUS);
    stream_start.num_samps = 0;
    stream_start.stream_now = false;
    stream_start.time_spec = uhd::time_spec_t(t_start);

    // Start streaming
    std::vector<uhd::rx_streamer::sptr> rxstreamer = usrp.get_rx_streamer();
    boost::thread_group stream_group;
    for (size_t i = 0; i < num_mboards; ++i) {
        rxstreamer[i]->issue_stream_cmd(stream_start);
        // Producer threads
        stream_group.create_thread(boost::bind(&streaming,
            rxstreamer[i], &buf_ctrl[i], nsamps_per_mboard));
    }
    std::cout
        << boost::format("start streaming in %.1lf s") % t_start
        << std::endl;

    // CUDA Streams
    cudaStream_t stream_h2d, stream_d2h;
    cudaStreamCreate(&stream_h2d);
    cudaStreamCreate(&stream_d2h);

    // Consumer thread
    iqsamp_t** readbuf;

    const size_t samps_per_chan = nsamps_per_mboard / DECFACTOR;

    std::vector<size_t> pktcount(num_mboards * DECFACTOR, 0);

    pcapmerger pc;
    int err = pc.create(fname.c_str());
    if (err) {
        std::cerr << "Failed to create pcap saver" << std::endl;
        stopsig = true;
    }
    // allocate packet worker thread
    std::thread pkt_thread(
        packet_worker_thread,
        std::ref(pc),
        nsamps_per_mboard,
        samps_per_chan,
        num_mboards,
        pktcount.data()
    );
    size_t num_samps_rx = 0;
    init_zmq_publisher();

    while (stopsig == false) {
        // Profiling start
        auto loop_start = std::chrono::high_resolution_clock::now();
        
        // Claim buffer for reading (wait until ready).
        do readbuf = buf_ctrl[0].start_reading();
        while (readbuf == nullptr);

        auto t1 = std::chrono::high_resolution_clock::now();
        cudaMemcpyAsync(d_iqbuffer, *readbuf, nsamps_overall * sizeof(iqsamp_t),
                   cudaMemcpyHostToDevice, stream_h2d);
        //cudaMemcpyAsync(h_binbuffer, d_binbuffer, nsamps_overall * sizeof(uint8_t),
        //           cudaMemcpyDeviceToHost, stream_d2h);
        cudaMemcpyAsync((void**)h_binbuffer_1[bin_buf_idx], d_binbuffer, nsamps_overall * sizeof(uint8_t),
                cudaMemcpyDeviceToHost, stream_d2h);
        // RSSI codes travel with the bits: same stream, same double-buffer slot
        cudaMemcpyAsync(h_rssibuffer_1[bin_buf_idx], get_rssi_devbuf(), nsamps_overall * sizeof(uint8_t),
                cudaMemcpyDeviceToHost, stream_d2h);
        auto t2 = std::chrono::high_resolution_clock::now();
        cudaStreamSynchronize(stream_h2d); // wait until iqsamps are ready
        iq_processing(d_iqbuffer, d_binbuffer, nsamps_per_mboard, num_mboards);
        auto t3 = std::chrono::high_resolution_clock::now();
        cudaStreamSynchronize(stream_d2h); // wait until bits are ready
        chan_processing(d_iqbuffer, d_binbuffer, nsamps_per_mboard, num_mboards);

        
        auto t4 = std::chrono::high_resolution_clock::now();
        // Save new packets to file.
        //register_new_packets(h_binbuffer, pc, nsamps_per_mboard,
        //    samps_per_chan, num_mboards, num_samps_rx, pktcount.data());
        {
            std::lock_guard<std::mutex> lock(work_mutex);

        // IMPORTANT: h_binbuffer must remain valid!
        /*
        work_queue.push(PacketWork{
            h_binbuffer,
            num_samps_rx
        });
        }*/
        work_queue.push(PacketWork{
            h_binbuffer_1[bin_buf_idx],
            num_samps_rx,
            h_rssibuffer_1[bin_buf_idx]
        });
        }
        work_cv.notify_one();
        bin_buf_idx = (bin_buf_idx + 1) % 2;
        auto t5 = std::chrono::high_resolution_clock::now();
        // Calculate timings
        double h2d_ms = std::chrono::duration<double, std::milli>(t2 - t1).count();
        double kernel_ms = std::chrono::duration<double, std::milli>(t3 - t2).count();
        double d2h_ms = std::chrono::duration<double, std::milli>(t4 - t3).count();
        double packet_ms = std::chrono::duration<double, std::milli>(t5 - t4).count();
        double total_ms = std::chrono::duration<double, std::milli>(t5 - loop_start).count();
    
        total_h2d_time += h2d_ms;
        total_kernel_time += kernel_ms;
        total_d2h_time += d2h_ms;
        total_packet_time += packet_ms;
        timing_samples++;

        // NEW: Track min/max and history
        if (total_ms < min_total_time) min_total_time = total_ms;
        if (total_ms > max_total_time) max_total_time = total_ms;
        time_history[history_idx++ % HISTORY_SIZE] = total_ms;
        // Display how many packets have been decoded.
        if (debug) {
            for (int k = 0; k < num_mboards*DECFACTOR; k++) 
                std::cout << boost::format("%3d ") % pktcount[k];
            std::cout << std::endl;
        }
        if (timing_samples % 100 == 0) {
            // Calculate variance
            int n = (history_idx < HISTORY_SIZE) ? history_idx : HISTORY_SIZE;
            double sum = 0, sum_sq = 0;
            for (int i = 0; i < n; i++) {
                sum += time_history[i];
                sum_sq += time_history[i] * time_history[i];
            }
            double mean = sum / n;
            double variance = (sum_sq / n) - (mean * mean);
            double stddev = std::sqrt(variance);
        
            double available_ms = (nsamps_per_mboard / (double)SAMP_RATE) * 1000.0;
            std::cout << boost::format(
                "Timing (avg ms): H2D=%.2f Kernel=%.2f D2H=%.2f Packet=%.2f Total=%.2f | Available=%.2f"
                ) % (total_h2d_time/timing_samples)
                % (total_kernel_time/timing_samples) 
                % (total_d2h_time/timing_samples)
                % (total_packet_time/timing_samples)
                % ((total_h2d_time+total_kernel_time+total_d2h_time+total_packet_time)/timing_samples)
                % ((nsamps_per_mboard /(double) SAMP_RATE) * 1000.0)  // Time available before buffer fills
                << std::endl;
            std::cout << boost::format(
                "Timing: Avg=%.2f Min=%.2f Max=%.2f StdDev=%.2f | Available=%.2f Margin=%.2f%%"
                ) % mean 
                % min_total_time 
                % max_total_time 
                % stddev
                % available_ms
                % (((available_ms - mean) / available_ms) * 100.0)
                << std::endl;
            // Calculate how much headroom you need
            double needed_margin = (max_total_time - mean) / mean * 100.0;
            if (needed_margin > ((available_ms - mean) / mean * 100.0)) {
                std::cout << "RECOMMENDATION: Need " << needed_margin 
                      << "% headroom for variance, only have "
                      << (((available_ms - mean) / mean) * 100.0) << "%" << std::endl;
                }
            min_total_time = 1e9;
            max_total_time = 0;
            history_idx = 0;
            // Reset timing stats
            total_h2d_time = 0;
            total_kernel_time = 0;
            total_d2h_time = 0;
            total_packet_time = 0;
            timing_samples = 0;

        //std::cout << boost::format("Overflow: %d Success: %d Ratio: %.2f%%") 
        //    % overflow_count % success_count 
        //    % (100.0 * overflow_count / (overflow_count + success_count))
        //<< std::endl;
        }
        num_samps_rx += samps_per_chan;
        buf_ctrl[0].end_reading();
 
    }

    std::cout << "\n\nShutting down...\n" << std::endl;
    stream_group.join_all();
    free_decoder();

    cudaStreamDestroy(stream_h2d);
    cudaStreamDestroy(stream_d2h);

    // Save data to pcap file.
    pc.flush();
    pc.finalise();

    worker_running = false;
    work_cv.notify_all();
    pkt_thread.join();
    
    // Free allocated memory.
    cudaFreeHost(h_iqbuffer_a);
    cudaFreeHost(h_iqbuffer_b);
    cudaFreeHost(h_binbuffer);
    cudaFreeHost(h_rssibuffer_1[0]);
    cudaFreeHost(h_rssibuffer_1[1]);
    cudaFree(d_iqbuffer);
    cudaFree(d_binbuffer);
    cleanup_zmq();
    std::cout << "\nDone.\n" << std::endl;
    return 0;
}
