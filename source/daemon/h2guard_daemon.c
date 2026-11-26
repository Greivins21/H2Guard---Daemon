/*
 * Copyright (c) 2024, The H2Guard Project Author: Greivin Sanchez Garita
 * All rights reserved.
 * NFQUEUE-based HTTP/2 DoS mitigation daemon.
 *
 * Goal:
 *   Detect and mitigate two related attack families:
 *
 *   1. Multiplexed Asymmetric Workload DDoS / MAWD-like behavior
 *      - This is response-flow oriented.
 *      - The daemon observes server response packets:
 *
 *            server:443 -> client
 *
 *      - It extracts packet accumulation features inspired by the MAWD paper:
 *            max_itv
 *            itv[5]
 *            spd_payload
 *            std_payload
 *
 *   2. Rapid Reset behavior
 *      - This is request-side oriented.
 *      - Rapid Reset primarily manifests as many client-side HTTP/2 stream
 *        creation/cancellation events.
 *      - Since HTTPS traffic is encrypted, this daemon cannot directly inspect
 *        HTTP/2 HEADERS or RST_STREAM frames.
 *      - Instead, it approximates Rapid Reset behavior using packet-level
 *        indicators:
 *            high incoming packet rate
 *            high incoming TCP payload packet rate
 *            low or asymmetric server response ratio
 *            repeated suspicious activity inside a short time window
 *
 * Pipeline:
 *
 *   nftables queue rule
 *        ->
 *   NFQUEUE queue 0
 *        ->
 *   C daemon
 *        ->
 *   packet parsing
 *        ->
 *   MAWD response-flow feature extraction
 *        ->
 *   Rapid Reset request-side heuristic
 *        ->
 *   suspicious IP cache
 *        ->
 *   nftables blocked_ips set
 *
 * Important:
 *   - The daemon accepts the current packet using NF_ACCEPT.
 *   - Blocking is applied to future packets by inserting the client IP into an nftables set.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>
#include <math.h>

#include <linux/ip.h>
#include <linux/tcp.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#ifndef NF_DROP
#define NF_DROP 0
#endif

#ifndef NF_ACCEPT
#define NF_ACCEPT 1
#endif

#define NFQUEUE_NUM 0
#define HTTPS_PORT 443

#define FLOW_TABLE_SIZE 4096
#define CLIENT_TABLE_SIZE 4096
#define SUSPICIOUS_TABLE_SIZE 1024

/*
 * MAWD packet accumulation threshold.
 */
#define EPOCH_PACKET_THRESHOLD 500

/*
 * Suspicious IP attention time.
 * First suspicious event:
 *   mark IP as suspicious
 * Second suspicious event within ATTENTION_TIME_SEC:
 *   block IP using nftables
 */
#define ATTENTION_TIME_SEC 5

/*
 * nftables block timeout.(short for testing reasons)
 */
#define BLOCK_TIMEOUT_SEC 120

/*
 * MAWD response-flow thresholds.
 * These values are intentionally simple and explainable.
 */
#define HIGH_MAX_INTERVAL_SEC 1.0
#define LOW_STD_PAYLOAD_THRESHOLD 80.0
#define HIGH_SPEED_PAYLOAD_THRESHOLD 20000000.0
#define BURST_RATIO_PERCENT 90
#define MAWD_SUSPICIOUS_SCORE_THRESHOLD 4

/*
 * Rapid Reset-style request-side detection window.
 * The daemon evaluates request-side behavior per client over short windows.
 */
#define CLIENT_WINDOW_SEC 2.0

/*
 * Rapid Reset heuristic thresholds.
 *
 * Since TLS hides HTTP/2 frames, these thresholds do not detect RST_STREAM
 * directly. Instead, they look for the observable side effects of Rapid Reset:
 *
 *   - many client-to-server packets
 *   - many client-to-server payload packets
 *   - repeated short bursts
 *   - comparatively few server response payload packets
 *
 */
#define RR_HIGH_INCOMING_PKTS 800
#define RR_HIGH_INCOMING_PAYLOAD_PKTS 400
#define RR_HIGH_INCOMING_BYTES 50000
#define RR_LOW_RESPONSE_RATIO_PERCENT 15
#define RR_SUSPICIOUS_SCORE_THRESHOLD 3

typedef struct flow_key {
    uint32_t server_ip;
    uint32_t client_ip;
    uint16_t server_port;
    uint16_t client_port;
} flow_key_t;

typedef struct flow_entry {
    bool used;

    flow_key_t key;

    struct timeval t_start;
    struct timeval t_last;
    struct timeval t_end;

    uint64_t np;
    uint64_t total_payload_len;
    uint64_t total_payload_len_sq;

    double max_itv;

    uint64_t itv[5];

    struct flow_entry *next;
} flow_entry_t;

/*
 * Per-client activity table.
 *
 * Logic for Rapid Reset detection.
 *
 *   Since this daemon cannot decrypt TLS, it cannot see HTTP/2 HEADERS and
 *   RST_STREAM frames directly. Instead, it tracks request-side metadata:
 *
 *       incoming packet count
 *       incoming TCP payload packet count
 *       incoming payload bytes
 *       SYN count
 *       outgoing server response payload packets
 *       outgoing server response bytes
 *
 *   The key idea:
 *       If a client sends many HTTPS payload packets in a short time window
 *       while producing relatively low server response payload, the pattern
 *       may indicate Rapid Reset-like behavior.
 */
typedef struct client_activity {
    bool used;

    uint32_t client_ip;

    struct timeval window_start;
    struct timeval last_seen;

    uint64_t incoming_packets;
    uint64_t incoming_payload_packets;
    uint64_t incoming_payload_bytes;

    uint64_t outgoing_packets;
    uint64_t outgoing_payload_packets;
    uint64_t outgoing_payload_bytes;

    uint64_t syn_packets;

    struct client_activity *next;
} client_activity_t;

typedef struct suspicious_entry {
    bool used;
    uint32_t client_ip;
    time_t last_seen;

    struct suspicious_entry *next;
} suspicious_entry_t;

static flow_entry_t *flow_table[FLOW_TABLE_SIZE];
static client_activity_t *client_table[CLIENT_TABLE_SIZE];
static suspicious_entry_t *suspicious_table[SUSPICIOUS_TABLE_SIZE];

static void ip_to_string(uint32_t ip, char *buf, size_t buflen) {
    struct in_addr addr;
    addr.s_addr = ip;
    inet_ntop(AF_INET, &addr, buf, buflen);
}

static double timeval_diff_sec(struct timeval newer, struct timeval older) {
    return (double)(newer.tv_sec - older.tv_sec) +
           (double)(newer.tv_usec - older.tv_usec) / 1000000.0;
}

static uint32_t hash_u32(uint32_t x) {
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = (x >> 16) ^ x;
    return x;
}

static uint32_t hash_flow_key(const flow_key_t *key) {
    uint32_t h = 0;

    h ^= hash_u32(key->server_ip);
    h ^= hash_u32(key->client_ip);
    h ^= hash_u32(((uint32_t)key->server_port << 16) | key->client_port);

    return h % FLOW_TABLE_SIZE;
}

static uint32_t hash_client_ip(uint32_t ip) {
    return hash_u32(ip) % CLIENT_TABLE_SIZE;
}

static uint32_t hash_suspicious_ip(uint32_t ip) {
    return hash_u32(ip) % SUSPICIOUS_TABLE_SIZE;
}

static bool flow_key_equals(const flow_key_t *a, const flow_key_t *b) {
    return a->server_ip == b->server_ip &&
           a->client_ip == b->client_ip &&
           a->server_port == b->server_port &&
           a->client_port == b->client_port;
}

static uint32_t get_packet_id(struct nfq_data *nfa) {
    struct nfqnl_msg_packet_hdr *packet_header;

    packet_header = nfq_get_msg_packet_hdr(nfa);

    if (packet_header != NULL) {
        return ntohl(packet_header->packet_id);
    }

    return 0;
}

static void block_ip_with_nft(uint32_t client_ip) {
    char ip_str[INET_ADDRSTRLEN];
    char cmd[256];

    ip_to_string(client_ip, ip_str, sizeof(ip_str));

    snprintf(
        cmd,
        sizeof(cmd),
        "nft add element inet nfqdefense blocked_ips '{ %s timeout %ds }' 2>/dev/null || true",
        ip_str,
        BLOCK_TIMEOUT_SEC
    );

    printf("[BLOCK] Blocking client %s for %d seconds\n", ip_str, BLOCK_TIMEOUT_SEC);

    int rc = system(cmd);

    if (rc != 0) {
        fprintf(stderr, "[!] nft command failed or returned non-zero status\n");
    }
}

static void mark_suspicious_or_block(uint32_t client_ip) {
    uint32_t index = hash_suspicious_ip(client_ip);
    time_t now = time(NULL);

    suspicious_entry_t *entry = suspicious_table[index];

    while (entry != NULL) {
        if (entry->used && entry->client_ip == client_ip) {
            double delta = difftime(now, entry->last_seen);

            char ip_str[INET_ADDRSTRLEN];
            ip_to_string(client_ip, ip_str, sizeof(ip_str));

            if (delta <= ATTENTION_TIME_SEC) {
                printf("[ALERT] Client %s suspicious again within %.0f seconds\n", ip_str, delta);
                block_ip_with_nft(client_ip);
            } else {
                printf("[SUSPICIOUS] Client %s marked again, previous event expired\n", ip_str);
                entry->last_seen = now;
            }

            return;
        }

        entry = entry->next;
    }

    suspicious_entry_t *new_entry = calloc(1, sizeof(suspicious_entry_t));

    if (new_entry == NULL) {
        perror("calloc suspicious_entry");
        return;
    }

    new_entry->used = true;
    new_entry->client_ip = client_ip;
    new_entry->last_seen = now;

    new_entry->next = suspicious_table[index];
    suspicious_table[index] = new_entry;

    char ip_str[INET_ADDRSTRLEN];
    ip_to_string(client_ip, ip_str, sizeof(ip_str));

    printf("[SUSPICIOUS] First suspicious event for client %s\n", ip_str);
}

static void reset_flow_entry(flow_entry_t *entry, struct timeval now) {
    entry->t_start = now;
    entry->t_last = now;
    entry->t_end = now;

    entry->np = 0;
    entry->total_payload_len = 0;
    entry->total_payload_len_sq = 0;
    entry->max_itv = 0.0;

    memset(entry->itv, 0, sizeof(entry->itv));
}

static flow_entry_t *get_or_create_flow(const flow_key_t *key, struct timeval now) {
    uint32_t index = hash_flow_key(key);
    flow_entry_t *entry = flow_table[index];

    while (entry != NULL) {
        if (entry->used && flow_key_equals(&entry->key, key)) {
            return entry;
        }

        entry = entry->next;
    }

    flow_entry_t *new_entry = calloc(1, sizeof(flow_entry_t));

    if (new_entry == NULL) {
        perror("calloc flow_entry");
        return NULL;
    }

    new_entry->used = true;
    new_entry->key = *key;

    reset_flow_entry(new_entry, now);

    new_entry->next = flow_table[index];
    flow_table[index] = new_entry;

    return new_entry;
}

static void reset_client_activity(client_activity_t *entry, struct timeval now) {
    entry->window_start = now;
    entry->last_seen = now;

    entry->incoming_packets = 0;
    entry->incoming_payload_packets = 0;
    entry->incoming_payload_bytes = 0;

    entry->outgoing_packets = 0;
    entry->outgoing_payload_packets = 0;
    entry->outgoing_payload_bytes = 0;

    entry->syn_packets = 0;
}

static client_activity_t *get_or_create_client_activity(uint32_t client_ip, struct timeval now) {
    uint32_t index = hash_client_ip(client_ip);
    client_activity_t *entry = client_table[index];

    while (entry != NULL) {
        if (entry->used && entry->client_ip == client_ip) {
            return entry;
        }

        entry = entry->next;
    }

    client_activity_t *new_entry = calloc(1, sizeof(client_activity_t));

    if (new_entry == NULL) {
        perror("calloc client_activity");
        return NULL;
    }

    new_entry->used = true;
    new_entry->client_ip = client_ip;

    reset_client_activity(new_entry, now);

    new_entry->next = client_table[index];
    client_table[index] = new_entry;

    return new_entry;
}

static void update_interval_histogram(flow_entry_t *entry, double interval) {
    if (interval < 0.01) {
        entry->itv[0]++;
    } else if (interval < 0.1) {
        entry->itv[1]++;
    } else if (interval < 1.0) {
        entry->itv[2]++;
    } else if (interval < 10.0) {
        entry->itv[3]++;
    } else {
        entry->itv[4]++;
    }

    if (interval > entry->max_itv) {
        entry->max_itv = interval;
    }
}

static int classify_mawd_features(
    double max_itv,
    uint64_t np,
    uint64_t itv[5],
    double spd_payload,
    double std_payload
) {
    int score = 0;

    /*
     * MAWD signal 1:
     * High maximum interval between server response packets.
     * This can indicate abnormal response-flow behavior.
     */
    if (max_itv > HIGH_MAX_INTERVAL_SEC) {
        score++;
    }

    /*
     * MAWD signal 2:
     * Low standard deviation of payload sizes.
     * Automated repeated request patterns may produce less variability.
     */
    if (std_payload < LOW_STD_PAYLOAD_THRESHOLD) {
        score++;
    }

    /*
     * MAWD signal 3:
     * High payload transmission speed.
     * This may indicate response bursts caused by multiplexed requests.
     */
    if (spd_payload > HIGH_SPEED_PAYLOAD_THRESHOLD) {
        score++;
    }

    /*
     * MAWD signal 4:
     * Many tightly spaced packets.
     * HTTP/2 multiplexing abuse may produce response bursts.
     */
    uint64_t burst_packets = itv[0] + itv[1];

    if (np > 0 && (burst_packets * 100 / np) >= BURST_RATIO_PERCENT) {
        score++;
    }

    return score;
}

static void extract_features_and_decide(flow_entry_t *entry) {
    char server_ip_str[INET_ADDRSTRLEN];
    char client_ip_str[INET_ADDRSTRLEN];

    ip_to_string(entry->key.server_ip, server_ip_str, sizeof(server_ip_str));
    ip_to_string(entry->key.client_ip, client_ip_str, sizeof(client_ip_str));

    double duration = timeval_diff_sec(entry->t_end, entry->t_start);

    if (duration <= 0.0) {
        duration = 0.000001;
    }

    double spd_payload = (double)entry->total_payload_len / duration;

    double mean = (double)entry->total_payload_len / (double)entry->np;

    double variance =
        ((double)entry->total_payload_len_sq / (double)entry->np) -
        (mean * mean);

    if (variance < 0.0) {
        variance = 0.0;
    }

    double std_payload = sqrt(variance);

    int score = classify_mawd_features(
        entry->max_itv,
        entry->np,
        entry->itv,
        spd_payload,
        std_payload
    );

    if (score >= MAWD_SUSPICIOUS_SCORE_THRESHOLD) {
        mark_suspicious_or_block(entry->key.client_ip);
    }
}

static void evaluate_rapid_reset_window(client_activity_t *entry, struct timeval now) {
    char client_ip_str[INET_ADDRSTRLEN];
    ip_to_string(entry->client_ip, client_ip_str, sizeof(client_ip_str));

    double duration = timeval_diff_sec(now, entry->window_start);

    if (duration <= 0.0) {
        duration = 0.000001;
    }

    double incoming_pkt_rate = (double)entry->incoming_packets / duration;
    double incoming_payload_pkt_rate = (double)entry->incoming_payload_packets / duration;
    double incoming_byte_rate = (double)entry->incoming_payload_bytes / duration;

    uint64_t response_ratio_percent = 100;

    /*
     * Response ratio:
     *
     *   outgoing_payload_packets / incoming_payload_packets
     *
     * Rapid Reset behavior often creates a large amount of client-side
     * stream/control activity while reducing the amount of meaningful server
     * response payload that reaches completion.
     *
     * If incoming_payload_packets is 0, the ratio is kept at 100 to avoid
     * false positives from empty TCP control traffic.
     */
    if (entry->incoming_payload_packets > 0) {
        response_ratio_percent =
            (entry->outgoing_payload_packets * 100) /
            entry->incoming_payload_packets;
    }

    int score = 0;

    /*
     * Rapid Reset signal 1:
     * High number of incoming client packets in a short window.
     */
    if (entry->incoming_packets >= RR_HIGH_INCOMING_PKTS) {
        score++;
    }

    /*
     * Rapid Reset signal 2:
     * High number of incoming TCP payload packets.
     * TLS hides whether these packets contain HEADERS or RST_STREAM frames,
     * but a high payload-packet rate from one client is still suspicious when
     * combined with other indicators.
     */
    if (entry->incoming_payload_packets >= RR_HIGH_INCOMING_PAYLOAD_PKTS) {
        score++;
    }

    /*
     * Rapid Reset signal 3:
     * High incoming payload volume.
     * This helps differentiate active request-side pressure from pure TCP ACKs.
     */
    if (entry->incoming_payload_bytes >= RR_HIGH_INCOMING_BYTES) {
        score++;
    }

    /*
     * Rapid Reset signal 4:
     * Low server response ratio.
     * This is important because Rapid Reset can create many request/control
     * events that do not result in normal completed responses.
     */
    if (entry->incoming_payload_packets > 0 &&
        response_ratio_percent <= RR_LOW_RESPONSE_RATIO_PERCENT) {
        score++;
    }

    if (entry->incoming_payload_packets < 1000) {
    return;
    }

    if (score >= RR_SUSPICIOUS_SCORE_THRESHOLD) {
        mark_suspicious_or_block(entry->client_ip);
    }
}

static void update_client_activity(
    uint32_t client_ip,
    bool is_incoming,
    bool is_outgoing,
    bool has_payload,
    int tcp_payload_len,
    bool is_syn,
    struct timeval now
) {
    client_activity_t *entry = get_or_create_client_activity(client_ip, now);

    if (entry == NULL) {
        return;
    }

    double window_age = timeval_diff_sec(now, entry->window_start);

    /*
     * Evaluate and reset the window when it reaches CLIENT_WINDOW_SEC.
     *
     * This keeps Rapid Reset detection responsive. The attention-window
     * logic in mark_suspicious_or_block() prevents immediate blocking on a
     * single suspicious window.
     */
    if (window_age >= CLIENT_WINDOW_SEC) {
        evaluate_rapid_reset_window(entry, now);
        reset_client_activity(entry, now);
    }

    entry->last_seen = now;

    if (is_incoming) {
        entry->incoming_packets++;

        if (has_payload) {
            entry->incoming_payload_packets++;
            entry->incoming_payload_bytes += (uint64_t)tcp_payload_len;
        }

        if (is_syn) {
            entry->syn_packets++;
        }
    }

    if (is_outgoing) {
        entry->outgoing_packets++;

        if (has_payload) {
            entry->outgoing_payload_packets++;
            entry->outgoing_payload_bytes += (uint64_t)tcp_payload_len;
        }
    }
}

   /*
     * This function implements the MAWD-inspired part of the daemon.
     *
     * It only handles:
     *
     *      server:443 -> client:ephemeral_port
     *
     * This is suitable for multiplexed asymmetric workload attacks where the
     * server produces observable response-flow behavior.
     */
static void process_server_response_flow(
    struct iphdr *ip,
    struct tcphdr *tcp,
    uint16_t src_port,
    uint16_t dst_port,
    int tcp_payload_len,
    struct timeval now
) {
 
    if (tcp_payload_len <= 0) {
        return;
    }

    flow_key_t key;

    memset(&key, 0, sizeof(key));

    key.server_ip = ip->saddr;
    key.client_ip = ip->daddr;
    key.server_port = src_port;
    key.client_port = dst_port;

    flow_entry_t *entry = get_or_create_flow(&key, now);

    if (entry == NULL) {
        return;
    }

    if (entry->np > 0) {
        double interval = timeval_diff_sec(now, entry->t_last);

        if (interval >= 0.0) {
            update_interval_histogram(entry, interval);
        }
    }

    entry->t_last = now;
    entry->t_end = now;

    entry->np++;
    entry->total_payload_len += (uint64_t)tcp_payload_len;
    entry->total_payload_len_sq +=
        (uint64_t)tcp_payload_len * (uint64_t)tcp_payload_len;

    if (entry->np >= EPOCH_PACKET_THRESHOLD) {
        extract_features_and_decide(entry);
        reset_flow_entry(entry, now);
    }
}

static void process_packet(unsigned char *payload, int payload_len) {
    if (payload_len < (int)sizeof(struct iphdr)) {
        return;
    }

    struct iphdr *ip = (struct iphdr *)payload;

    if (ip->version != 4 || ip->protocol != IPPROTO_TCP) {
        return;
    }

    int ip_header_len = ip->ihl * 4;

    if (ip_header_len < (int)sizeof(struct iphdr)) {
        return;
    }

    if (payload_len < ip_header_len + (int)sizeof(struct tcphdr)) {
        return;
    }

    struct tcphdr *tcp = (struct tcphdr *)(payload + ip_header_len);

    int tcp_header_len = tcp->doff * 4;

    if (tcp_header_len < (int)sizeof(struct tcphdr)) {
        return;
    }

    int total_header_len = ip_header_len + tcp_header_len;

    int ip_total_len = ntohs(ip->tot_len);

    if (ip_total_len < total_header_len) {
        return;
    }

    uint16_t src_port = ntohs(tcp->source);
    uint16_t dst_port = ntohs(tcp->dest);

    int tcp_payload_len = ip_total_len - total_header_len;
    bool has_payload = tcp_payload_len > 0;

    struct timeval now;
    gettimeofday(&now, NULL);

    /*
     * Direction classification:
     *
     *   incoming request-side traffic:
     *       client:ephemeral_port -> server:443
     *
     *   outgoing response-side traffic:
     *       server:443 -> client:ephemeral_port
     *
     * Both directions are needed:
     *
     *   - outgoing response flows feed the MAWD-style detector
     *   - incoming client traffic feeds the Rapid Reset-style detector
     */
    bool is_incoming_https = dst_port == HTTPS_PORT;
    bool is_outgoing_https = src_port == HTTPS_PORT;

    if (!is_incoming_https && !is_outgoing_https) {
        return;
    }

    uint32_t client_ip;

    if (is_incoming_https) {
        client_ip = ip->saddr;
    } else {
        client_ip = ip->daddr;
    }

    /*
     * Track Rapid Reset-style request-side behavior for BOTH directions.
     *
     * Incoming packets increase request-side counters.
     * Outgoing packets increase response-side counters.
     *
     * The response-side counters are used to estimate whether one client is
     * generating many incoming payload packets without corresponding normal
     * server responses.
     */
    update_client_activity(
        client_ip,
        is_incoming_https,
        is_outgoing_https,
        has_payload,
        tcp_payload_len,
        tcp->syn && !tcp->ack,
        now
    );

    /*
     * MAWD response-flow analysis.
     * Only server responses are useful for the MAWD-inspired packet
     * accumulation features.
     */
    if (is_outgoing_https) {
        process_server_response_flow(
            ip,
            tcp,
            src_port,
            dst_port,
            tcp_payload_len,
            now
        );
    }
}

static int packet_callback(
    struct nfq_q_handle *qh,
    struct nfgenmsg *nfmsg,
    struct nfq_data *nfa,
    void *data
) {
    (void)nfmsg;
    (void)data;

    uint32_t packet_id = get_packet_id(nfa);

    unsigned char *payload = NULL;
    int payload_len = nfq_get_payload(nfa, &payload);

    if (payload_len >= 0 && payload != NULL) {
        process_packet(payload, payload_len);
    }

    /*
     * Current packet is accepted.
     * If a client becomes blocked, nftables will drop future packets using:
     *      ip saddr @blocked_ips drop
     */
    return nfq_set_verdict(qh, packet_id, NF_ACCEPT, 0, NULL);
}

int main(void) {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;

    int fd;
    int rv;

    char buf[8192] __attribute__((aligned));

    setvbuf(stdout, NULL, _IONBF, 0);

    printf("[*] Starting NFQUEUE HTTP/2 DoS mitigation daemon\n");
    printf("[*] Queue number: %d\n", NFQUEUE_NUM);
    printf("[*] HTTPS port: %d\n", HTTPS_PORT);
    printf("[*] MAWD response-flow threshold theta=%d packets\n", EPOCH_PACKET_THRESHOLD);
    printf("[*] Rapid Reset client window=%.2f seconds\n", CLIENT_WINDOW_SEC);
    printf("[*] Attention time alpha=%d seconds\n", ATTENTION_TIME_SEC);
    printf("[*] Block timeout=%d seconds\n", BLOCK_TIMEOUT_SEC);

    h = nfq_open();

    if (h == NULL) {
        fprintf(stderr, "[-] nfq_open() failed\n");
        exit(EXIT_FAILURE);
    }

    /*
    * Create the NFQUEUE.
    */
    qh = nfq_create_queue(h, NFQUEUE_NUM, &packet_callback, NULL);

    if (qh == NULL) {
        fprintf(stderr, "[-] nfq_create_queue() failed. Is another daemon already using queue 0?\n");
        nfq_close(h);
        exit(EXIT_FAILURE);
    }

        /*
    * Increase kernel-side NFQUEUE length.
    */
    if (nfq_set_queue_maxlen(qh, 65535) < 0) {
        fprintf(stderr, "[!] nfq_set_queue_maxlen() failed\n");
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 256) < 0) { // 256 is a common choice for the copy range. Getting just the beginning of the packet is enough for the analysis. 
        fprintf(stderr, "[-] nfq_set_mode() failed\n");
        nfq_destroy_queue(qh);
        nfq_close(h);
        exit(EXIT_FAILURE);
    }

    if (nfq_set_queue_flags(
        qh,
        NFQA_CFG_F_FAIL_OPEN,
        NFQA_CFG_F_FAIL_OPEN) < 0) {
    fprintf(stderr, "[!] nfq_set_queue_flags() failed\n");}

    fd = nfq_fd(h);
    int rcvbuf = 32 * 1024 * 1024;

    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
        perror("setsockopt SO_RCVBUF");
    }

    printf("[+] Daemon running. Press Ctrl+C to stop.\n");

    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        int result = nfq_handle_packet(h, buf, rv);

        if (result < 0) {
            fprintf(stderr, "[!] nfq_handle_packet() returned error\n");
        }
    }

    if (rv < 0) {
        fprintf(stderr, "[-] recv() failed: %s\n", strerror(errno));
    }

    nfq_destroy_queue(qh);
    nfq_close(h);

    return EXIT_SUCCESS;
}