#include "../../inc/crypto_layer2.h"
#include "../../inc/ne_l2_trace.h"
#include "../../inc/config.h"
#include <string.h>

#define NE_L2_POLICY_EXTRA (NE_WIRE_POLICY_U32 - 1)
#define MIN_ETH_PKT  (ETH_HEADER_SIZE + 8)

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

static inline int l2_enc_start_offset(int nonce_size) {
    return ETH_HEADER_SIZE + 2 + NE_L2_POLICY_EXTRA + nonce_size;
}

static inline int verify_ipv4_after_decrypt(const uint8_t *ip_payload, size_t len) {
    if (unlikely(len < 20)) return 0;
    uint8_t ttl   = ip_payload[8];
    uint8_t proto = ip_payload[9];
    if (unlikely(ttl == 0)) return 0;
    if (proto == 1 || proto == 2 || proto == 6 || proto == 17 ||
        proto == 47 || proto == 50 || proto == 51 || proto == 58 ||
        proto == 89 || proto == 132)
        return 1;
    return 0;
}

int crypto_layer2_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len) {
    if (unlikely(!ctx || !ctx->initialized || !packet || pkt_len < MIN_ETH_PKT))
        return -1;

    const int nonce_size = packet_crypto_get_nonce_size();
    const int l2_enc_start = l2_enc_start_offset(nonce_size);
    const int l2_wire_extra = l2_enc_start - ETH_HEADER_SIZE;

    uint16_t ether_type = ((uint16_t)packet[12] << 8) | packet[13];
    if (unlikely(ether_type != 0x0800))
        return (int)pkt_len;

    uint16_t fake_etype = packet_crypto_get_fake_ethertype_ipv4();
    if (fake_etype == 0)
        fake_etype = NE_DEFAULT_FAKE_ETHERTYPE_IPV4;

    uint32_t counter = packet_crypto_next_counter();
    uint8_t nonce[16];
    int nonce_len;
    const int is_gcm = (packet_crypto_get_mode() == CRYPTO_MODE_GCM);

    crypto_generate_nonce(counter, PROTO_FLAG_IPV4, nonce, &nonce_len);

    const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    const size_t payload_len = pkt_len - ETH_HEADER_SIZE;

    memmove(packet + l2_enc_start, packet + ETH_HEADER_SIZE, payload_len);

    crypto_write_counter(packet, nonce, nonce_size, (uint8_t)(fake_etype >> 8),
                         packet_crypto_get_policy_wire_u32());

    if (likely(is_gcm)) {
        uint8_t tag[AES128_GCM_TAG_SIZE];
        if (unlikely(crypto_aes_gcm_encrypt(key, nonce, nonce_len,
                                            packet + l2_enc_start, (int)payload_len, tag) != 0)) {
            ne_l2_trace_plain("S3-FRAG-ENC", NULL, "FAIL gcm_encrypt");
            return -1;
        }
        memcpy(packet + l2_enc_start + payload_len, tag, AES128_GCM_TAG_SIZE);
        return (int)(pkt_len + l2_wire_extra + AES128_GCM_TAG_SIZE);
    }

    uint8_t iv[AES128_IV_SIZE];
    crypto_nonce_to_iv(nonce, nonce_size, iv);
    if (unlikely(crypto_aes_ctr_with_key(key, iv, packet + l2_enc_start, (int)payload_len) != 0)) {
        ne_l2_trace_plain("S3-FRAG-ENC", NULL, "FAIL ctr_encrypt");
        return -1;
    }
    return (int)(pkt_len + l2_wire_extra);
}

int crypto_layer2_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len) {
    if (unlikely(!ctx || !ctx->initialized || !packet))
        return -1;

    const int nonce_size = packet_crypto_get_nonce_size();
    const int l2_enc_start = l2_enc_start_offset(nonce_size);

    if (unlikely(pkt_len < (size_t)l2_enc_start))
        return -1;

    uint16_t fake_ipv4 = packet_crypto_get_fake_ethertype_ipv4();
    if (fake_ipv4 == 0)
        fake_ipv4 = NE_DEFAULT_FAKE_ETHERTYPE_IPV4;

    if (packet[12] != (uint8_t)(fake_ipv4 >> 8))
        return (int)pkt_len;

    uint8_t proto_flag;
    uint8_t nonce[16];
    uint32_t policy_wire = 0;
    crypto_read_counter(packet, nonce_size, nonce, &policy_wire, &proto_flag);
    (void)proto_flag;
    (void)policy_wire;

    const int is_gcm = (packet_crypto_get_mode() == CRYPTO_MODE_GCM);
    const int nonce_len = is_gcm ? nonce_size : AES128_IV_SIZE;

    size_t enc_len = pkt_len - l2_enc_start;
    uint8_t tag[AES128_GCM_TAG_SIZE];
    if (is_gcm) {
        if (unlikely(pkt_len < (size_t)(l2_enc_start + AES128_GCM_TAG_SIZE)))
            return -1;
        enc_len -= AES128_GCM_TAG_SIZE;
        memcpy(tag, packet + l2_enc_start + enc_len, AES128_GCM_TAG_SIZE);
    }

    const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    uint8_t *work_ptr = packet + l2_enc_start;

    if (likely(is_gcm)) {
        if (crypto_aes_gcm_decrypt(key, nonce, nonce_len, work_ptr, (int)enc_len, tag) != 0) {
            ne_l2_trace_plain("S6-RX-DEC", NULL, "FAIL gcm_decrypt");
            return -1;
        }
    } else {
        uint8_t iv[AES128_IV_SIZE];
        crypto_nonce_to_iv(nonce, nonce_size, iv);
        if (crypto_aes_ctr_with_key(key, iv, work_ptr, (int)enc_len) != 0 ||
            !verify_ipv4_after_decrypt(work_ptr, enc_len)) {
            ne_l2_trace_plain("S6-RX-DEC", NULL, "FAIL ctr_decrypt");
            return -1;
        }
    }

    int has_ethertype = (work_ptr[0] == 0x08 && work_ptr[1] == 0x00);
    int out_len;
    if (has_ethertype) {
        packet[12] = work_ptr[0];
        packet[13] = work_ptr[1];
        memmove(packet + ETH_HEADER_SIZE, work_ptr + 2, enc_len - 2);
        out_len = (int)(ETH_HEADER_SIZE + enc_len - 2);
    } else {
        packet[12] = 0x08;
        packet[13] = 0x00;
        memmove(packet + ETH_HEADER_SIZE, work_ptr, enc_len);
        out_len = (int)(ETH_HEADER_SIZE + enc_len);
    }

    return out_len;
}
