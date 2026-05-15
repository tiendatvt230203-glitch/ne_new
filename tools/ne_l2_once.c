/* ne_l2_once — one-shot L2 encrypt / check capture. Throw away after debug works.
 *
 *   make ne_l2_once
 *   ./bin/ne_l2_once enc cleartext.bin wire.bin 00112233445566778899aabbccddeeff 421
 *   ./bin/ne_l2_once chk capture.hex 00112233445566778899aabbccddeeff 421
 *
 * capture.hex = paste one frame from: tcpdump -i WAN -xx -c 1 'ether proto 0x88b5'
 */

#include "../inc/packet_crypto.h"
#include "../inc/crypto_layer2.h"
#include "../inc/config.h"

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PKT 9216

static int parse_key(const char *hex, uint8_t k[AES_MAX_KEY_SIZE]) {
    if (strlen(hex) != 32) return -1;
    for (int i = 0; i < 16; i++) {
        unsigned x;
        if (sscanf(hex + i * 2, "%2x", &x) != 1) return -1;
        k[i] = (uint8_t)x;
    }
    return 0;
}

static void crypto_setup(struct packet_crypto_ctx *ctx, const uint8_t k[AES_MAX_KEY_SIZE], uint32_t pol) {
    packet_crypto_init(ctx, k);
    packet_crypto_set_mode(CRYPTO_MODE_GCM);
    packet_crypto_set_aes_bits(128);
    packet_crypto_set_nonce_size(12);
    packet_crypto_set_ethertype(NE_DEFAULT_FAKE_ETHERTYPE_IPV4, 0);
    packet_crypto_set_policy_wire_u32(pol);
    packet_crypto_reset_counter();
}

static int load_bin(const char *path, uint8_t *b, size_t cap, size_t *n) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    *n = fread(b, 1, cap, f);
    fclose(f);
    return (*n > 0) ? 0 : -1;
}

static int load_hex(const char *path, uint8_t *b, size_t cap, size_t *n) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    *n = 0;
    int hi = -1, c;
    while ((c = fgetc(f)) != EOF) {
        if (c == '#') { while ((c = fgetc(f)) != EOF && c != '\n') {} continue; }
        int v = (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10
              : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
        if (v < 0) continue;
        if (hi < 0) hi = v;
        else {
            if (*n >= cap) { fclose(f); return -1; }
            b[(*n)++] = (uint8_t)((hi << 4) | v);
            hi = -1;
        }
    }
    fclose(f);
    return 0;
}

static int save_bin(const char *path, const uint8_t *b, size_t n) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    if (fwrite(b, 1, n, f) != n) { fclose(f); return -1; }
    fclose(f);
    return 0;
}

static int cmd_enc(int argc, char **argv) {
    if (argc < 6) {
        fprintf(stderr, "enc <in.bin> <out.bin> <key_hex_32> <policy_id>\n");
        return 1;
    }
    uint8_t key[AES_MAX_KEY_SIZE], pkt[MAX_PKT], out[MAX_PKT];
    size_t n = 0;
    if (parse_key(argv[4], key) || load_bin(argv[2], pkt, sizeof(pkt), &n)) {
        fprintf(stderr, "bad key or cannot read %s\n", argv[2]);
        return 1;
    }
    uint32_t pol = (uint32_t)strtoul(argv[5], NULL, 0);
    memcpy(out, pkt, n);
    struct packet_crypto_ctx ctx;
    crypto_setup(&ctx, key, pol);
    int nw = crypto_layer2_encrypt(&ctx, out, n);
    if (nw < 0) {
        fprintf(stderr, "encrypt failed (input must be IPv4 eth 0x0800)\n");
        return 1;
    }
    if (save_bin(argv[3], out, (size_t)nw)) {
        fprintf(stderr, "write %s failed\n", argv[3]);
        return 1;
    }
  fprintf(stderr, "OK %zu -> %d bytes  marker=0x%02x policy=%u  (send this file or inject out.bin)\n",
            n, nw, out[12], pol);
    return 0;
}

static int cmd_chk(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "chk <capture.hex> <key_hex_32> <policy_id>\n");
        return 1;
    }
    uint8_t key[AES_MAX_KEY_SIZE], pkt[MAX_PKT];
    size_t n = 0;
    if (parse_key(argv[3], key) || load_hex(argv[2], pkt, sizeof(pkt), &n)) {
        fprintf(stderr, "bad key or cannot parse hex %s\n", argv[2]);
        return 1;
    }
    uint32_t pol = (uint32_t)strtoul(argv[4], NULL, 0);
    uint32_t wire = ((uint32_t)pkt[13] << 24) | ((uint32_t)pkt[14] << 16) |
                    ((uint32_t)pkt[15] << 8) | pkt[16];

    fprintf(stderr, "wire len=%zu byte[12]=0x%02x policy_on_wire=%u expect=%u\n",
            n, n > 12 ? pkt[12] : 0, wire, pol);

    if (n > 12 && pkt[12] != (uint8_t)(NE_DEFAULT_FAKE_ETHERTYPE_IPV4 >> 8)) {
        fprintf(stderr, "FAIL: not NE L2 marker (expect 0x88)\n");
        return 1;
    }
    if (wire != pol) {
        fprintf(stderr, "FAIL: policy id mismatch\n");
        return 1;
    }

    struct packet_crypto_ctx ctx;
    crypto_setup(&ctx, key, pol);
    int dec = crypto_layer2_decrypt(&ctx, pkt, n);
    if (dec < 0) {
        fprintf(stderr, "FAIL: decrypt (wrong key/mode or truncated frame; 1500B cleartext expect ~1533 wire)\n");
        return 1;
    }
    if (dec < 14 + 20 || pkt[12] != 0x08 || pkt[13] != 0x00) {
        fprintf(stderr, "FAIL: after decrypt no IPv4 ethertype\n");
        return 1;
    }
    fprintf(stderr, "OK decrypt -> %d bytes IPv4 frame\n", dec);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage:\n  %s enc <in.bin> <out.bin> <key32hex> <policy>\n"
                        "  %s chk <capture.hex> <key32hex> <policy>\n", argv[0], argv[0]);
        return 1;
    }
    if (!strcmp(argv[1], "enc")) return cmd_enc(argc, argv);
    if (!strcmp(argv[1], "chk")) return cmd_chk(argc, argv);
    fprintf(stderr, "unknown: %s (use enc or chk)\n", argv[1]);
    return 1;
}
