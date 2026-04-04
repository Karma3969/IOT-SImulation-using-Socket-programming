#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

// ----------------------------------------------------------------------------
// SHA1 specific definitions
// ----------------------------------------------------------------------------
#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

// blk0() and blk() perform the initial expand.
// I got the idea of expanding during the round function from SSLeay
#if BYTE_ORDER == LITTLE_ENDIAN
#define blk0(i) (block->l[i] = (rol(block->l[i],24)&0xFF00FF00) \
    |(rol(block->l[i],8)&0x00FF00FF))
#elif BYTE_ORDER == BIG_ENDIAN
#define blk0(i) block->l[i]
#else
#define blk0(i) (block->l[i] = (rol(block->l[i],24)&0xFF00FF00) \
    |(rol(block->l[i],8)&0x00FF00FF))
#endif
#define blk(i) (block->l[i&15] = rol(block->l[(i+13)&15]^block->l[(i+8)&15] \
    ^block->l[(i+2)&15]^block->l[i&15],1))

// (R0+R1), R2, R3, R4 are the different operations used in SHA1
#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk0(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);

// Hash a single 512-bit block. This is the core of the algorithm.
static void SHA1Transform(uint32_t state[5], const uint8_t buffer[64])
{
union {
    uint8_t c[64];
    uint32_t l[16];
} block_u;
memcpy(block_u.c, buffer, 64);
uint32_t a = state[0];
uint32_t b = state[1];
uint32_t c = state[2];
uint32_t d = state[3];
uint32_t e = state[4];

#define block (&block_u)

    // 4 rounds of 20 operations each. Loop unrolled.
    R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
    R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
    R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
    R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
    R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
    R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
    R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
    R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
    R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
    R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
    R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
    R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
    R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
    R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
    R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
    R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
    R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
    R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
    R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
    R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;

#undef block
}

void my_SHA1_Init(SHA1_CTX* context)
{
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count[0] = context->count[1] = 0;
}

void my_SHA1_Update(SHA1_CTX* context, const uint8_t* data, uint32_t len)
{
    uint32_t i, j;
    j = (context->count[0] >> 3) & 63;
    if ((context->count[0] += len << 3) < (len << 3)) context->count[1]++;
    context->count[1] += (len >> 29);
    if ((j + len) > 63) {
        memcpy(&context->buffer[j], data, (i = 64-j));
        SHA1Transform(context->state, context->buffer);
        for ( ; i + 63 < len; i += 64) {
            SHA1Transform(context->state, &data[i]);
        }
        j = 0;
    }
    else i = 0;
    memcpy(&context->buffer[j], &data[i], len - i);
}

void my_SHA1_Final(uint8_t digest[20], SHA1_CTX* context)
{
    uint32_t i, j;
    uint8_t finalcount[8];
    uint8_t c;
    for (i = 0; i < 8; i++) {
        finalcount[i] = (uint8_t)((context->count[(i >= 4 ? 0 : 1)]
         >> ((3-(i & 3)) * 8) ) & 255);
    }
    c = 0200;
    my_SHA1_Update(context, &c, 1);
    while ((context->count[0] & 504) != 448) {
        c = 0000;
        my_SHA1_Update(context, &c, 1);
    }
    my_SHA1_Update(context, finalcount, 8);
    for (i = 0; i < 20; i++) {
        digest[i] = (uint8_t)
         ((context->state[i>>2] >> ((3-(i & 3)) * 8) ) & 255);
    }
    memset(context, '\0', sizeof(*context));
}

// ----------------------------------------------------------------------------
// Base64 encoding
// ----------------------------------------------------------------------------
static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void base64_encode(const uint8_t *src, size_t len, char *out_str)
{
    size_t i = 0, j = 0;
    uint32_t octet_a, octet_b, octet_c, triple;

    for (i = 0; i < len; ) {
        octet_a = i < len ? src[i++] : 0;
        octet_b = i < len ? src[i++] : 0;
        octet_c = i < len ? src[i++] : 0;

        triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        out_str[j++] = b64_table[(triple >> 3 * 6) & 0x3F];
        out_str[j++] = b64_table[(triple >> 2 * 6) & 0x3F];
        out_str[j++] = b64_table[(triple >> 1 * 6) & 0x3F];
        out_str[j++] = b64_table[(triple >> 0 * 6) & 0x3F];
    }

    // padding
    int mod_table[] = {0, 2, 1};
    int pad_len = mod_table[len % 3];
    for (i = 0; i < pad_len; i++) {
        out_str[j - 1 - i] = '=';
    }
    out_str[j] = '\0';
}

// ----------------------------------------------------------------------------
// WebSocket Helpers
// ----------------------------------------------------------------------------
#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

void generate_ws_accept_key(const char* client_key, char* accept_key_out)
{
    char concat[256];
    snprintf(concat, sizeof(concat), "%s%s", client_key, WS_GUID);

    SHA1_CTX ctx;
    uint8_t hash[20];
    my_SHA1_Init(&ctx);
    my_SHA1_Update(&ctx, (uint8_t*)concat, strlen(concat));
    my_SHA1_Final(hash, &ctx);

    base64_encode(hash, 20, accept_key_out);
}

// Parse WebSocket frame
int parse_ws_frame(uint8_t* in_buffer, size_t in_len, uint8_t** payload_out, size_t* frame_size_out, int* opcode)
{
    if (in_len < 2) return -1; // Need at least 2 bytes

    uint8_t first_byte = in_buffer[0];
    uint8_t second_byte = in_buffer[1];

    int fin = (first_byte & 0x80) != 0;
    *opcode = first_byte & 0x0F;
    int mask = (second_byte & 0x80) != 0;
    uint64_t payload_len = second_byte & 0x7F;

    size_t header_size = 2;
    if (payload_len == 126) {
        if (in_len < 4) return -1;
        payload_len = (in_buffer[2] << 8) | in_buffer[3];
        header_size += 2;
    } else if (payload_len == 127) {
        if (in_len < 10) return -1;
        payload_len = 0;
        for (int i = 0; i < 8; i++) {
            payload_len = (payload_len << 8) | in_buffer[2 + i];
        }
        header_size += 8;
    }

    uint8_t masking_key[4] = {0};
    if (mask) {
        if (in_len < header_size + 4) return -1;
        memcpy(masking_key, &in_buffer[header_size], 4);
        header_size += 4;
    }

    if (in_len < header_size + payload_len) return -1; // Incomplete frame

    *payload_out = &in_buffer[header_size];
    *frame_size_out = header_size + payload_len;

    // Unmask
    if (mask) {
        for (size_t i = 0; i < payload_len; i++) {
            (*payload_out)[i] ^= masking_key[i % 4];
        }
    }

    return (int)payload_len;
}

// Build text frame
size_t build_ws_text_frame(const char* payload, uint8_t* out_frame, size_t max_out_len)
{
    size_t payload_len = strlen(payload);
    size_t header_len = 2;

    if (payload_len >= 126 && payload_len <= 65535) {
        header_len += 2;
    } else if (payload_len > 65535) {
        header_len += 8;
    }

    if (header_len + payload_len > max_out_len) return 0; // Buffer too small

    out_frame[0] = 0x81; // FIN + Text opcode
    if (payload_len < 126) {
        out_frame[1] = payload_len;
    } else if (payload_len <= 65535) {
        out_frame[1] = 126;
        out_frame[2] = (payload_len >> 8) & 0xFF;
        out_frame[3] = payload_len & 0xFF;
    } else {
        out_frame[1] = 127;
        for(int i=0; i<8; i++){
            out_frame[2+i] = (payload_len >> (8*(7-i))) & 0xFF;
        }
    }

    memcpy(&out_frame[header_len], payload, payload_len);
    return header_len + payload_len;
}

void hash_password_sha1(const char* password, char* hash_out) {
    SHA1_CTX ctx;
    uint8_t hash[20];
    my_SHA1_Init(&ctx);
    my_SHA1_Update(&ctx, (const uint8_t*)password, strlen(password));
    my_SHA1_Final(hash, &ctx);
    base64_encode(hash, 20, hash_out);
}
