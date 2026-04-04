#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

// ----------------------------------------------------------------------------
// SHA1 specific definitions
// ----------------------------------------------------------------------------
typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    uint8_t buffer[64];
} SHA1_CTX;

void my_SHA1_Init(SHA1_CTX* context);
void my_SHA1_Update(SHA1_CTX* context, const uint8_t* data, uint32_t len);
void my_SHA1_Final(uint8_t digest[20], SHA1_CTX* context);

// ----------------------------------------------------------------------------
// Base64 encoding
// ----------------------------------------------------------------------------
void base64_encode(const uint8_t *src, size_t len, char *out_str);

// ----------------------------------------------------------------------------
// WebSocket Helpers
// ----------------------------------------------------------------------------
void generate_ws_accept_key(const char* client_key, char* accept_key_out);

// Extract WebSocket frame payload.
// Returns payload length on success, or < 0 if frame is incomplete/invalid.
// `payload_out` will point to the unmasked payload inside `in_buffer`.
// `frame_size_out` will contain the total size of the frame consumed.
int parse_ws_frame(uint8_t* in_buffer, size_t in_len, uint8_t** payload_out, size_t* frame_size_out, int* opcode);

// Build a WebSocket text frame.
// Returns the size of the constructed frame.
size_t build_ws_text_frame(const char* payload, uint8_t* out_frame, size_t max_out_len);

// Hash password
void hash_password_sha1(const char* password, char* hash_out);

#endif // UTILS_H
