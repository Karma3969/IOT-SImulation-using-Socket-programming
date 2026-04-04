/**
 * device_client.c
 * Simulates an IoT device connecting to the WebSocket server over TLS/SSL.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <errno.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "utils.h"

#define SERVER_IP "127.0.0.1"
#define PORT 8080

// Build and send masked text frame (Clients MUST mask frames according to RFC 6455)
void send_masked_ws_text(SSL* ssl, const char* payload) {
    size_t payload_len = strlen(payload);
    uint8_t frame[4096];
    
    // Very simple short frame builder
    frame[0] = 0x81; // FIN + Text
    frame[1] = 0x80 | (payload_len & 0x7F); // MASK bit + length
    
    // Random masking key
    uint8_t mask_key[4] = { rand() % 256, rand() % 256, rand() % 256, rand() % 256 };
    memcpy(&frame[2], mask_key, 4);
    
    // Mask payload
    for (size_t i = 0; i < payload_len; i++) {
        frame[6 + i] = payload[i] ^ mask_key[i % 4];
    }
    
    SSL_write(ssl, frame, 6 + payload_len);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <device_id>\n", argv[0]);
        return 1;
    }

    char* device_id = argv[1];
    srand(time(NULL));

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    // Reconnection logic loop
    while (1) {
        int sock = 0;
        struct sockaddr_in serv_addr;
        
        printf("Connecting to server as %s...\n", device_id);

        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            perror("Socket creation error");
            sleep(2);
            continue;
        }

        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(PORT);

        if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
            perror("Invalid address/ Address not supported");
            close(sock);
            sleep(2);
            continue;
        }

        if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
            perror("Connection Failed");
            close(sock);
            sleep(5); // Wait before reconnect
            continue;
        }

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock);
        
        if (SSL_connect(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(sock);
            sleep(5);
            continue;
        }

        // Perform HTTP WebSocket Upgrade
        const char* req = 
            "GET / HTTP/1.1\r\n"
            "Host: localhost:8080\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" // Hardcoded for simulator
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n";
            
        SSL_write(ssl, req, strlen(req));

        char buffer[4096] = {0};
        int valread = SSL_read(ssl, buffer, sizeof(buffer)-1);
        if (valread <= 0 || !strstr(buffer, "101 Switching Protocols")) {
            printf("Upgrade failed.\n");
            SSL_free(ssl);
            close(sock);
            sleep(3);
            continue;
        }

        printf("Connected and Upgraded to Secure WebSockets!\n");

        // Send auth frame (using default hardcoded admin account for devices)
        char auth_json[256];
        snprintf(auth_json, sizeof(auth_json), "{\"type\":\"auth\",\"is_device\":true,\"device\":\"%s\",\"username\":\"admin\",\"password\":\"admin123\"}", device_id);
        send_masked_ws_text(ssl, auth_json);

        char device_status[16] = "OFF";

        fd_set readfds;
        struct timeval tv;
        time_t last_update = 0;

        while (1) {
            FD_ZERO(&readfds);
            FD_SET(sock, &readfds);

            tv.tv_sec = 1;
            tv.tv_usec = 0;

            int activity = select(sock + 1, &readfds, NULL, NULL, &tv);

            if (activity < 0) {
                printf("select error\n");
                break;
            }

            // Periodic status update (every 5 seconds)
            time_t now = time(NULL);
            if (now - last_update >= 5) {
                char json[256];
                snprintf(json, sizeof(json), "{\"type\":\"status\",\"device\":\"%s\",\"state\":\"%s\"}", device_id, device_status);
                send_masked_ws_text(ssl, json);
                last_update = now;
            }

            if (FD_ISSET(sock, &readfds)) {
                uint8_t buf[1024];
                int n = SSL_read(ssl, buf, sizeof(buf)-1);
                if (n <= 0) {
                    printf("Server disconnected. Reconnecting...\n");
                    break;
                }
                
                // Parse frame
                uint8_t* payload;
                size_t frame_size;
                int opcode;
                if (parse_ws_frame(buf, n, &payload, &frame_size, &opcode) > 0) {
                    if (opcode == 0x1) { // Text
                        payload[frame_size - (payload - buf)] = '\0'; // Null terminate
                        
                        // Parse command
                        char* act_ptr = strstr((char*)payload, "\"action\":\"");
                        if (act_ptr) {
                            char action[16] = {0};
                            sscanf(act_ptr + 10, "%15[^\"]", action);
                            printf("Received Command: Set state to %s\n", action);
                            strncpy(device_status, action, sizeof(device_status)-1);
                            
                            // Immediately send new status back
                            char json_resp[256];
                            snprintf(json_resp, sizeof(json_resp), "{\"type\":\"status\",\"device\":\"%s\",\"state\":\"%s\"}", device_id, device_status);
                            send_masked_ws_text(ssl, json_resp);
                        }
                    } else if (opcode == 0x9) { // Ping
                        buf[0] = 0x8A; // Pong
                        // mask it
                        uint8_t mask_key[4] = {0,0,0,0};
                        buf[1] = 0x80;
                        memcpy(&buf[2], mask_key, 4);
                        SSL_write(ssl, buf, 6);
                    }
                }
            }
        }
        SSL_free(ssl);
        close(sock);
    }
    SSL_CTX_free(ctx);
    return 0;
}
