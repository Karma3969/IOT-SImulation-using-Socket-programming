/**
 * websocket_server.c
 * Core server implementation for the IoT Smart Home Controller.
 * Handles TCP lifecycle, I/O multiplexing with select(), HTTP/WebSocket handshake, and message parsing.
 * Now updated with OpenSSL and Authentication.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/select.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "utils.h"
#include "db.h"

#define PORT 8080
#define MAX_CLIENTS 100
#define BUFFER_SIZE 8192

typedef enum {
    STATE_HTTP,
    STATE_AUTH_PENDING,
    STATE_WEBSOCKET
} ClientState;

typedef struct {
    int fd;
    SSL *ssl;
    ClientState state;
    uint8_t buffer[BUFFER_SIZE]; // Partial read buffer
    size_t buffer_len;
    int is_device;               // 1 if device simulator, 0 if web client
    char device_id[32];          // e.g. "light1"
    char username[64];
} client_t;

client_t clients[MAX_CLIENTS];

// Make a socket non-blocking
void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return;
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// Disconnect a client and clean up
void disconnect_client(int i) {
    if (clients[i].fd != -1) {
        if (clients[i].ssl) {
            SSL_shutdown(clients[i].ssl);
            SSL_free(clients[i].ssl);
            clients[i].ssl = NULL;
        }
        close(clients[i].fd);
        clients[i].fd = -1;
        clients[i].state = STATE_HTTP;
        clients[i].buffer_len = 0;
        clients[i].is_device = 0;
        memset(clients[i].device_id, 0, sizeof(clients[i].device_id));
        memset(clients[i].username, 0, sizeof(clients[i].username));
        printf("Client slot %d disconnected.\n", i);
    }
}

// Broadcast a message to all authenticated web clients (and optionally devices)
void broadcast_ws_text(const char* payload, int only_web_clients) {
    uint8_t frame[BUFFER_SIZE];
    size_t frame_len = build_ws_text_frame(payload, frame, sizeof(frame));
    if (frame_len == 0) return;

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].fd != -1 && clients[i].state == STATE_WEBSOCKET) {
            if (only_web_clients && clients[i].is_device) continue;
            
            ssize_t sent = SSL_write(clients[i].ssl, frame, frame_len);
            if (sent <= 0) {
                int err = SSL_get_error(clients[i].ssl, sent);
                if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                    disconnect_client(i);
                }
            }
        }
    }
}

// Process HTTP upgrade to WebSocket
void handle_http_request(int client_index) {
    client_t* c = &clients[client_index];
    
    char* header_end = strstr((char*)c->buffer, "\r\n\r\n");
    if (!header_end) {
        if (c->buffer_len == BUFFER_SIZE) {
            disconnect_client(client_index);
        }
        return; 
    }

    char* key_start = strstr((char*)c->buffer, "Sec-WebSocket-Key: ");
    if (!key_start) {
        const char* bad_req = "HTTP/1.1 400 Bad Request\r\n\r\n";
        SSL_write(c->ssl, bad_req, strlen(bad_req));
        disconnect_client(client_index);
        return;
    }

    key_start += 19;
    char* key_end = strchr(key_start, '\r');
    if (!key_end) return;

    char client_key[64] = {0};
    strncpy(client_key, key_start, key_end - key_start);

    char accept_key[64];
    generate_ws_accept_key(client_key, accept_key);

    char response[512];
    snprintf(response, sizeof(response),
             "HTTP/1.1 101 Switching Protocols\r\n"
             "Upgrade: websocket\r\n"
             "Connection: Upgrade\r\n"
             "Sec-WebSocket-Accept: %s\r\n"
             "\r\n", accept_key);

    SSL_write(c->ssl, response, strlen(response));

    // Transition to Auth Pending
    c->state = STATE_AUTH_PENDING;
    c->buffer_len = 0;
    printf("Client slot %d upgraded to WebSocket. Awaiting authentication.\n", client_index);
}

// Parse basic JSON using standard C string matching 
void handle_json_message(int client_index, const char* json) {
    client_t* c = &clients[client_index];

    char type[32] = {0};
    char* type_ptr = strstr(json, "\"type\":\"");
    if (type_ptr) sscanf(type_ptr + 8, "%31[^\"]", type);

    if (c->state == STATE_AUTH_PENDING) {
        if (strcmp(type, "auth") == 0) {
            char username[64] = {0};
            char password[64] = {0};
            
            char* user_ptr = strstr(json, "\"username\":\"");
            if (user_ptr) sscanf(user_ptr + 12, "%63[^\"]", username);
            
            char* pass_ptr = strstr(json, "\"password\":\"");
            if (pass_ptr) sscanf(pass_ptr + 12, "%63[^\"]", password);
            
            char hashed[64];
            hash_password_sha1(password, hashed);
            
            if (db_verify_user(username, hashed)) {
                c->state = STATE_WEBSOCKET; // Authenticated
                strncpy(c->username, username, sizeof(c->username)-1);
                
                // Optional: Device might send is_device=true in auth
                char* dev_ptr = strstr(json, "\"is_device\":true");
                if (dev_ptr) {
                    c->is_device = 1;
                    char dev_id[32] = {0};
                    char* id_ptr = strstr(json, "\"device\":\"");
                    if (id_ptr) sscanf(id_ptr + 10, "%31[^\"]", dev_id);
                    strncpy(c->device_id, dev_id, sizeof(c->device_id)-1);
                    printf("Device %s authenticated successfully.\n", c->device_id);
                } else {
                    printf("User %s authenticated successfully.\n", c->username);
                }
                
                // Respond success
                const char* ack = "{\"type\":\"auth_ack\",\"status\":\"success\"}";
                uint8_t frame[256];
                size_t flen = build_ws_text_frame(ack, frame, sizeof(frame));
                SSL_write(c->ssl, frame, flen);
            } else {
                printf("Authentication failed for user: %s\n", username);
                const char* nack = "{\"type\":\"auth_ack\",\"status\":\"fail\"}";
                uint8_t frame[256];
                size_t flen = build_ws_text_frame(nack, frame, sizeof(frame));
                SSL_write(c->ssl, frame, flen);
                disconnect_client(client_index);
            }
        } else {
            // Disconnect unauthenticated attempting other commands
            disconnect_client(client_index);
        }
        return;
    }

    // Authenticated handlers
    char device[32] = {0};
    char state_or_action[32] = {0};

    char* dev_ptr = strstr(json, "\"device\":\"");
    if (dev_ptr) sscanf(dev_ptr + 10, "%31[^\"]", device);

    if (strcmp(type, "status") == 0) {
        char* state_ptr = strstr(json, "\"state\":\"");
        if (state_ptr) sscanf(state_ptr + 9, "%31[^\"]", state_or_action);
        
        printf("[Device Status] %s is %s\n", device, state_or_action);
        
        db_update_device_status(device, state_or_action);
        db_log_action(device, "STATUS_UPDATE");
        
        broadcast_ws_text(json, 1);

    } else if (strcmp(type, "command") == 0) {
        char* act_ptr = strstr(json, "\"action\":\"");
        if (act_ptr) sscanf(act_ptr + 10, "%31[^\"]", state_or_action);
        
        printf("[Web Client Cmd by %s] Turn %s %s\n", c->username, device, state_or_action);
        db_log_action(device, state_or_action);

        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].fd != -1 && clients[i].is_device && strcmp(clients[i].device_id, device) == 0) {
                uint8_t frame[BUFFER_SIZE];
                size_t frame_len = build_ws_text_frame(json, frame, sizeof(frame));
                SSL_write(clients[i].ssl, frame, frame_len);
            }
        }
    }
}


void handle_ws_request(int client_index) {
    client_t* c = &clients[client_index];

    uint8_t* payload;
    size_t frame_size;
    int opcode;
    
    int payload_len = parse_ws_frame(c->buffer, c->buffer_len, &payload, &frame_size, &opcode);
    
    if (payload_len < 0) {
        if (c->buffer_len == BUFFER_SIZE) {
            disconnect_client(client_index); 
        }
        return;
    }

    if (opcode == 0x8) {
        disconnect_client(client_index);
        return;
    } else if (opcode == 0x9) {
        uint8_t pong_frame[128];
        pong_frame[0] = 0x8A; 
        pong_frame[1] = payload_len < 125 ? payload_len : 0;
        if(payload_len < 125 && payload_len > 0) {
            memcpy(&pong_frame[2], payload, payload_len);
        }
        SSL_write(c->ssl, pong_frame, 2 + pong_frame[1]);
    } else if (opcode == 0x1) {
        char json[BUFFER_SIZE];
        if (payload_len < (int)sizeof(json)) {
            memcpy(json, payload, payload_len);
            json[payload_len] = '\0';
            handle_json_message(client_index, json);
        }
    }

    memmove(c->buffer, c->buffer + frame_size, c->buffer_len - frame_size);
    c->buffer_len -= frame_size;
}

int main() {
    int server_fd;
    struct sockaddr_in address;

    // OpenSSL Initialization
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);

    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    
    // Configure certs (You must generate these via OpenSSL manually)
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        printf("Error: Missing cert.pem. Please generate it.\n");
        exit(1);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        printf("Error: Missing key.pem. Please generate it.\n");
        exit(1);
    }

    if (db_init("smarthome_wsl.db") < 0) return 1;

    // Seed default admin
    char admin_hash[64];
    hash_password_sha1("admin123", admin_hash);
    db_add_user("admin", admin_hash); // Will ignore if exists

    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i].fd = -1;
        clients[i].ssl = NULL;
    }

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed"); exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt SO_REUSEADDR"); exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt))) {
        perror("setsockopt TCP_NODELAY"); exit(EXIT_FAILURE);
    }

    set_nonblocking(server_fd);

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed"); exit(EXIT_FAILURE);
    }

    if (listen(server_fd, SOMAXCONN) < 0) {
        perror("Listen failed"); exit(EXIT_FAILURE);
    }

    printf("WebSocket Server (SSL) running on port %d\n", PORT);

    fd_set readfds;

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);
        int max_sd = server_fd;

        for (int i = 0; i < MAX_CLIENTS; i++) {
            int sd = clients[i].fd;
            if (sd > 0) FD_SET(sd, &readfds);
            if (sd > max_sd) max_sd = sd;
        }

        int activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);

        if ((activity < 0) && (errno != EINTR)) {
            printf("select error\n");
        }

        if (FD_ISSET(server_fd, &readfds)) {
            int new_socket;
            struct sockaddr_in client_addr;
            socklen_t addrlen = sizeof(client_addr);

            if ((new_socket = accept(server_fd, (struct sockaddr *)&client_addr, &addrlen)) >= 0) {
                
                // For a robust server, SSL_accept should be non-blocking with select() tracking SSL_ERROR_WANT_READ.
                // For simplicity in this implementation, we will perform a blocking accept.
                int flags = fcntl(new_socket, F_GETFL, 0);
                fcntl(new_socket, F_SETFL, flags & ~O_NONBLOCK);

                SSL *ssl = SSL_new(ctx);
                SSL_set_fd(ssl, new_socket);

                if (SSL_accept(ssl) <= 0) {
                    ERR_print_errors_fp(stderr);
                    SSL_free(ssl);
                    close(new_socket);
                } else {
                    fcntl(new_socket, F_SETFL, flags | O_NONBLOCK); // Set back to non-blocking
                    for (int i = 0; i < MAX_CLIENTS; i++) {
                        if (clients[i].fd == -1) {
                            clients[i].fd = new_socket;
                            clients[i].ssl = ssl;
                            clients[i].state = STATE_HTTP;
                            clients[i].buffer_len = 0;
                            clients[i].is_device = 0;
                            printf("New SSL connection on fd %d (slot %d)\n", new_socket, i);
                            break;
                        }
                    }
                }
            }
        }

        for (int i = 0; i < MAX_CLIENTS; i++) {
            int sd = clients[i].fd;
            if (sd != -1 && FD_ISSET(sd, &readfds)) {
                
                int valread = SSL_read(clients[i].ssl, clients[i].buffer + clients[i].buffer_len, 
                                   BUFFER_SIZE - clients[i].buffer_len);

                if (valread <= 0) {
                    int err = SSL_get_error(clients[i].ssl, valread);
                    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                        disconnect_client(i);
                    }
                } else {
                    clients[i].buffer_len += valread;

                    if (clients[i].state == STATE_HTTP) {
                        handle_http_request(i);
                    } else if (clients[i].state == STATE_AUTH_PENDING || clients[i].state == STATE_WEBSOCKET) {
                        handle_ws_request(i);
                    }
                }
            }
        }
    }

    SSL_CTX_free(ctx);
    db_close();
    return 0;
}
