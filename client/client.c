#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <windows.h>
#include <process.h> 
#include "./openssl/ssl.h"
#include "./openssl/err.h"
#include "../common.h"

#pragma comment(lib, "Ws2_32.lib")

static SSL *global_ssl = NULL;
static SSL_CTX *global_ctx = NULL;
static SOCKET server_socket = INVALID_SOCKET;
static HANDLE ssl_mutex = NULL; 
static uint8_t client_id = 0;
static SOCKET connections[256]; 

static HANDLE connect_lock = NULL;  
// FIXED: Changed single global event/rc to an array to prevent multi-threading race conditions
static HANDLE connect_events[256];      
static int connect_rcs[256]; 
static int threads_started = 0;     

int start_proxy_threads();
// -------------------- TLS Helpers --------------------

int init_client_tls(const char *server_ip, int port) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return -1;

    ssl_mutex = CreateMutex(NULL, FALSE, NULL);
    connect_lock = CreateMutex(NULL, FALSE, NULL);

    for (int i = 0; i < 256; i++) {
        connections[i] = INVALID_SOCKET;
        connect_events[i] = CreateEvent(NULL, FALSE, FALSE, NULL);
        connect_rcs[i] = -1;
    }

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    global_ctx = SSL_CTX_new(TLS_client_method());

    server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, server_ip, &addr.sin_addr);

    if (connect(server_socket, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) return -1;
    
    global_ssl = SSL_new(global_ctx);
    SSL_set_fd(global_ssl, (SOCKET)server_socket);
    
    if (SSL_connect(global_ssl) <= 0) return -1;
    
    return 0;
}

int send_all(SOCKET socket, char *buf, int size){
    if (socket == INVALID_SOCKET) return -1;
    int remaining = size;
    while(remaining > 0){
        int sent = send(socket, buf + (size - remaining), remaining, 0);
        if(sent <= 0) return -1;
        remaining -= sent;
    }
    return 0;
}

int send_ssl(void *buf, unsigned short size, SSL *ssl, uint8_t dest, uint8_t cid, char big_MSG){
    if(ssl == NULL) return -1;
    
    HeaderStructure header = {0};
    header.dest = dest;
    header.client_id = cid;
    header.msgSize = size;
    header.big_MSG = big_MSG;
    header.protocol = 0;
    
    WaitForSingleObject(ssl_mutex, INFINITE);
    
    if (global_ssl == NULL) {
        ReleaseMutex(ssl_mutex);
        return -1;
    }

    int total_sent = 0;
    while(total_sent < (int)sizeof(HeaderStructure)){
        int sent = SSL_write(ssl, ((char*)&header) + total_sent, (int)sizeof(HeaderStructure) - total_sent);
        if(sent <= 0){
            ReleaseMutex(ssl_mutex); 
            return -1; 
        }
        total_sent += sent;
    }
    
    if(buf && size > 0) {
        total_sent = 0;
        char *ptr = (char*)buf;
        while(total_sent < (int)size) {
            int sent = SSL_write(ssl, ptr + total_sent, (int)size - total_sent);
            if(sent <= 0){
                ReleaseMutex(ssl_mutex);
                return -1;
            } 
            total_sent += sent;
        }
    }
    
    ReleaseMutex(ssl_mutex);
    return 0;
}

int recv_ssl(void *buf, int size) {
    if (buf == NULL || size <= 0 || global_ssl == NULL) return -1;
    
    int remaining = size;
    unsigned char *ptr = (unsigned char *)buf; 
    
    while (remaining > 0) {
        int bytes_read = SSL_read(global_ssl, ptr + (size - remaining), remaining);
        if (bytes_read <= 0) return -1;
        remaining -= bytes_read;
    }
    return 0;
}

// -------------------- Authentication --------------------

int client_login(const char *username, const char *password) {
    char buffer[64] = {0};
    strncpy(buffer, username, 31); 
    strncpy(buffer + 32, password, 31);

    if(send_ssl(buffer, 64, global_ssl, 0, MAX_CLIENTS-3, 0) != 0) return -1;
    
    HeaderStructure result_header = {0};
    if (recv_ssl(&result_header, sizeof(HeaderStructure)) < 0) return -1;
   
    int result;
    if (recv_ssl(&result, sizeof(int)) != 0) return -1;
    
    if(result == -2){
        MessageBox(NULL, "Rate Limited - timed out for 30 seconds. SLOW DOWN!","Login Error",MB_ICONERROR);
        return result;
    }
    else if(result != 0) return result;

    client_id = result_header.client_id; 
    start_proxy_threads();
    return 0;
}

int client_signup(const char *username, const char *password, const char *confirm) {
    char buffer[96] = {0};
    strncpy(buffer, username, 31);
    strncpy(buffer + 32, password, 31);
    strncpy(buffer + 64, confirm, 31);

    if(send_ssl(buffer, 96, global_ssl, 0, MAX_CLIENTS-4, 0) != 0) return -1;

    HeaderStructure result_header = {0};
    if (recv_ssl(&result_header, sizeof(HeaderStructure)) != 0) return -1;
    
    int result = -1;
    if (recv_ssl(&result, sizeof(int)) != 0) return -1;
   
    if(result == -2){
        MessageBox(NULL,"Rate Limited - timed out for 30 seconds. SLOW DOWN!" ,"Signup Error",  MB_ICONERROR);
        return -1;
    }
    
    else if(result != 0) return -1;
    client_id = result_header.client_id;
    return 0;
}

// -------------------- Proxy & Relay Logic --------------------

typedef struct {
    SOCKET webview_socket;
} ThreadArgs;

// FIXED: Properly lock, prevent double close, and send server disconnect packet
void cleanup_connection(SOCKET webview_socket, char* data_buf, uint8_t* full_request, int dest) {
    if (data_buf) free(data_buf);
    if (full_request) free(full_request);
    
    if (webview_socket != INVALID_SOCKET) {
        int owned = 1;

        if (dest >= 0 && dest < 256) {
            WaitForSingleObject(connect_lock, INFINITE);
            if (connections[dest] == webview_socket) {
                connections[dest] = INVALID_SOCKET;
            } else {
                owned = 0; // The receiver thread already closed it
            }
            ReleaseMutex(connect_lock);
            
            if (owned) {
                // FIXED: Tell the server to close its end of the tunnel!
                char payload = 0; 
                send_ssl(&payload, 1, global_ssl, (uint8_t)dest, MAX_CLIENTS-1, 0);
            }
        }
        
        if (owned) {
            shutdown(webview_socket, SD_BOTH);
            char drain_buf[4096];
            while (recv(webview_socket, drain_buf, sizeof(drain_buf), 0) > 0) {
            }
            closesocket(webview_socket);
        }
    }
}

DWORD WINAPI connection_handler(void* pArguments) {
    ThreadArgs* args = (ThreadArgs*)pArguments;
    SOCKET webview_socket = args->webview_socket;
    free(args); 

    char* data_buf = NULL; 
    uint8_t* full_request = NULL;
    int my_dest = -1;

    // Phase 1: SOCKS5 Handshake
    uint8_t sock5_header[2] = {0};
    if(recv(webview_socket, (char*)sock5_header, 2, 0) <= 0) {
        cleanup_connection(webview_socket, data_buf, full_request, my_dest);
        return 0;
    }
    if(sock5_header[1] != 0x1){
        unsigned char error_resp[10] = {0x05, 0x07, 0x00, 0x01, 0,0,0,0,0,0};
        send_all(webview_socket, (char*)error_resp, 10);
        cleanup_connection(webview_socket, data_buf, full_request, my_dest);
        return 0;
    }

    uint8_t methods[256] = {0};
    if(recv(webview_socket, (char*)methods, sizeof(methods), 0) <= 0) {
        cleanup_connection(webview_socket, data_buf, full_request, my_dest);
        return 0;
    }

    uint8_t response[2] = {0x05, 0x00}; // No Auth
    if(send_all(webview_socket, (char*)response, 2) != 0) {
        cleanup_connection(webview_socket, data_buf, full_request, my_dest);
        return 0;
    }

    unsigned char request_header[4] = {0};
    if(recv(webview_socket, (char*)request_header, 4, 0) <= 0) {
        cleanup_connection(webview_socket, data_buf, full_request, my_dest);
        return 0;
    }
    
    full_request = (uint8_t*)malloc(300); 
    if (!full_request) {
        cleanup_connection(webview_socket, data_buf, full_request, my_dest);
        return 0;
    }

    int bytes_to_send = 0;
    if(request_header[3] == 0x01) { // IPv4
        full_request[0] = 2;
        if (recv(webview_socket, (char*)full_request+1, 6, 0) <= 0) { cleanup_connection(webview_socket, data_buf, full_request, my_dest); return 0; }
        bytes_to_send = 7;
    } 
    else if(request_header[3] == 0x03) { // Domain
        uint8_t len = 0;
        if (recv(webview_socket, (char*)&len, 1, 0) <= 0) { cleanup_connection(webview_socket, data_buf, full_request, my_dest); return 0; }
        full_request[0] = 0;
        if (recv(webview_socket, (char*)full_request + 1, len + 2, 0) <= 0) { cleanup_connection(webview_socket, data_buf, full_request, my_dest); return 0; }
        bytes_to_send = len + 3; 
    } 
    else if(request_header[3] == 0x04){ // IPv6
        full_request[0] = 1;
        if(recv(webview_socket, (char*)full_request+1,18,0)<= 0){cleanup_connection(webview_socket,data_buf, full_request, my_dest); return 0;}
        bytes_to_send = 19;
    }
    else { //unsupported
        cleanup_connection(webview_socket, data_buf, full_request, my_dest);
        return 0;
    }
    
    // --- ESTABLISH TUNNEL ---
    WaitForSingleObject(connect_lock, INFINITE); 
    for(int i = 0; i < 255; i++) {
        if(connections[i] == INVALID_SOCKET) {
            my_dest = i;
            connections[i] = webview_socket; 
            break;
        }
    }

    if (my_dest == -1) { 
        ReleaseMutex(connect_lock);
        cleanup_connection(webview_socket, data_buf, full_request, my_dest);
        return 0;
    }

    ResetEvent(connect_events[my_dest]); 
    if (send_ssl(full_request, (unsigned short)bytes_to_send, global_ssl, (uint8_t)my_dest, MAX_CLIENTS - 2, 0) != 0) {
        connections[my_dest] = INVALID_SOCKET; 
        ReleaseMutex(connect_lock);
        cleanup_connection(webview_socket, data_buf, full_request, -1);
        return 0;
    }
    ReleaseMutex(connect_lock); // Release lock while waiting for server response
    
    free(full_request); full_request = NULL;

    // FIXED: Use specific array event to wait, avoiding race condition with other threads
    DWORD wait_res = WaitForSingleObject(connect_events[my_dest], 10000); 
    
    WaitForSingleObject(connect_lock, INFINITE);
    int local_rc = (wait_res == WAIT_OBJECT_0) ? connect_rcs[my_dest] : -1;
    ReleaseMutex(connect_lock);

    if(local_rc == 0) { // succesfull connection established by the server
        uint8_t connect_ok[10] = {0x05, 0x00, 0x00, 0x01, 0,0,0,0,0,0}; 
        if(send_all(webview_socket, (char*)connect_ok, 10) != 0) {
            cleanup_connection(webview_socket, data_buf, full_request, my_dest);
            return 0;
        } 
    } 
    else { //server couldnt establish a connection with the server
        cleanup_connection(webview_socket, data_buf, full_request, my_dest);
        return 0;
    }
    
    data_buf = (char*)malloc(MAX_BIG_SIZE);
    if (!data_buf) {
        cleanup_connection(webview_socket, data_buf, full_request, my_dest);
        return 0;
    }

   int n;

    while ((n = recv(webview_socket, data_buf, MAX_BIG_SIZE, 0)) > 0) {
        int bytes_sent = 0;
    
        while (bytes_sent < n) {
            int remaining = n - bytes_sent;
            int chunk;
            uint8_t big_flag;
            char chunk_payload[BUF_SIZE];

            if (n <= BUF_SIZE) {
                chunk = n;
                big_flag = 0;
                memcpy(chunk_payload, data_buf, chunk);
            } 
            else{ 
                if (bytes_sent == 0) {
                big_flag = 1;
                chunk = (remaining > (BUF_SIZE - sizeof(int))) ? (BUF_SIZE - sizeof(int)) : remaining;
                memcpy(chunk_payload, &n, sizeof(int));
                memcpy(chunk_payload + sizeof(int), data_buf, chunk);
                chunk += sizeof(int);
            } 
            else {
                chunk = (remaining > BUF_SIZE) ? BUF_SIZE : remaining;
                big_flag = (bytes_sent + chunk < n) ? 2 : 3;
                memcpy(chunk_payload, data_buf + bytes_sent, chunk);
                }
            }

            if (send_ssl(chunk_payload, (unsigned short)chunk, global_ssl, (uint8_t)my_dest, client_id, big_flag) != 0) {
                closesocket(webview_socket);
                return 0;
            }

            if (big_flag == 1) {
                bytes_sent += (chunk - sizeof(int));
            } else {
                bytes_sent += chunk;
            }
        }
    }


    cleanup_connection(webview_socket, data_buf, full_request, my_dest);
    return 0;
}

DWORD WINAPI webview_proxy_thread(LPVOID lp) {
    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(listener == INVALID_SOCKET) return 1;
    
    int opt = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(7080);
    
    if(bind(listener, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) return 1;
    listen(listener, SOMAXCONN);
    
    while(1){
        SOCKET webview_socket = accept(listener, NULL, NULL);
        if(webview_socket != INVALID_SOCKET){
            ThreadArgs *args = (ThreadArgs*)malloc(sizeof(ThreadArgs));
            if(args) {
                args->webview_socket = webview_socket;
                HANDLE h = CreateThread(NULL, 0, connection_handler, args, 0, NULL);
                if(h) CloseHandle(h); else { closesocket(webview_socket); free(args); }
            } else {
                closesocket(webview_socket);
            }
        }
    }
    return 0;
}

DWORD WINAPI server_receiver_thread(LPVOID lp) {
    while (1) {
        HeaderStructure h = {0};
        if (recv_ssl(&h, sizeof(h)) < 0) break;
        
        if (h.dest >= 256) {
            if (h.msgSize > 0) {
                char* trash = malloc(h.msgSize);
                if (trash) { recv_ssl(trash, h.msgSize); free(trash); }
            }
            continue;
        }

        if(h.client_id == MAX_CLIENTS-1) { // Disconnect
            WaitForSingleObject(connect_lock, INFINITE);
            SOCKET s = connections[h.dest];
            connections[h.dest] = INVALID_SOCKET;
            ReleaseMutex(connect_lock);
            
            if (s != INVALID_SOCKET) {
                // DRAINING LOGIC: Prevent RST when server disconnects
                shutdown(s, SD_BOTH);
                char drain_buf[4096];
                while (recv(s, drain_buf, sizeof(drain_buf), 0) > 0) {
                    // Empty the buffer
                }
                closesocket(s);
            }
        }
        else if (h.client_id == MAX_CLIENTS-2) { // Connect Response
            int rc = -1;
            if (recv_ssl(&rc, sizeof(rc)) == 0) {
                WaitForSingleObject(connect_lock, INFINITE);
                connect_rcs[h.dest] = rc;      
                SetEvent(connect_events[h.dest]); // FIXED: Notify specific thread
                ReleaseMutex(connect_lock);
            }
        }
        else { // Data
            char *payload = (char*)malloc(h.msgSize);
            if (payload) {
                if(recv_ssl(payload, h.msgSize) == 0){
                    SOCKET s = connections[h.dest];
                    if (s != INVALID_SOCKET) send_all(s, payload, h.msgSize);
                }
                free(payload); 
            } else {
                // FIXED: Drain the stream to avoid desync if malloc fails!
                char trash_buffer[1024];
                int remaining = h.msgSize;
                while(remaining > 0) {
                    int chunk = (remaining > sizeof(trash_buffer)) ? sizeof(trash_buffer) : remaining;
                    if(recv_ssl(trash_buffer, chunk) < 0) break;
                    remaining -= chunk;
                }
            }
        } 
    }
    return 0;
}

int start_proxy_threads() {
    if (threads_started) return 0; 
    threads_started = 1;

    HANDLE h1 = CreateThread(NULL, 0, server_receiver_thread, NULL, 0, NULL);
    HANDLE h2 = CreateThread(NULL, 0, webview_proxy_thread, NULL, 0, NULL);
    
    if (h1) CloseHandle(h1);
    if (h2) CloseHandle(h2);
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
    if (init_client_tls("10.0.0.8", 8080) != 0) { 
        MessageBoxA(NULL, "Could not connect to Server", "Connection Error", MB_ICONERROR);
        return -1;
    }
    
    extern int run_login_and_then_webview(HINSTANCE hInstance);
    return run_login_and_then_webview(hInstance);
}