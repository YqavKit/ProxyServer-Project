#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <WinSock2.h>
#include <windows.h>
#include <WS2tcpip.h>
#include "./common.h"
#include "./include/err.h"
#include "./include/ssl.h"
#include <io.h>
#include <time.h>


typedef struct Connection
{
    SOCKET socket; //חיבור עם המטרה
    char address[16]; // כתובת המטרה           

    char *big_MSG_buf; //מאגר מידע שבו מאחסנים את המידע במקרה של הודעה גדולה
    unsigned int recived_len; //אורך ההודעה הגדולה שהתקבלה עד עתה
    unsigned int expected_len; //אורך ההודעה הגדולה שמצופה לשלוח

} Connection;

typedef struct Client
{
    Connection connections[256]; //מערך חיבורים עם הכתובות החיצוניות
    SSL *ssl; //מצביע SSL (הצפנה)
    unsigned int last_activity; //ניסיון חיבור אחרון של הלקוח
    SOCKET socket; //חיבור עם הלקוח
    unsigned long ip; // כתובת הלקוח
} Client;

typedef struct handle_client_args
{
    SOCKET socket;
    uint8_t client_id;
} handle_client_args;

typedef struct tunnel_thread_args
{
    uint8_t client_id;
    uint8_t dest;

} tunnel_thread_args;

// מבנה ה-Rate Limiting שלך
typedef struct RateLimiting {
    unsigned long ip; //הלקוח שמנסה להתחבר IP
    uint8_t connection_attempts; //מספר בקשות התחברות
    uint8_t authentication_attempts; //מספר בקשות התחברות שאושרו לבדיקה ונכשלו
    unsigned long long last_reset_time; //זמן איתחול מחדש אחרון
} RateLimiting;

// -------------------- GLOBALS --------------------

static SOCKET listener_socket = INVALID_SOCKET;
Client global_clients[MAX_CLIENTS] = {0};
static SSL_CTX *tls_context = NULL;
static CRITICAL_SECTION *client_ssl_locks = NULL;
static char *client_ssl_lock_initialized = NULL;

// משתני Rate Limiting
#define MAX_TRACKED_IPS 500
#define RATE_LIMIT_WINDOW_MS 30000 // 30 שניות
#define MAX_ATTEMPTS 5

RateLimiting ip_registry[MAX_TRACKED_IPS] = {0};
int ip_registry_count = 0;
CRITICAL_SECTION rate_limit_lock;

// -------------------- RATE LIMITING FUNCTIONS --------------------

// מחפש רשומה שפג תוקפה כדי לנצל אותה מחדש (מניעת Exhaustion DoS)
// פונקציה זו נקראת אך ורק מתוך האזור הקריטי
static int find_expired_registry_index(ULONGLONG now) {
    for (int i = 0; i < ip_registry_count; i++) {
        if (now - ip_registry[i].last_reset_time > RATE_LIMIT_WINDOW_MS) {
            return i; // נמצאה רשומה ישנה שניתן לדרוס
        }
    }
    return -1; // המערך מלא וכל הרשומות בתוכו עדיין בחלון זמן פעיל
}

// בודק ומעדכן הגבלת קצב (Rate Limiting) עבור חיבורי TCP חדשים לפי כתובת IP
int check_connection_rate_limit(unsigned long ip) {
    ULONGLONG now = GetTickCount64();
    int allowed = 1;

    // כניסה לאזור קריטי למניעת Race Conditions על מערך הרישום הגלובלי
    EnterCriticalSection(&rate_limit_lock);
    int found = 0;

    // סריקת הרשם (Registry) לחפש אם כתובת ה-IP כבר קיימת ומנוטרת
    for (int i = 0; i < ip_registry_count; i++) {
        if (ip_registry[i].ip == ip) {
            found = 1;

            // בדיקה אם חלון הזמן הנוכחי פג - אם כן, מאפסים מונים ומתחילים חלון חדש
            if (now - ip_registry[i].last_reset_time > RATE_LIMIT_WINDOW_MS) {
                ip_registry[i].connection_attempts = 1;
                ip_registry[i].authentication_attempts = 0;
                ip_registry[i].last_reset_time = now;
            } else {
                // חלון הזמן עדיין פעיל - מקדמים את מונה הניסיונות
                // מוגן מפני Integer Overflow: לא מקדמים מעבר ל-MAX_ATTEMPTS + 1
                if (ip_registry[i].connection_attempts <= MAX_ATTEMPTS) {
                    ip_registry[i].connection_attempts++;
                }

                // אם חרגנו מהרף המקסימלי המותר, החיבור הנוכחי נחסם
                if (ip_registry[i].connection_attempts > MAX_ATTEMPTS) {
                    allowed = 0;
                }
            }
            break;
        }
    }

    // טיפול ב-IP חדש שלא נמצא ברשם
    if (!found) {
        if (ip_registry_count < MAX_TRACKED_IPS) { 
            // יש מקום פנוי במערך - מקצים אינדקס חדש בסוף
            ip_registry[ip_registry_count].ip = ip;
            ip_registry[ip_registry_count].connection_attempts = 1;
            ip_registry[ip_registry_count].authentication_attempts = 0;
            ip_registry[ip_registry_count].last_reset_time = now;
            ip_registry_count++;
        } else {
            // המערך מלא - ננסה למצוא רשומה ישנה שפג תוקפה כדי לפנות אותה (Eviction)
            int expired_index = find_expired_registry_index(now);
            if (expired_index != -1) {
                ip_registry[expired_index].ip = ip;
                ip_registry[expired_index].connection_attempts = 1;
                ip_registry[expired_index].authentication_attempts = 0;
                ip_registry[expired_index].last_reset_time = now;
            } else {
                // Fail-Secure: המערך מלא לחלוטין ואין אף רשומה שפג תוקפה.
                // חוסמים את ה-IP החדש כדי למנוע מהשרת קריסה או עקיפה של ה-Rate Limiter.
                allowed = 0;
            }
        }
    }

    // יציאה מהאזור הקריטי ושחרור הנעילה עבור תהליכונים אחרים
    LeaveCriticalSection(&rate_limit_lock);
    return allowed;
}

// בודק ומקדם הגבלת קצב עבור ניסיונות אימות (Authentication) של לקוחות קיימים
int check_auth_rate_limit(unsigned long ip) {
    ULONGLONG now = GetTickCount64();
    int allowed = 1;

    // הגנה על הגישה למערך ה-Registry באמצעות נעילת האזור הקריטי
    EnterCriticalSection(&rate_limit_lock);
    
    int found = 0;
    for (int i = 0; i < ip_registry_count; i++) {
        if (ip_registry[i].ip == ip) {
            found = 1;
            
            // בדיקה אם חלון הזמן הכללי פג - אם כן, מאפסים מונים ומתחילים חלון חדש
            // שים לב: אנו מעדכנים את last_reset_time רק אם החלון באמת פג
            if (now - ip_registry[i].last_reset_time > RATE_LIMIT_WINDOW_MS) {
                ip_registry[i].connection_attempts = 0;
                ip_registry[i].authentication_attempts = 1; // הניסיון הנוכחי
                ip_registry[i].last_reset_time = now;
            } else {
                // חלון הזמן עדיין פעיל - מקדמים את מונה ניסיונות האימות (מניעת גלישה)
                if (ip_registry[i].authentication_attempts <= MAX_ATTEMPTS) {
                    ip_registry[i].authentication_attempts++;
                }

                // בדיקה אם חרגנו מהרף המקסימלי המותר לאימות
                if (ip_registry[i].authentication_attempts > MAX_ATTEMPTS) {
                    allowed = 0;
                }
            }
            break;
        }
    }

    // אם ה-IP לא נמצא ב-Registry (למשל, אם הוא הצליח לעקוף את שלב החיבור 
    // או שהרשומה שלו פונתה לפני שהספיק לשלוח את חבילת ה-Auth), ניצור לו רשומה חדשה במידת האפשר
    if (!found) {
        if (ip_registry_count < MAX_TRACKED_IPS) {
            ip_registry[ip_registry_count].ip = ip;
            ip_registry[ip_registry_count].connection_attempts = 0;
            ip_registry[ip_registry_count].authentication_attempts = 1;
            ip_registry[ip_registry_count].last_reset_time = now;
            ip_registry_count++;
        } else {
            int expired_index = find_expired_registry_index(now);
            if (expired_index != -1) {
                ip_registry[expired_index].ip = ip;
                ip_registry[expired_index].connection_attempts = 0;
                ip_registry[expired_index].authentication_attempts = 1;
                ip_registry[expired_index].last_reset_time = now;
            } else {
                allowed = 0; // אין מקום ברשם - חסימה לביטחון השרת
            }
        }
    }
    
    // שחרור הנעילה ויציאה
    LeaveCriticalSection(&rate_limit_lock);
    return allowed;
}

void record_auth_failure(unsigned long ip) {
    EnterCriticalSection(&rate_limit_lock);
    for (int i = 0; i < ip_registry_count; i++) {
        if (ip_registry[i].ip == ip) {
            ip_registry[i].authentication_attempts++;
            break;
        }
    }
    LeaveCriticalSection(&rate_limit_lock);
}

void reset_auth_failures(unsigned long ip) {
    EnterCriticalSection(&rate_limit_lock);
    for (int i = 0; i < ip_registry_count; i++) {
        if (ip_registry[i].ip == ip) {
            ip_registry[i].authentication_attempts = 0;
            break;
        }
    }
    LeaveCriticalSection(&rate_limit_lock);
}

// -------------------- HELPER FUNCTIONS --------------------
void hash_password(const char *password, char *hashed_password)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)password, (size_t)strlen(password), hash);

    for (int i = 0; i < SHA256_192_DIGEST_LENGTH; i++) {
        hashed_password[i] = (char)hash[i];
    }
}

static void close_socket(SOCKET *socket_ptr)
{
    if (*socket_ptr != INVALID_SOCKET) {
        closesocket(*socket_ptr);
        *socket_ptr = INVALID_SOCKET;
    }
}

int send_ssl(void *buf, unsigned short size, SSL *ssl, uint8_t dest, uint8_t client_id){
    if(ssl == 0) return -1;
    HeaderStructure header = {.dest = dest, .client_id = client_id ,.msgSize = size, .big_MSG = 0, .protocol = 0};
    int total_sent = 0;
    while(total_sent < sizeof(HeaderStructure)){
        int sent = SSL_write(ssl, ((char*)&header) + total_sent, sizeof(HeaderStructure)-total_sent);
        if(sent<=0) return -1; 
        total_sent+=sent;
    }
    total_sent = 0;
    char *ptr = (char*)buf;
    if(!buf) return 0;
    while(total_sent < size) {
        int sent = SSL_write(ssl, ptr + total_sent, size - total_sent);
        if(sent <= 0) return -1;
        total_sent += sent;
    }
    return 0;
}

static void cleanup_tunnel_slot(uint8_t client_id, uint8_t dest)
{
    if (client_id >= MAX_CLIENTS) return;

    if (client_ssl_lock_initialized[client_id]) {
        EnterCriticalSection(&client_ssl_locks[client_id]);
    }

    if (global_clients[client_id].connections[dest].socket != INVALID_SOCKET) {
        closesocket(global_clients[client_id].connections[dest].socket);
        global_clients[client_id].connections[dest].socket = INVALID_SOCKET;
    }

    if (global_clients[client_id].connections[dest].big_MSG_buf != NULL) {
        free(global_clients[client_id].connections[dest].big_MSG_buf);
        global_clients[client_id].connections[dest].big_MSG_buf = NULL;
    }

    global_clients[client_id].connections[dest].recived_len = 0;
    global_clients[client_id].connections[dest].expected_len = 0;
    memset(global_clients[client_id].connections[dest].address, 0, 16);

    if (client_ssl_lock_initialized[client_id]) {
        LeaveCriticalSection(&client_ssl_locks[client_id]);
    }
}

static void cleanup_client(unsigned short client_id)
{
    printf("Closed the connection with client: %d. cleaning up...\n", client_id);
    if (client_id >= MAX_CLIENTS) return;

    if (client_ssl_lock_initialized[client_id]) {
        EnterCriticalSection(&client_ssl_locks[client_id]);
    }

    if (global_clients[client_id].ssl != NULL) {
        SSL_shutdown(global_clients[client_id].ssl);
        SSL_free(global_clients[client_id].ssl);
        global_clients[client_id].ssl = NULL;
    }

    close_socket(&global_clients[client_id].socket);

    if (client_ssl_lock_initialized[client_id]) {
        LeaveCriticalSection(&client_ssl_locks[client_id]);
    }

    for (unsigned short i = 0; i < 256; i++) {
        cleanup_tunnel_slot(client_id, i);
    }
}


static DWORD WINAPI tunnel_dest_to_client(LPVOID lp)
{
    tunnel_thread_args *thread_args_ptr = (tunnel_thread_args*)lp;
    uint8_t client_id = (*thread_args_ptr).client_id;
    uint8_t dest = (*thread_args_ptr).dest;
    free(thread_args_ptr);
    
    char *recv_buffer = malloc(BUF_SIZE);
    while (1) {
        SOCKET tunnel_socket = global_clients[client_id].connections[dest].socket;
        if (tunnel_socket == INVALID_SOCKET) break;

        int recv_len = recv(tunnel_socket, recv_buffer, BUF_SIZE, 0);
        if (recv_len <= 0){
            int err = WSAGetLastError();
            if (err != 10053 && err != 10054 && err != 0) {
                printf("connection closed/failed %d \n", err);
            }
            break;
        }

        EnterCriticalSection(&client_ssl_locks[client_id]);
        SSL *client_ssl = global_clients[client_id].ssl;
        
        if (client_ssl == NULL) {
            LeaveCriticalSection(&client_ssl_locks[client_id]);
            break; 
        }

        if (send_ssl(recv_buffer, recv_len, client_ssl, dest, client_id) != 0) {
            printf("couldnt sent back to client : %d a packet. TLS connection might be dead.\n", client_id);
            LeaveCriticalSection(&client_ssl_locks[client_id]);
            break;
        }
        else printf("succesfully sent back to client: %d a packet \n", client_id);
        
        LeaveCriticalSection(&client_ssl_locks[client_id]);
    }
    free(recv_buffer);
    cleanup_tunnel_slot(client_id, dest);
    return 0;
}

int send_all(SOCKET socket, char *buf, int size){
    int remaining = size;
    while(remaining > 0){
        int sent = send(socket, buf+(size-remaining), remaining ,0);
        if(sent <= 0) return -1;
        remaining -= sent;
    }
    return 0;
}

static int process_msg(char *buf, int buf_size, int client_owner) 
{
    printf("A packet entered process_msg()... for client id: %d\n", client_owner);
    HeaderStructure *header_ptr = (HeaderStructure*)buf;
    unsigned short msg_len = (*header_ptr).msgSize;
    uint8_t dest = (*header_ptr).dest;
    uint8_t client_id = (*header_ptr).client_id;
    char protocol = (*header_ptr).protocol;
    char big_flag = (*header_ptr).big_MSG;

    if (msg_len != (unsigned short)(buf_size - (int)sizeof(HeaderStructure)) || msg_len > BUF_SIZE) {
        return -1; 
    }

    switch (client_id) {

        case MAX_CLIENTS-1:
        { 
            char payload = buf[sizeof(HeaderStructure)];
            if(payload == 0) cleanup_tunnel_slot(client_owner, dest);
            else{
                printf("Missmatch in a close connection request - expected 0 but got %c. closing the entire client connections...\n",payload);
                return -1;
            }
        } break;

        case MAX_CLIENTS-2: // Create Tunnel
        {
            if (msg_len < 5 || msg_len>258) return 0;

            printf("got a connection packet for dest: %d | connection type recived %d \n", dest, buf[sizeof(HeaderStructure)]);
            int rc = 1;
            SSL *ssl = global_clients[client_owner].ssl; 
            
            cleanup_tunnel_slot(client_owner, dest);

            struct addrinfo *domain_info = NULL;

            if(buf[sizeof(HeaderStructure)] == 0){
                char domain_name[256] = {0};
                memcpy(domain_name, buf + sizeof(HeaderStructure) + 1, msg_len - 3);
                if(domain_name[msg_len - 3 ] != '\0') domain_name[msg_len - 3 ] = '\0';
                if (strstr(domain_name, "microsoft.com") || strstr(domain_name, "windows.com") || strstr(domain_name, "skype.com")    ||strstr(domain_name, "bing.com")) {
        
                printf("[INFO] Dropping background system request: %s\n", domain_name);
                EnterCriticalSection(&client_ssl_locks[client_owner]);
                send_ssl(&rc, sizeof(rc), ssl, dest, MAX_CLIENTS-2);
                LeaveCriticalSection(&client_ssl_locks[client_owner]);
                return 0; 
                }
                struct addrinfo hints = {0};
                hints.ai_family = AF_UNSPEC;
                hints.ai_socktype = SOCK_STREAM; 
                printf("domain_name: %s | length: %d \n", domain_name, (int)strlen(domain_name));
                int result = getaddrinfo(domain_name, NULL, &hints, &domain_info);
                if(result != 0 || !domain_name){
                    printf("could not connect to %s with error: %s\n", domain_name,gai_strerror(result));
                    EnterCriticalSection(&client_ssl_locks[client_owner]);
                    send_ssl(&rc, sizeof(rc), ssl, dest, client_owner);
                    LeaveCriticalSection(&client_ssl_locks[client_owner]);
                    return 0;
                }
                printf("Passed getaddrinfo()! \n");
                if(domain_info->ai_family == AF_INET){//ipv4
                    struct sockaddr_in *ipv4 ={0};
                    ipv4 = (struct sockaddr_in*)domain_info->ai_addr;
                    memcpy(global_clients[client_owner].connections[dest].address, &ipv4->sin_addr, 4);
                }
                else if(domain_info->ai_family == AF_INET6){//ipv6
                    struct sockaddr_in6 *ipv6 = {0};
                    ipv6 = (struct sockaddr_in6*)domain_info->ai_addr;
                    memcpy(global_clients[client_owner].connections[dest].address, &ipv6->sin6_addr, 16);
                }
                else{
                    printf("unknown ip type: %d \n", domain_info->ai_family);
                    EnterCriticalSection(&client_ssl_locks[client_owner]);
                    send_ssl(&rc, sizeof(rc), ssl, dest, client_owner);
                    LeaveCriticalSection(&client_ssl_locks[client_owner]);
                    freeaddrinfo(domain_info);
                    return 0;
                }
            }
            
            char compare_buf[16] = {0};
            if(memcmp(global_clients[client_owner].connections[dest].address, compare_buf, 16) == 0){
                for(int i = 0; i < msg_len - 3; i++) {
                    global_clients[client_owner].connections[dest].address[i] = *(buf + sizeof(HeaderStructure)+1 + i); 
                }
            }

            if(buf[sizeof(HeaderStructure)] == 1 || (domain_info != NULL && domain_info->ai_family == AF_INET6)) { // IPv6
                struct sockaddr_in6 dest_addr = {0};
                global_clients[client_owner].connections[dest].socket = (protocol == 0) ? socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP) : socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
                
                if (global_clients[client_owner].connections[dest].socket == INVALID_SOCKET) {
                    if (domain_info != NULL) freeaddrinfo(domain_info);
                    EnterCriticalSection(&client_ssl_locks[client_owner]);
                    send_ssl(&rc, sizeof(rc), ssl, dest, client_owner);
                    LeaveCriticalSection(&client_ssl_locks[client_owner]);
                    cleanup_tunnel_slot(client_owner, dest);
                    return 0;
                }

                memcpy(&dest_addr.sin6_addr, global_clients[client_owner].connections[dest].address, 16);
                uint16_t port = 0; 
                memcpy(&port ,buf + sizeof(HeaderStructure) + msg_len - 2, 2);
                dest_addr.sin6_port = port;
                dest_addr.sin6_family = AF_INET6;

                char ip_str[INET6_ADDRSTRLEN]; 
                inet_ntop(AF_INET6, global_clients[client_owner].connections[dest].address, ip_str, sizeof(ip_str));

                printf("Trying to connect to IPv6: [%s]:%d\n", ip_str, ntohs(dest_addr.sin6_port));

                if (connect(global_clients[client_owner].connections[dest].socket, (SOCKADDR*)&dest_addr, sizeof(dest_addr)) == SOCKET_ERROR) {
                    printf("couldnt connect to the destination of client_id: %d and dest: %d with error: %d\n", client_owner, dest, WSAGetLastError());
                    EnterCriticalSection(&client_ssl_locks[client_owner]);
                    send_ssl(&rc, sizeof(rc), ssl, dest, client_owner);
                    LeaveCriticalSection(&client_ssl_locks[client_owner]);
                    cleanup_tunnel_slot(client_owner, dest);
                    if (domain_info != NULL) freeaddrinfo(domain_info);
                    return 0;
                }
            } 
            else if(buf[sizeof(HeaderStructure)] == 2 || (domain_info != NULL && domain_info->ai_family == AF_INET)){ // IPv4
                struct sockaddr_in dest_addr = {0};
                global_clients[client_owner].connections[dest].socket = (protocol == 0) ? socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) : socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                
                if (global_clients[client_owner].connections[dest].socket == INVALID_SOCKET) {
                    if (domain_info != NULL) freeaddrinfo(domain_info);
                    EnterCriticalSection(&client_ssl_locks[client_owner]);
                    send_ssl(&rc, sizeof(rc), ssl, dest, client_owner);
                    LeaveCriticalSection(&client_ssl_locks[client_owner]);
                    cleanup_tunnel_slot(client_owner, dest);
                    return 0;
                }

                memcpy(&dest_addr.sin_addr, global_clients[client_owner].connections[dest].address, 4);
                uint16_t port = 0; 
                memcpy(&port ,buf + sizeof(HeaderStructure) + msg_len - 2, 2);
                dest_addr.sin_port = port;
                dest_addr.sin_family = AF_INET;

                char ip_str[INET_ADDRSTRLEN]; 
                inet_ntop(AF_INET, global_clients[client_owner].connections[dest].address, ip_str, sizeof(ip_str));

                printf("Trying to connect to IPv4: [%s]:%d\n", ip_str, ntohs(dest_addr.sin_port));

                if (connect(global_clients[client_owner].connections[dest].socket, (SOCKADDR*)&dest_addr, sizeof(dest_addr)) == SOCKET_ERROR) {
                    printf("couldnt connect to the destination of client_id: %d and dest: %d with error: %d \n", client_owner, dest, WSAGetLastError());
                    EnterCriticalSection(&client_ssl_locks[client_owner]);
                    send_ssl(&rc, sizeof(rc), ssl, dest, client_owner);
                    LeaveCriticalSection(&client_ssl_locks[client_owner]);
                    cleanup_tunnel_slot(client_owner, dest);
                    if (domain_info != NULL) freeaddrinfo(domain_info);
                    return 0;
                }
            }
            else{
                printf("Error with connection type: got %c instead of 0/1/2 \n", buf[sizeof(HeaderStructure)]);
                EnterCriticalSection(&client_ssl_locks[client_owner]);
                send_ssl(&rc, sizeof(rc), ssl, dest, MAX_CLIENTS-2);
                LeaveCriticalSection(&client_ssl_locks[client_owner]);
                if (domain_info != NULL) freeaddrinfo(domain_info);
                return 0; 
            }
            
            if (domain_info != NULL) {
                freeaddrinfo(domain_info);
            }
            
            EnterCriticalSection(&client_ssl_locks[client_owner]);
            rc = 0; 
            printf("succesfull connection established for client: %d dest: %d - sending back rc of 0 \n",client_owner, dest);
            if (send_ssl(&rc, sizeof(rc), ssl, dest, MAX_CLIENTS-2) != 0) {
                LeaveCriticalSection(&client_ssl_locks[client_owner]);
                cleanup_tunnel_slot(client_owner, dest);
                return 0;
            }
            LeaveCriticalSection(&client_ssl_locks[client_owner]);

            tunnel_thread_args *thread_args_ptr = (tunnel_thread_args*)malloc(sizeof(tunnel_thread_args));
            if (thread_args_ptr == NULL) {
                cleanup_tunnel_slot(client_owner, dest);
                return 0;
            }
            (*thread_args_ptr).dest = dest;
            (*thread_args_ptr).client_id = client_owner;

            HANDLE tunnel_thread_handle = CreateThread(NULL, 0, tunnel_dest_to_client, (LPVOID)thread_args_ptr, 0, NULL);
            if (tunnel_thread_handle != NULL) {
                CloseHandle(tunnel_thread_handle);
            }
        } break;
        
        case MAX_CLIENTS-3: // Login
        {
            if (msg_len != 64) return -1;
            
            SSL *ssl = global_clients[client_owner].ssl;

            // --- RATE LIMITING CHECK ---
            if (!check_auth_rate_limit(global_clients[client_owner].ip)) {
                int rc = -2; // חסימת Timeout
                printf("[SECURITY] Blocked login attempt from client %d (Rate Limited)\n", client_owner);
                EnterCriticalSection(&client_ssl_locks[client_owner]);
                send_ssl(&rc, sizeof(rc), ssl, 0, MAX_CLIENTS-3);
                LeaveCriticalSection(&client_ssl_locks[client_owner]);
                return 0; 
            }

            char username[32] = {0};
            char password[32] = {0};
            char hashed_password[32] = {0};

            memcpy(username, buf + sizeof(HeaderStructure), 32);
            memcpy(password, buf + sizeof(HeaderStructure) + 32, 32);

            hash_password(password, hashed_password);
            int rc = db_login_user(username, hashed_password);
            
            if (rc != 0) {
                record_auth_failure(global_clients[client_owner].ip);
                rc = -1;
            } else {
                reset_auth_failures(global_clients[client_owner].ip);
                printf("succefully connected %s to the server\n" ,username);
            }
            
            EnterCriticalSection(&client_ssl_locks[client_owner]);
            int write_ret = send_ssl(&rc, sizeof(rc), ssl, dest ,client_owner);
            LeaveCriticalSection(&client_ssl_locks[client_owner]);
            
            if (write_ret < 0) return -1;
        } break;

        case MAX_CLIENTS-4: // Signup
        {
            if (msg_len != 96) return -1;

            SSL *ssl = global_clients[client_owner].ssl;

            // --- RATE LIMITING CHECK ---
            if (!check_auth_rate_limit(global_clients[client_owner].ip)) {
                int rc = -2; // חסימת Timeout
                printf("[SECURITY] Blocked signup attempt from client %d (Rate Limited)\n", client_owner);
                EnterCriticalSection(&client_ssl_locks[client_owner]);
                send_ssl(&rc, sizeof(rc), ssl, 0, MAX_CLIENTS-4);
                LeaveCriticalSection(&client_ssl_locks[client_owner]);
                return 0; 
            }

            char username[32] = {0};
            char password[32] = {0};
            char confirm[32] = {0};
            char hashed_password[32] = {0};

            memcpy(username, buf + sizeof(HeaderStructure), 32);
            memcpy(password, buf + sizeof(HeaderStructure) + 32, 32);
            memcpy(confirm, buf + sizeof(HeaderStructure) + 64, 32);

            if (strlen(username) == 0 || memcmp(password, confirm, 32) != 0) {
                 record_auth_failure(global_clients[client_owner].ip); // נרשם ככישלון לאותה מטרה
                 int rc = -1;
                 EnterCriticalSection(&client_ssl_locks[client_owner]);
                 send_ssl(&rc, sizeof(rc), ssl, 0, MAX_CLIENTS-4);
                 LeaveCriticalSection(&client_ssl_locks[client_owner]);
                 return 0; 
            }
            hash_password(password, hashed_password);
            int rc = db_register_user(username, hashed_password);
            
            if (rc != 0) {
                record_auth_failure(global_clients[client_owner].ip);
                rc = -1;
            } else {
                reset_auth_failures(global_clients[client_owner].ip);
                printf("Succesfully registerd %s in the database!\n", username);
            }

            printf("sending client rc for signup: %d \n",rc);
            
            EnterCriticalSection(&client_ssl_locks[client_owner]);
            int write_ret = send_ssl(&rc, sizeof(rc), ssl, dest, client_owner);
            LeaveCriticalSection(&client_ssl_locks[client_owner]);
            
            if(write_ret < 0) return -1;
        } break;

        default: // Data Packet: Client -> Destination
        {
            if (global_clients[client_owner].connections[dest].socket == INVALID_SOCKET) return 0; //בדיקת סף
            
            if (big_flag == 1) { //תחילת הודעה גדולה
                //אתחול גודל מצופה של פקטה ובדיקת סף(גודל פקטה מקסימלי לא יעלה על הגודל המקסימלי שהוקצה)
                if (msg_len < 4) return 0; 
                unsigned int expected_len = *((unsigned int*)(buf + sizeof(HeaderStructure)));
                if (expected_len == 0 || expected_len > MAX_BIG_SIZE) return 0; 
                
                if (global_clients[client_owner].connections[dest].big_MSG_buf != NULL) free(global_clients[client_owner].
                connections[dest].big_MSG_buf);
                //אתחול המקום לקליטת מידע לפי הגודל שהתקבל
                global_clients[client_owner].connections[dest].big_MSG_buf = (char*)malloc(expected_len);
                if (global_clients[client_owner].connections[dest].big_MSG_buf == NULL) return 0;
                //קליטת המידע לאחר 4 הבייטים הראשונים לתוך המאגר
                memcpy(global_clients[client_owner].connections[dest].big_MSG_buf,buf + sizeof(HeaderStructure) + 4, msg_len - 4);
                global_clients[client_owner].connections[dest].expected_len = expected_len;
                global_clients[client_owner].connections[dest].recived_len = msg_len - 4;
                return 0;
            }

            if (big_flag == 2) { // המשך הודעה גדולה
                if (global_clients[client_owner].connections[dest].big_MSG_buf == NULL) return 0;
                //בדיקת גודל המידע שהתקבל - מונע bufferoverflow ובכך חריגות זיכרון
                if (global_clients[client_owner].connections[dest].expected_len < global_clients[client_owner].connections[dest].
                    recived_len + msg_len) {
                    cleanup_tunnel_slot(client_owner, dest);
                    return 0;
                }
                //קליטת מידע
                memcpy(global_clients[client_owner].connections[dest].big_MSG_buf + global_clients[client_owner].connections[dest].recived_len,buf + 
                sizeof(HeaderStructure),msg_len);

                global_clients[client_owner].connections[dest].recived_len += msg_len;
                return 0;
            }

            if (big_flag == 3) { // סיום הודעה גדולה
                if (global_clients[client_owner].connections[dest].big_MSG_buf == NULL) return 0;
                //בדיקת גודל המידע שהתקבל - מונע bufferoverflow ובכך חריגות זיכרון
                if (global_clients[client_owner].connections[dest].expected_len < global_clients[client_owner].connections[dest].recived_len + msg_len) {
                    cleanup_tunnel_slot(client_owner, dest);
                    return 0;
                }
                //העתקת סיום המידע
                memcpy(global_clients[client_owner].connections[dest].big_MSG_buf +global_clients[client_owner].connections[dest].recived_len,buf + 
                sizeof(HeaderStructure), msg_len);

                global_clients[client_owner].connections[dest].recived_len += msg_len;
                //בדיקות סף לפני שליחה - אורך מתאים
                if (global_clients[client_owner].connections[dest].recived_len != global_clients[client_owner].connections[dest].expected_len){
                    cleanup_tunnel_slot(client_owner, dest);
                    return 0;
                }
                //שליחת הפקטה הגדולה שנאספה כמקשה אחת
                if (send_all(global_clients[client_owner].connections[dest].socket, global_clients[client_owner].connections[dest].big_MSG_buf, 
                global_clients[client_owner].connections[dest].expected_len) == -1) {
                    cleanup_tunnel_slot(client_owner, dest);
                    return 0;
                }
                //החזרת הפרמטרים למצבם המקורי - ניקיון
                free(global_clients[client_owner].connections[dest].big_MSG_buf); 
                global_clients[client_owner].connections[dest].big_MSG_buf = NULL;
                return 0;
            }

            // Single Packet
            else{
                char *payload = buf + sizeof(HeaderStructure); //חילוץ המידע מהפקטה
                if (send_all(global_clients[client_owner].connections[dest].socket, payload, msg_len) == -1) { //שליחת הפקטה הבודדת
                    cleanup_tunnel_slot(client_owner, dest); //ניקוי המנהרה עבור שגיאה בשליחה
                    return 0;
                }
            } break;
        } break;
    }
    return 0;
}

static char *receive_packet_tls(SSL *ssl, int *out_packet_len)
{
    if (ssl == NULL || out_packet_len == NULL) return NULL;

    *out_packet_len = 0;

    HeaderStructure header;
    int header_bytes_read = 0;

    while (header_bytes_read < (int)sizeof(HeaderStructure)) {
        int tls_read_result = SSL_read(ssl, ((char*)&header) + header_bytes_read, (int)sizeof(HeaderStructure) - header_bytes_read);
        if (tls_read_result <= 0) return NULL;
        header_bytes_read += tls_read_result;
    }

    if (header.msgSize == 0 || header.msgSize > BUF_SIZE) return NULL;

    int total_len = (int)sizeof(HeaderStructure) + (int)header.msgSize;
    char *packet = (char*)malloc(total_len);
    if (packet == NULL) return NULL;

    memcpy(packet, &header, sizeof(HeaderStructure));

    int payload_len = (int)header.msgSize;
    int payload_bytes_read = 0;
    char *payload = packet + sizeof(HeaderStructure);

    while (payload_bytes_read < payload_len) {
        int tls_read_result = SSL_read(ssl, payload + payload_bytes_read, payload_len - payload_bytes_read);
        if (tls_read_result <= 0) {
            free(packet);
            return NULL;
        }
        payload_bytes_read += tls_read_result;
    }

    *out_packet_len = total_len;
    return packet;
}

static DWORD WINAPI handle_client(LPVOID lp)
{
    handle_client_args *args_ptr = (handle_client_args*)lp;
    SOCKET client_socket = (*args_ptr).socket;
    uint8_t client_id = (*args_ptr).client_id;
    free(args_ptr);

    SSL *client_ssl = SSL_new(tls_context);
    if (client_ssl == NULL) {
        closesocket(client_socket);
        return 1;
    }

    SSL_set_fd(client_ssl, (SOCKET)client_socket);

    if (SSL_accept(client_ssl) <= 0) {
        SSL_free(client_ssl);
        closesocket(client_socket);
        return 1;
    }

    global_clients[client_id].ssl = client_ssl;

    while (1) {
        int packet_len = 0;
        char *packet = receive_packet_tls(client_ssl, &packet_len);
        if (packet == NULL) break; 

        if (process_msg(packet, packet_len,client_id) == -1) {
            free(packet);
            break;
        }
        free(packet);
    }

    cleanup_client(client_id);
    return 0;
}

static BOOL WINAPI consoleHandler(DWORD signal)
{
    if (signal == CTRL_C_EVENT)
    {
        printf("\nShutdown signal received. Cleaning up...\n");

        for (unsigned short i = 0; i <MAX_CLIENTS-4; i++) {
            cleanup_client(i);
        }

        close_socket(&listener_socket);
        db_close();
        DeleteCriticalSection(&rate_limit_lock); 
        WSACleanup();
        exit(0);
    }
    return TRUE;
}

void log_connection(struct sockaddr_in* addr) {
    char* ip = inet_ntoa(addr->sin_addr);
    int port = ntohs(addr->sin_port);
    printf("[+] Connection: %s:%d\n", ip, port);
}

int main()
{
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup failed\n");
        return -1;
    }

    SetConsoleCtrlHandler(consoleHandler, TRUE);

    // אתחול המנעול של ה-Rate Limit
    InitializeCriticalSection(&rate_limit_lock);

    client_ssl_locks = (CRITICAL_SECTION*)calloc(MAX_CLIENTS, sizeof(CRITICAL_SECTION));
    client_ssl_lock_initialized = (char*)calloc(MAX_CLIENTS, sizeof(char));
    
    if (client_ssl_locks == NULL || client_ssl_lock_initialized == NULL) {
        printf("Failed to allocate SSL locks\n");
        return -1;
    }

    for (int i = 0; i < MAX_CLIENTS; i++) {
        global_clients[i].socket = INVALID_SOCKET; 
        global_clients[i].ssl = NULL;
        global_clients[i].last_activity = 0;
        global_clients[i].ip = 0;
        
        for(int j = 0; j < 256; j++) {
            global_clients[i].connections[j].big_MSG_buf = NULL;
            global_clients[i].connections[j].socket = INVALID_SOCKET; 
            global_clients[i].connections[j].recived_len = 0;
            global_clients[i].connections[j].expected_len = 0;
        }
        
        InitializeCriticalSection(&client_ssl_locks[i]);
        client_ssl_lock_initialized[i] = 1;
    }

    listener_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener_socket == INVALID_SOCKET) {
        printf("Failed to create listener socket.\n");
        return -1;
    }

    SOCKADDR_IN bind_addr = {0};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(8080);
    bind_addr.sin_addr.S_un.S_addr = INADDR_ANY;

    if (bind(listener_socket, (SOCKADDR*)&bind_addr, sizeof(bind_addr)) == SOCKET_ERROR) {
        printf("Failed to bind listener.\n");
        return -1;
    }

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    tls_context = SSL_CTX_new(TLS_server_method());
    if (tls_context == NULL) {
        printf("Failed to initialize TLS context.\n");
        return -1;
    }
    
    if (SSL_CTX_use_certificate_file(tls_context, "./server.crt", SSL_FILETYPE_PEM) <= 0) {
        printf("Error loading server.crt\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if (SSL_CTX_use_PrivateKey_file(tls_context, "./server.key", SSL_FILETYPE_PEM) <= 0) {
        printf("Error loading server.key\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if (!SSL_CTX_check_private_key(tls_context)) {
        printf("Private key does not match certificate\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if (db_init() != 0) {
        printf("Database failed to initialize.\n");
        return -1;
    }

    listen(listener_socket, 10);
    printf("Server listening on port 8080...\n");

    struct sockaddr_in addr;
    int addr_len = sizeof(addr);

    while (1) {
        SOCKET client_socket = accept(listener_socket, (struct sockaddr*)&addr, &addr_len);
        if (client_socket == INVALID_SOCKET) {
            printf("Failed to accept client.\n");
            continue;
        }

        // --- RATE LIMITING CHECK FOR CONNECTIONS ---
        if (!check_connection_rate_limit(addr.sin_addr.S_un.S_addr)) {
            printf("[SECURITY] Dropped connection from %s - Rate Limited\n", inet_ntoa(addr.sin_addr));
            closesocket(client_socket);
            continue;
        }

        int optval = 1;
        setsockopt(client_socket, SOL_SOCKET, SO_KEEPALIVE, (char*)&optval, sizeof(optval));
        log_connection(&addr);

        int client_id = -1;
        
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (global_clients[i].socket == INVALID_SOCKET && global_clients[i].ssl == NULL) {
                client_id = i;
                break;
            }
        }

        if (client_id == -1) {
            printf("Server full. Rejecting client.\n");
            closesocket(client_socket);
            continue;
        }

        global_clients[client_id].socket = client_socket;
        global_clients[client_id].ip = addr.sin_addr.S_un.S_addr; 
        handle_client_args *args_ptr = (handle_client_args*)malloc(sizeof(handle_client_args));
        if (args_ptr == NULL) {
            closesocket(client_socket);
            global_clients[client_id].socket = INVALID_SOCKET;
            continue;
        }

        args_ptr->socket = client_socket;
        args_ptr->client_id = client_id; 

        HANDLE client_thread_handle = CreateThread(NULL, 0, handle_client, (LPVOID)args_ptr, 0, NULL);
        if (client_thread_handle == NULL) {
            printf("Failed to create client thread.\n");
            free(args_ptr);
        } else {
            CloseHandle(client_thread_handle);
        }
    }
    return 0;
}