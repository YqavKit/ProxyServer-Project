#ifndef COMMON_H
#define COMMON_H
#include <stdint.h>
#include "./include/err.h"
#include "./include/ssl.h"

#define ID_STATIC_USERNAME 101
#define ID_EDIT_USERNAME   102
#define ID_STATIC_PASSWORD 103
#define ID_EDIT_PASSWORD   104
#define ID_BUTTON_LOGIN    105
#define ID_BUTTON_SIGNUP   106
#define ID_STATIC_CONFIRM  107
#define ID_EDIT_CONFIRM    108
#define ID_BUTTON_CREATE   109
#define ID_BUTTON_BACK     110

#define EDIT_W 200
#define EDIT_H 25
#define LABEL_W 80
#define LABEL_H 25
#define BTN_W 80
#define BTN_H 30
#define TOP_MARGIN 50
#define ROW_SPACING 10
#define CTRL_SPACING 10
#define BTN_SPACING 20

#define USERNAME_MAX_LEN 31 // leave room for a null terminator (\0)
#define PASSWORD_MAX_LEN 31
#define BUF_SIZE 4096
#define MAX_BIG_SIZE BUF_SIZE * 512 //maximum physicly possible packet size is about 2 MB
#define MAX_CLIENTS 64

#pragma pack(push,1)
typedef struct HeaderStructure {
    unsigned short msgSize;
    uint8_t client_id; //client id last 4 places are for - Disconnect/Connect/Login/signup in order
    uint8_t dest; 
    char big_MSG; // bsig MSG cases 0(single packet - no big MSG) 1(start of big MSG) 2 (ongoing big MSG) 3(end of big MSG)
    char protocol; //0 (tcp) 1(udp) - I planned to have udp support but destiny made me not to for now
} HeaderStructure;
#pragma pack(pop)

int start_webview_window();
int run_login_and_then_webview(HINSTANCE hInstance); 
int start_proxy_threads();
int client_login(const char *username, const char *passsword);
int client_signup(const char *username, const char *password, const char *confirm_passsword);
int db_init();
int db_register_user(const char *username, const char *password_hash);
int db_login_user(const char *username, const char *password_hash);
int db_close(void);

#endif