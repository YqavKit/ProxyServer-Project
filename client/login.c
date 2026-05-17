#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../common.h"

// from client.c
int client_login(const char *username, const char *hash);
int client_signup(const char *username, const char *hash, const char *confirm);

// from web_ui.cpp
int start_webview_window();

// from client.c


static int login_success = 0;

LRESULT CALLBACK LoginWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {

        case WM_CREATE: {
            RECT rc;
            GetClientRect(hwnd, &rc);
            int winW = rc.right - rc.left;

            int startX = (winW - EDIT_W) / 2 - LABEL_W;
            int startY = TOP_MARGIN;

            CreateWindow("STATIC", "Username:",
                        WS_VISIBLE | WS_CHILD,
                        startX, startY, LABEL_W, LABEL_H,
                        hwnd, (HMENU)ID_STATIC_USERNAME, NULL, NULL);

            CreateWindow("EDIT", "",
                        WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL,
                        startX + LABEL_W + CTRL_SPACING, startY,
                        EDIT_W, EDIT_H, hwnd,
                        (HMENU)ID_EDIT_USERNAME, NULL, NULL);

            int nextY = startY + LABEL_H + EDIT_H + ROW_SPACING;

            CreateWindow("STATIC", "Password:",
                        WS_VISIBLE | WS_CHILD,
                        startX, nextY, LABEL_W, LABEL_H,
                        hwnd, (HMENU)ID_STATIC_PASSWORD, NULL, NULL);

            CreateWindow("EDIT", "",
                        WS_VISIBLE | WS_CHILD | WS_BORDER | ES_PASSWORD | ES_AUTOHSCROLL,
                        startX + LABEL_W + CTRL_SPACING, nextY,
                        EDIT_W, EDIT_H, hwnd,
                        (HMENU)ID_EDIT_PASSWORD, NULL, NULL);

            int btnStartX = startX + LABEL_W + CTRL_SPACING + (EDIT_W - (BTN_W * 2 + BTN_SPACING)) / 2;
            int btnY = nextY + LABEL_H + EDIT_H + ROW_SPACING;

            CreateWindow("BUTTON", "Login",
                        WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                        btnStartX, btnY, BTN_W, BTN_H,
                        hwnd, (HMENU)ID_BUTTON_LOGIN, NULL, NULL);

            CreateWindow("BUTTON", "Signup",
                        WS_VISIBLE | WS_CHILD,
                        btnStartX + BTN_W + BTN_SPACING, btnY, BTN_W, BTN_H,
                        hwnd, (HMENU)ID_BUTTON_SIGNUP, NULL, NULL);
        }break;

        case WM_COMMAND:{
            switch (LOWORD(wParam)) {

                case ID_BUTTON_LOGIN: {
                    char username[USERNAME_MAX_LEN] = {0};
                    char password[PASSWORD_MAX_LEN] = {0};

                    GetWindowText(GetDlgItem(hwnd, ID_EDIT_USERNAME), username, sizeof(username));
                    GetWindowText(GetDlgItem(hwnd, ID_EDIT_PASSWORD), password, sizeof(password));

                    if(strlen(password) == 0 || strlen(username) == 0){
                        MessageBox(hwnd, "Password and username cannot be empty!", "Error", MB_OK | MB_ICONERROR);
                        break;
                    }
                    else if(strlen(password) > 31 || strlen(username) > 31){
                        MessageBox(hwnd, "Username and Password lengths must be up to 31 charecters", "Error", MB_OK | MB_ICONERROR);
                        break;
                    }

                    int rc = client_login(username, password);
                    if (rc == 0) {
                        MessageBox(hwnd,"Logged in succesfully", "LOGIN", MB_OK);
                        login_success = 1;
                        DestroyWindow(hwnd);
                    } 
                    else {
                        MessageBox(hwnd, "Login failed", "Error", MB_OK | MB_ICONERROR);
                    }

                }break;

                case ID_BUTTON_SIGNUP: {
                    // Manual destruction of UI elements as requested
                    DestroyWindow(GetDlgItem(hwnd, ID_BUTTON_LOGIN));
                    DestroyWindow(GetDlgItem(hwnd, ID_BUTTON_SIGNUP));
                    DestroyWindow(GetDlgItem(hwnd, ID_EDIT_PASSWORD));
                    DestroyWindow(GetDlgItem(hwnd, ID_EDIT_USERNAME));
                    DestroyWindow(GetDlgItem(hwnd, ID_STATIC_USERNAME));
                    DestroyWindow(GetDlgItem(hwnd, ID_STATIC_PASSWORD));

                    RECT rc;
                    GetClientRect(hwnd, &rc);
                    int winW = rc.right - rc.left;

                    int startX = (winW - EDIT_W) / 2 - LABEL_W;
                    int startY = TOP_MARGIN;

                    // Re-create Labels and Edits for Signup
                    CreateWindow("STATIC", "Username:", WS_VISIBLE | WS_CHILD,
                                startX, startY, LABEL_W, LABEL_H, hwnd, (HMENU)ID_STATIC_USERNAME, NULL, NULL);

                    CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL,
                                startX + LABEL_W + CTRL_SPACING, startY,
                                EDIT_W, EDIT_H, hwnd, (HMENU)ID_EDIT_USERNAME, NULL, NULL);

                    int nextY = startY + LABEL_H + EDIT_H + ROW_SPACING;

                    CreateWindow("STATIC", "Password:", WS_VISIBLE | WS_CHILD,
                                startX, nextY, LABEL_W, LABEL_H, hwnd, (HMENU)ID_STATIC_PASSWORD, NULL, NULL);

                    CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_PASSWORD | ES_AUTOHSCROLL,
                                startX + LABEL_W + CTRL_SPACING, nextY,
                                EDIT_W, EDIT_H, hwnd, (HMENU)ID_EDIT_PASSWORD, NULL, NULL);

                    nextY += LABEL_H + EDIT_H + ROW_SPACING;

                    CreateWindow("STATIC", "Confirm:",
                                WS_VISIBLE | WS_CHILD,
                                startX, nextY, LABEL_W, LABEL_H,
                                hwnd, (HMENU)ID_STATIC_CONFIRM, NULL, NULL);

                    CreateWindow("EDIT", "",
                                WS_VISIBLE | WS_CHILD | WS_BORDER | ES_PASSWORD | ES_AUTOHSCROLL,
                                startX + LABEL_W + CTRL_SPACING, nextY,
                                EDIT_W, EDIT_H, hwnd,
                                (HMENU)ID_EDIT_CONFIRM, NULL, NULL);

                    nextY += LABEL_H + EDIT_H + ROW_SPACING;
                    int btnStartX = startX + LABEL_W + CTRL_SPACING + (EDIT_W - (BTN_W * 2 + BTN_SPACING)) / 2;

                    CreateWindow("BUTTON", "Create Account",
                                WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                                btnStartX-30 , nextY,
                                BTN_W+30, BTN_H,
                                hwnd, (HMENU)ID_BUTTON_CREATE, NULL, NULL);

                    CreateWindow("BUTTON", "Back",
                                WS_VISIBLE | WS_CHILD,
                                btnStartX + BTN_W + BTN_SPACING, nextY,
                                BTN_W, BTN_H,
                                hwnd, (HMENU)ID_BUTTON_BACK, NULL, NULL);

                }break;

                case ID_BUTTON_CREATE:{
                    char username[USERNAME_MAX_LEN] = {0};
                    char password[PASSWORD_MAX_LEN] = {0};
                    char confirm_password[PASSWORD_MAX_LEN] = {0};

                    GetWindowText(GetDlgItem(hwnd, ID_EDIT_USERNAME), username, sizeof(username));
                    GetWindowText(GetDlgItem(hwnd, ID_EDIT_PASSWORD), password, sizeof(password));
                    GetWindowText(GetDlgItem(hwnd, ID_EDIT_CONFIRM), confirm_password, sizeof(confirm_password));

                    if(strlen(username) == 0 || strlen(password) == 0){
                        MessageBox(hwnd, "Fields cannot be empty!", "Error", MB_OK | MB_ICONERROR);
                        break;
                    }
                    if(strlen(password) < 8){
                        MessageBox(hwnd, "A password must be at least 8 characters long", "Error", MB_OK|MB_ICONERROR);
                        break;
                    }

                    if(strcmp(confirm_password, password) != 0){
                        MessageBox(hwnd, "Passwords do not match", "Error", MB_OK | MB_ICONERROR);
                        break;
                    }

                    if(strlen(username) > 31 || strlen(password) > 31){
                        MessageBox(hwnd, "Username and Password lengths must be up to 31 charecters", "Error", MB_OK | MB_ICONERROR);
                        break;
                    }

                    int rc = client_signup(username, password, confirm_password);
                    if (rc == 0) {
                        int login_rc = client_login(username, password);
                        if (login_rc == 0){MessageBox(hwnd,"Signed up successfully", "SIGNUP", MB_OK); login_success = 1; DestroyWindow(hwnd); break;}
                        MessageBox(hwnd, "Try logging in again", "Server Error", MB_OK | MB_ICONERROR);
                    } 
                    else {
                        MessageBox(hwnd, "Signup failed", "Error", MB_OK | MB_ICONERROR);
                    }

                }break;

                case ID_BUTTON_BACK:{
                    DestroyWindow(GetDlgItem(hwnd, ID_EDIT_CONFIRM));
                    DestroyWindow(GetDlgItem(hwnd, ID_STATIC_CONFIRM));
                    DestroyWindow(GetDlgItem(hwnd, ID_EDIT_PASSWORD));
                    DestroyWindow(GetDlgItem(hwnd, ID_EDIT_USERNAME));
                    DestroyWindow(GetDlgItem(hwnd, ID_STATIC_USERNAME));
                    DestroyWindow(GetDlgItem(hwnd, ID_STATIC_PASSWORD));
                    DestroyWindow(GetDlgItem(hwnd, ID_BUTTON_CREATE));
                    DestroyWindow(GetDlgItem(hwnd, ID_BUTTON_BACK));

                    // Re-trigger the initial UI generation
                    SendMessage(hwnd, WM_CREATE, 0, 0);
                }break;
            }
        }break;

        case WM_DESTROY:{
            PostQuitMessage(0);
            break;
        }

        default:{
            return DefWindowProc(hwnd, msg, wParam, lParam);
        }
    }
    return 0;
}

HWND CreateLoginWindow(HINSTANCE hInstance){
    WNDCLASS wc = {0};
    wc.lpfnWndProc = LoginWndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "LoginWindowClass";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);

    if (!RegisterClass(&wc)) {
        return NULL;
    }

    RECT workArea;
    SystemParametersInfo(SPI_GETWORKAREA, 0, &workArea, 0);

    // Centering the window based on screen size
    int winW = 700;
    int winH = 600;
    int x = (workArea.right - winW) / 2;
    int y = (workArea.bottom - winH) / 2;

    HWND hwnd = CreateWindowEx(
        0,
        "LoginWindowClass",
        "MiniVPN - Authenticate",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        x, y,
        winW, winH,
        NULL, NULL, hInstance, NULL
    );

    if (!hwnd) return NULL;

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    return hwnd;
}

int run_login_and_then_webview(HINSTANCE hInstance)
{
    HWND hwnd = CreateLoginWindow(hInstance);
    if (!hwnd) return -1;

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    if (login_success == 1) {
        if (start_proxy_threads() != 0) {
            MessageBoxA(NULL, "Proxy failed to start", "Error", MB_ICONERROR);
            return -1;
        }
        start_webview_window();
        return 1;
    }
    return 0;
}