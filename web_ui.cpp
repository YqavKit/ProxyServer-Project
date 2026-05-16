#include <windows.h>
#include <stdio.h>
#include "WebView2.h"

static ICoreWebView2Controller* g_controller = nullptr;
static HWND g_main_hwnd = nullptr;

// Called when the WebView2 controller is finished building
class ControllerHandler : public ICoreWebView2CreateCoreWebView2ControllerCompletedHandler {
public:
    STDMETHODIMP QueryInterface(REFIID riid, void** ppv) {
        if (riid == IID_ICoreWebView2CreateCoreWebView2ControllerCompletedHandler || riid == IID_IUnknown) {
            *ppv = this; 
            return S_OK;
        }
        *ppv = nullptr; 
        return E_NOINTERFACE;
    }
    
    STDMETHODIMP_(ULONG) AddRef() { return 1; }
    STDMETHODIMP_(ULONG) Release() { return 1; }

    STDMETHODIMP Invoke(HRESULT result, ICoreWebView2Controller* controller) override {
        if (FAILED(result) || !controller) {
            MessageBoxW(g_main_hwnd, L"Failed to create the WebView controller.", L"Error", MB_ICONERROR);
            return result;
        }
        
        g_controller = controller;
        g_controller->AddRef();

        ICoreWebView2* webview = nullptr;
        g_controller->get_CoreWebView2(&webview);

        // Fit the webview to the current window size
        RECT bounds;
        GetClientRect(g_main_hwnd, &bounds);
        g_controller->put_Bounds(bounds);
        g_controller->put_IsVisible(TRUE);

        webview->Navigate(L"https://google.com");
        return S_OK;
    }
};

// Called when the base WebView2 environment is ready
class EnvironmentHandler : public ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler {
public:
    STDMETHODIMP QueryInterface(REFIID riid, void** ppv) {
        if (riid == IID_ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler || riid == IID_IUnknown) {
            *ppv = this; 
            return S_OK;
        }
        *ppv = nullptr; 
        return E_NOINTERFACE;
    }
    
    STDMETHODIMP_(ULONG) AddRef() { return 1; }
    STDMETHODIMP_(ULONG) Release() { return 1; }

    STDMETHODIMP Invoke(HRESULT result, ICoreWebView2Environment* env) override {
        if (FAILED(result) || !env) {
            wchar_t buf[256];
            swprintf(buf, 256, L"Failed to init WebView environment. HRESULT: 0x%08X", result);
            MessageBoxW(g_main_hwnd, buf, L"Error", MB_ICONERROR);
            return result;
        }
        
        env->CreateCoreWebView2Controller(g_main_hwnd, new ControllerHandler());
        return S_OK;
    }
};

// Standard window procedure
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_SIZE:
            if (g_controller) {
                RECT bounds; 
                GetClientRect(hwnd, &bounds);
                g_controller->put_Bounds(bounds);
            }
            break;

        case WM_DESTROY:
            if (g_controller) {
                g_controller->Close();
                g_controller->Release();
                g_controller = nullptr;
            }
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProcW(hwnd, msg, wp, lp);
    }
    return 0;
}

// Exported for client.c
extern "C" int start_webview_window(HINSTANCE hInstance) {
    
    // We pass our browser arguments globally here.
    // Adding --disable-quic forces the browser to use standard TCP (SOCKS5 friendly).
    SetEnvironmentVariableW(
        L"WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", 
        L"--proxy-server=\"socks5://127.0.0.1:7080\" --disable-gpu --disable-quic"
    );
    
    if (FAILED(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED))) {
        return -1;
    }

    // Window registration
    WNDCLASSW wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.lpszClassName = L"VPN_Browser_Class";
    wc.hInstance = hInstance; 
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    
    if (!RegisterClassW(&wc)) {
        MessageBoxW(NULL, L"Failed to register window class.", L"Error", MB_ICONERROR);
        return -1;
    }

    g_main_hwnd = CreateWindowExW(
        0, L"VPN_Browser_Class", L"Secure VPN Browser", 
        WS_OVERLAPPEDWINDOW | WS_VISIBLE, 
        CW_USEDEFAULT, CW_USEDEFAULT, 1024, 768, 
        NULL, NULL, hInstance, NULL
    );

    if (!g_main_hwnd) {
        MessageBoxW(NULL, L"Failed to create main window.", L"Error", MB_ICONERROR);
        return -1;
    }

    // Start up WebView2, storing user data in a local folder
    HRESULT hr = CreateCoreWebView2EnvironmentWithOptions(
        NULL, L".\\WebView_Data", NULL, new EnvironmentHandler()
    );

    if (FAILED(hr)) {
        wchar_t buf[256];
        swprintf(buf, 256, L"Failed to start WebView. HRESULT: 0x%08X", hr);
        MessageBoxW(g_main_hwnd, buf, L"Fatal Error", MB_ICONERROR);
        return -1;
    }

    // Main UI loop
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    CoUninitialize();
    return (int)msg.wParam;
}