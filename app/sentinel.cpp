// Sentinel - app nativo (Win32 + WebView2).
// Sobe o backend local (node server.js), espera a porta, mostra a UI numa janela propria
// e encerra o backend ao fechar. Navegacao e restrita ao 127.0.0.1 (nada de virar navegador).
// winsock2/ws2tcpip ANTES de windows.h (senao o windows.h puxa o winsock v1 e conflita).
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windowsx.h>
#include <shellapi.h>
#include <shlobj.h>
#include <wrl.h>
#include <string>
#include "WebView2.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "advapi32.lib")

using namespace Microsoft::WRL;

static const wchar_t* kHost = L"127.0.0.1";
static const int      kPort = 7777;
static const wchar_t* kUrl  = L"http://127.0.0.1:7777/";

static ComPtr<ICoreWebView2Controller> g_controller;
static ComPtr<ICoreWebView2>           g_webview;
static HANDLE g_nodeProcess = nullptr;
static HWND   g_hwnd = nullptr;

// ---------- barra de titulo propria (sem a barra padrao do Windows) ----------
// Reserva uma tira no topo da PROPRIA janela (o WebView2 comeca abaixo dela) e desenhamos ali
// o titulo e os 3 botoes com GDI simples. O resto da janela continua com borda redimensionavel,
// encaixe nas bordas (snap), Aero Shake, Alt+F4 e menu do sistema - tudo comportamento padrao do
// Windows, preservado porque mantemos WS_THICKFRAME/WS_SYSMENU e devolvemos HTCAPTION na faixa.
static const int TITLEBAR_H = 36;
static const int BTN_W = 46;
static int g_hoverBtn = -1;    // -1 nenhum, 0 minimizar, 1 maximizar, 2 fechar
static bool g_tracking = false;

static RECT BtnRect(HWND h, int index) {
    RECT cr; GetClientRect(h, &cr);
    int right = cr.right - index * BTN_W;
    RECT r{ right - BTN_W, 0, right, TITLEBAR_H };
    return r;
}
static int HitButton(HWND h, int x, int y) {
    if (y < 0 || y >= TITLEBAR_H) return -1;
    for (int i = 0; i < 3; i++) { RECT r = BtnRect(h, i); if (x >= r.left && x < r.right) return i; }
    return -1;
}

static void PaintTitlebar(HWND h) {
    PAINTSTRUCT ps; HDC dc = BeginPaint(h, &ps);
    RECT cr; GetClientRect(h, &cr);
    RECT bar{ 0, 0, cr.right, TITLEBAR_H };
    HBRUSH bg = CreateSolidBrush(RGB(0, 0, 0));
    FillRect(dc, &bar, bg);
    DeleteObject(bg);

    SetBkMode(dc, TRANSPARENT);
    HFONT font = CreateFontW(13, 0, 0, 0, FW_MEDIUM, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
    HFONT old = (HFONT)SelectObject(dc, font);
    SetTextColor(dc, RGB(230, 230, 230));
    RECT label{ 14, 0, cr.right - 3 * BTN_W, TITLEBAR_H };
    DrawTextW(dc, L"Sentinel", -1, &label, DT_SINGLELINE | DT_VCENTER | DT_LEFT);

    HFONT glyphFont = CreateFontW(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
    SelectObject(dc, glyphFont);
    bool zoomed = IsZoomed(h);
    const wchar_t* glyphs[3] = { L"─", zoomed ? L"▣" : L"□", L"✕" }; // minimizar, maximizar/restaurar, fechar
    for (int i = 0; i < 3; i++) {
        RECT r = BtnRect(h, i);
        if (g_hoverBtn == i) {
            HBRUSH hb = CreateSolidBrush(i == 2 ? RGB(60, 10, 10) : RGB(28, 28, 28));
            FillRect(dc, &r, hb); DeleteObject(hb);
        }
        SetTextColor(dc, g_hoverBtn == i && i == 2 ? RGB(255, 140, 140) : RGB(220, 220, 220));
        DrawTextW(dc, glyphs[i], -1, &r, DT_SINGLELINE | DT_VCENTER | DT_CENTER);
    }
    SelectObject(dc, old);
    DeleteObject(font); DeleteObject(glyphFont);
    EndPaint(h, &ps);
}

// ---- util: diretorio do executavel ----
static std::wstring ExeDir() {
    wchar_t buf[MAX_PATH]; GetModuleFileNameW(nullptr, buf, MAX_PATH);
    std::wstring p(buf); size_t s = p.find_last_of(L"\\/"); return s == std::wstring::npos ? L"." : p.substr(0, s);
}

// ---- sobe o backend node ----
static bool StartBackend(const std::wstring& dir) {
    std::wstring cmd = L"node.exe server.js";
    STARTUPINFOW si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::wstring mutableCmd = cmd;  // CreateProcessW pode modificar o buffer
    BOOL ok = CreateProcessW(
        nullptr, &mutableCmd[0], nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW, nullptr, dir.c_str(), &si, &pi);
    if (!ok) return false;
    CloseHandle(pi.hThread);
    g_nodeProcess = pi.hProcess;
    return true;
}

// ---- espera a porta aceitar conexao (backend pronto) ----
static bool WaitForPort(int seconds) {
    WSADATA w; WSAStartup(MAKEWORD(2, 2), &w);
    for (int i = 0; i < seconds * 10; ++i) {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = htons((u_short)kPort);
        InetPtonW(AF_INET, kHost, &a.sin_addr);
        bool up = connect(s, (sockaddr*)&a, sizeof(a)) == 0;
        closesocket(s);
        if (up) { WSACleanup(); return true; }
        Sleep(100);
    }
    WSACleanup(); return false;
}

static void KillBackend() {
    if (g_nodeProcess) {
        DWORD pid = GetProcessId(g_nodeProcess);
        wchar_t cmd[128]; wsprintfW(cmd, L"taskkill /PID %lu /T /F", pid);
        STARTUPINFOW si{}; si.cb = sizeof(si); PROCESS_INFORMATION pi{};
        if (CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, 4000); CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        }
        TerminateProcess(g_nodeProcess, 0);
        CloseHandle(g_nodeProcess); g_nodeProcess = nullptr;
    }
}

// ---- restringe navegacao ao host local; o resto abre no navegador padrao ----
static bool IsLocal(LPCWSTR uri) {
    std::wstring u = uri ? uri : L"";
    return u.rfind(L"http://127.0.0.1:7777", 0) == 0 ||
           u.rfind(L"http://localhost:7777", 0) == 0 ||
           u.rfind(L"about:", 0) == 0 || u.empty();
}

static void ResizeWebView(HWND h) {
    if (!g_controller) return;
    RECT r; GetClientRect(h, &r);
    r.top = TITLEBAR_H; // o WebView2 comeca ABAIXO da faixa de titulo propria
    g_controller->put_Bounds(r);
}

LRESULT CALLBACK WndProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_NCCALCSIZE:
        // wParam TRUE: devolver 0 faz a area "nao-cliente" sumir - a janela toda vira area cliente
        // (sem isso o Windows ainda tentaria desenhar uma borda de titulo padrao em cima da nossa).
        if (wp) return 0;
        break;
    case WM_GETMINMAXINFO: {
        // Sem isso, uma janela WS_POPUP maximizada cobre a barra de tarefas (bug classico do Win32).
        MINMAXINFO* mmi = reinterpret_cast<MINMAXINFO*>(lp);
        HMONITOR mon = MonitorFromWindow(h, MONITOR_DEFAULTTONEAREST);
        MONITORINFO mi{ sizeof(mi) };
        if (GetMonitorInfoW(mon, &mi)) {
            mmi->ptMaxPosition.x = mi.rcWork.left - mi.rcMonitor.left;
            mmi->ptMaxPosition.y = mi.rcWork.top - mi.rcMonitor.top;
            mmi->ptMaxSize.x = mi.rcWork.right - mi.rcWork.left;
            mmi->ptMaxSize.y = mi.rcWork.bottom - mi.rcWork.top;
            mmi->ptMinTrackSize.x = 480; mmi->ptMinTrackSize.y = 360;
        }
        return 0;
    }
    case WM_NCHITTEST: {
        POINT pt{ GET_X_LPARAM(lp), GET_Y_LPARAM(lp) };
        ScreenToClient(h, &pt);
        RECT cr; GetClientRect(h, &cr);
        // bordas de redimensionar primeiro (faixa de 6px em cada lado, igual ao padrao do Windows)
        const int edge = 6;
        bool left = pt.x < edge, right = pt.x > cr.right - edge;
        bool top = pt.y < edge, bottom = pt.y > cr.bottom - edge;
        if (top && left) return HTTOPLEFT; if (top && right) return HTTOPRIGHT;
        if (bottom && left) return HTBOTTOMLEFT; if (bottom && right) return HTBOTTOMRIGHT;
        if (left) return HTLEFT; if (right) return HTRIGHT;
        if (top) return HTTOP; if (bottom) return HTBOTTOM;
        if (pt.y < TITLEBAR_H) return HitButton(h, pt.x, pt.y) >= 0 ? HTCLIENT : HTCAPTION;
        return HTCLIENT;
    }
    case WM_NCMOUSEMOVE:
    case WM_MOUSEMOVE: {
        POINT pt{ GET_X_LPARAM(lp), GET_Y_LPARAM(lp) };
        if (msg == WM_NCMOUSEMOVE) ScreenToClient(h, &pt);
        int b = HitButton(h, pt.x, pt.y);
        if (b != g_hoverBtn) { g_hoverBtn = b; InvalidateRect(h, nullptr, FALSE); }
        if (!g_tracking) { TRACKMOUSEEVENT tme{ sizeof(tme), TME_LEAVE, h, 0 }; TrackMouseEvent(&tme); g_tracking = true; }
        break;
    }
    case WM_MOUSELEAVE:
        g_tracking = false;
        if (g_hoverBtn != -1) { g_hoverBtn = -1; InvalidateRect(h, nullptr, FALSE); }
        break;
    case WM_LBUTTONUP: {
        POINT pt{ GET_X_LPARAM(lp), GET_Y_LPARAM(lp) };
        int b = HitButton(h, pt.x, pt.y);
        if (b == 0) ShowWindow(h, SW_MINIMIZE);
        else if (b == 1) ShowWindow(h, IsZoomed(h) ? SW_RESTORE : SW_MAXIMIZE);
        else if (b == 2) PostMessageW(h, WM_CLOSE, 0, 0);
        return 0;
    }
    case WM_PAINT:
        PaintTitlebar(h);
        return 0;
    case WM_SIZE:
        ResizeWebView(h);
        InvalidateRect(h, nullptr, FALSE);
        return 0;
    case WM_NCACTIVATE:
        return DefWindowProcW(h, msg, wp, -1); // -1: nao deixa o Windows tentar redesenhar non-client
    case WM_CLOSE:
        DestroyWindow(h); return 0;
    case WM_DESTROY:
        KillBackend(); PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}

static void CreateWebView(HWND hwnd) {
    std::wstring udf;
    wchar_t* local = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &local))) {
        udf = std::wstring(local) + L"\\Sentinel\\WebView2";
        CoTaskMemFree(local);
    }

    CreateCoreWebView2EnvironmentWithOptions(nullptr, udf.empty() ? nullptr : udf.c_str(), nullptr,
        Callback<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler>(
            [hwnd](HRESULT, ICoreWebView2Environment* env) -> HRESULT {
                env->CreateCoreWebView2Controller(hwnd,
                    Callback<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>(
                        [hwnd](HRESULT, ICoreWebView2Controller* controller) -> HRESULT {
                            if (!controller) return S_OK;
                            g_controller = controller;
                            g_controller->get_CoreWebView2(&g_webview);

                            ICoreWebView2Settings* settings = nullptr;
                            if (SUCCEEDED(g_webview->get_Settings(&settings)) && settings) {
                                settings->put_AreDefaultContextMenusEnabled(TRUE);
                                settings->put_IsStatusBarEnabled(FALSE);
                                settings->put_AreDevToolsEnabled(TRUE); // util para o dono depurar
                                settings->Release();
                            }

                            // cor de fundo preta enquanto carrega (combina com o tema)
                            ICoreWebView2Controller2* c2 = nullptr;
                            if (SUCCEEDED(g_controller->QueryInterface(IID_PPV_ARGS(&c2))) && c2) {
                                COREWEBVIEW2_COLOR black{255, 0, 0, 0}; c2->put_DefaultBackgroundColor(black); c2->Release();
                            }

                            // bloqueia navegar para fora do app local
                            EventRegistrationToken tok;
                            g_webview->add_NavigationStarting(
                                Callback<ICoreWebView2NavigationStartingEventHandler>(
                                    [](ICoreWebView2*, ICoreWebView2NavigationStartingEventArgs* args) -> HRESULT {
                                        LPWSTR uri = nullptr; args->get_Uri(&uri);
                                        if (!IsLocal(uri)) {
                                            args->put_Cancel(TRUE);
                                            if (uri) ShellExecuteW(nullptr, L"open", uri, nullptr, nullptr, SW_SHOWNORMAL);
                                        }
                                        if (uri) CoTaskMemFree(uri);
                                        return S_OK;
                                    }).Get(), &tok);

                            ResizeWebView(hwnd);
                            g_webview->Navigate(kUrl);
                            return S_OK;
                        }).Get());
                return S_OK;
            }).Get());
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int nCmdShow) {
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    std::wstring dir = ExeDir();
    if (!StartBackend(dir)) {
        MessageBoxW(nullptr, L"Nao foi possivel iniciar o backend.\n\nVerifique se o Node.js esta instalado e se server.js esta na mesma pasta do Sentinel.exe.",
                    L"Sentinel", MB_ICONERROR);
        return 1;
    }
    if (!WaitForPort(25)) {
        KillBackend();
        MessageBoxW(nullptr, L"O backend nao respondeu a tempo na porta 7777.", L"Sentinel", MB_ICONERROR);
        return 1;
    }

    WNDCLASSW wc{}; wc.lpfnWndProc = WndProc; wc.hInstance = hInst; wc.lpszClassName = L"SentinelWindow";
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW); wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    wc.hIcon = LoadIconW(hInst, MAKEINTRESOURCEW(101));
    wc.style = CS_HREDRAW | CS_VREDRAW;
    RegisterClassW(&wc);

    // WS_OVERLAPPEDWINDOW de verdade (com WS_CAPTION) para o DWM tratar como janela normal: cantos
    // arredondados e sombra no Windows 11, miniatura certa no Alt+Tab, menu de encaixe (snap) ao
    // passar o mouse no botao de maximizar. O WM_NCCALCSIZE abaixo e que faz a barra sumir
    // visualmente, sem abrir mao desses comportamentos - e a tecnica usada pelo Windows Terminal.
    DWORD style = WS_OVERLAPPEDWINDOW;
    g_hwnd = CreateWindowExW(WS_EX_APPWINDOW, L"SentinelWindow", L"Sentinel",
        style, CW_USEDEFAULT, CW_USEDEFAULT, 1280, 820,
        nullptr, nullptr, hInst, nullptr);
    // Forca o Windows a reconsultar o WM_NCCALCSIZE agora que a janela ja existe de verdade;
    // sem isso o primeiro layout ainda reserva a altura da barra de titulo padrao (bug conhecido
    // dessa tecnica, documentado em varias implementacoes de titlebar customizada).
    SetWindowPos(g_hwnd, nullptr, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);
    ShowWindow(g_hwnd, nCmdShow ? nCmdShow : SW_SHOW);
    UpdateWindow(g_hwnd);

    CreateWebView(g_hwnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
    KillBackend();
    CoUninitialize();
    return 0;
}
