#include "plugin.h"
#include "call_scanner.h"
#include "memsearch.h"
#include "structview.h"

int pluginHandle;
HWND hwndDlg;
int hMenu;
int hMenuDump;
HINSTANCE hInst;

// ============================================================
// Global Hotkeys (F7/F8/F9)
// ============================================================

#define HOTKEY_ID_F7 1
#define HOTKEY_ID_F8 2
#define HOTKEY_ID_F9 3

static bool g_globalHotkeysEnabled = false;
static DWORD g_hotkeyThreadId = 0;
static HANDLE g_hotkeyThread = NULL;

static DWORD WINAPI HotkeyThreadProc(LPVOID)
{
    bool f7 = RegisterHotKey(NULL, HOTKEY_ID_F7, 0, VK_F7) != 0;
    bool f8 = RegisterHotKey(NULL, HOTKEY_ID_F8, 0, VK_F8) != 0;
    bool f9 = RegisterHotKey(NULL, HOTKEY_ID_F9, 0, VK_F9) != 0;

    if(!f7 || !f8 || !f9) {
        char buf[128];
        sprintf_s(buf, "[MyPlugin] \xc8\xab\xbe\xd6\xbf\xec\xbd\xdd\xbc\xfc\xd7\xa2\xb2\xe1: F7=%s F8=%s F9=%s",
            f7 ? "OK" : "FAIL", f8 ? "OK" : "FAIL", f9 ? "OK" : "FAIL");
        _plugin_logputs(buf);
    }

    MSG msg;
    while(GetMessage(&msg, NULL, 0, 0)) {
        if(msg.message == WM_HOTKEY) {
            if(!DbgIsDebugging()) continue;
            switch(msg.wParam) {
            case HOTKEY_ID_F7: DbgCmdExec("StepInto"); break;
            case HOTKEY_ID_F8: DbgCmdExec("StepOver"); break;
            case HOTKEY_ID_F9: DbgCmdExec("run"); break;
            }
        }
    }

    UnregisterHotKey(NULL, HOTKEY_ID_F7);
    UnregisterHotKey(NULL, HOTKEY_ID_F8);
    UnregisterHotKey(NULL, HOTKEY_ID_F9);
    return 0;
}

static void EnableGlobalHotkeys()
{
    if(g_globalHotkeysEnabled) return;
    g_hotkeyThread = CreateThread(NULL, 0, HotkeyThreadProc, NULL, 0, &g_hotkeyThreadId);
    if(g_hotkeyThread) {
        g_globalHotkeysEnabled = true;
        _plugin_logputs("[MyPlugin] Global hotkeys enabled (F7=StepInto, F8=StepOver, F9=Run)");
    }
}

static void DisableGlobalHotkeys()
{
    if(!g_globalHotkeysEnabled) return;
    PostThreadMessage(g_hotkeyThreadId, WM_QUIT, 0, 0);
    if(WaitForSingleObject(g_hotkeyThread, 3000) == WAIT_TIMEOUT)
        TerminateThread(g_hotkeyThread, 0);
    CloseHandle(g_hotkeyThread);
    g_hotkeyThread = NULL;
    g_hotkeyThreadId = 0;
    g_globalHotkeysEnabled = false;
    _plugin_logputs("[MyPlugin] Global hotkeys disabled");
}

static void MenuCallback(CBTYPE cbType, void* callbackInfo)
{
    PLUG_CB_MENUENTRY* info = (PLUG_CB_MENUENTRY*)callbackInfo;
    switch(info->hEntry)
    {
    case MENU_SHOW_DIALOG:
        ShowCallScannerWindow();
        break;
    case MENU_MEMORY_SEARCH:
        ShowMemSearchWindow();
        break;
    case MENU_DUMP_SEARCH_ADDR:
    {
        SELECTIONDATA sel = {};
        if(GuiSelectionGet(GUI_DUMP, &sel))
            MemSearch_SearchAddress(sel.start);
        break;
    }
    case MENU_GLOBAL_HOTKEYS:
        if(g_globalHotkeysEnabled)
            DisableGlobalHotkeys();
        else
            EnableGlobalHotkeys();
        _plugin_menuentrysetchecked(pluginHandle, MENU_GLOBAL_HOTKEYS, g_globalHotkeysEnabled);
        break;
    case MENU_STRUCT_VIEWER:
    {
        SELECTIONDATA sel = {};
        if(GuiSelectionGet(GUI_DUMP, &sel))
            ShowStructViewWindow(sel.start);
        break;
    }
    case MENU_ABOUT:
        MessageBoxA(hwndDlg,
            "MyPlugin v1.0\n\n"
            "CALL Scanner - Scan CALL instructions and count API calls.\n"
            "Memory Search - Cheat Engine style memory scan with before/after filter.",
            "About MyPlugin",
            MB_OK | MB_ICONINFORMATION);
        break;
    }
}

extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* initStruct)
{
    initStruct->pluginVersion = PLUGIN_VERSION;
    initStruct->sdkVersion = PLUG_SDKVERSION;
    strcpy_s(initStruct->pluginName, PLUGIN_NAME);
    pluginHandle = initStruct->pluginHandle;
    return true;
}

extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT* setupStruct)
{
    hwndDlg = setupStruct->hwndDlg;
    hMenu = setupStruct->hMenu;
    hMenuDump = setupStruct->hMenuDump;

    _plugin_menuaddentry(hMenu, MENU_SHOW_DIALOG, "CALL\xe6\x89\xab\xe6\x8f\x8f(&W)");
    _plugin_menuaddentry(hMenu, MENU_MEMORY_SEARCH, "\xe5\x86\x85\xe5\xad\x98\xe6\x90\x9c\xe7\xb4\xa2(&M)");
    _plugin_menuaddentry(hMenu, MENU_GLOBAL_HOTKEYS, "\xe5\x85\xa8\xe5\xb1\x80\xe5\xbf\xab\xe6\x8d\xb7\xe9\x94\xae F7/F8/F9(&H)");
    _plugin_menuaddseparator(hMenu);
    _plugin_menuaddentry(hMenu, MENU_ABOUT, "\xe5\x85\xb3\xe4\xba\x8e(&A)");

    _plugin_menuaddentry(hMenuDump, MENU_DUMP_SEARCH_ADDR, "\xe5\x9c\xa8\xe5\x86\x85\xe5\xad\x98\xe4\xb8\xad\xe6\x90\x9c\xe7\xb4\xa2\xe5\xbd\x93\xe5\x89\x8d\xe5\x9c\xb0\xe5\x9d\x80(&S)");
    _plugin_menuaddentry(hMenuDump, MENU_STRUCT_VIEWER, "\xe7\xbb\x93\xe6\x9e\x84\xe4\xbd\x93\xe6\x9f\xa5\xe7\x9c\x8b\xe5\x99\xa8(&T)");

    _plugin_registercallback(pluginHandle, CB_MENUENTRY, MenuCallback);
    CallScanner_RegisterCallbacks(pluginHandle);
    MemSearch_RegisterCallbacks(pluginHandle);

    _plugin_logputs("[MyPlugin] Plugin loaded - CALL Scanner ready.");
}

extern "C" __declspec(dllexport) void plugstop()
{
    DisableGlobalHotkeys();

    _plugin_unregistercallback(pluginHandle, CB_MENUENTRY);
    _plugin_unregistercallback(pluginHandle, CB_BREAKPOINT);

    CallScanner_Cleanup();
    MemSearch_Cleanup();
    StructView_Cleanup();

    _plugin_logputs("[MyPlugin] Plugin unloaded.");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    if(reason == DLL_PROCESS_ATTACH)
    {
        hInst = hModule;
        INITCOMMONCONTROLSEX icex = { sizeof(INITCOMMONCONTROLSEX), ICC_LISTVIEW_CLASSES | ICC_PROGRESS_CLASS };
        InitCommonControlsEx(&icex);
    }
    return TRUE;
}
