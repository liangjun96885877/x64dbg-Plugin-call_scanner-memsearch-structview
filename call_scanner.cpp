#include "plugin.h"
#include "call_scanner.h"

#define IDC_COMBO_MODULES   2001
#define IDC_LISTVIEW        2002
#define IDC_LABEL           2003
#define IDC_EDIT_LIMIT      2004
#define IDC_STATIC_LIMIT   2005

#define IDM_HOOK            3001
#define IDM_UNHOOK          3002
#define IDM_CLEAR_COUNT     3003

struct CallEntry
{
    duint callAddr;
    duint targetAddr;
    std::string targetLabel;
    std::string targetModule;
    std::string instruction;
    int callCount;
    bool hooked;
};

static HWND hPluginWnd = NULL;
static HWND hCombo = NULL;
static HWND hListView = NULL;
static HWND hLabel = NULL;
static HWND hEditLimit = NULL;
static HMENU hContextMenu = NULL;

static std::vector<ModuleItem> g_modules;
static std::vector<CallEntry> g_calls;
static std::map<duint, int> g_callCountMap;
static std::set<duint> g_hookedAddrs;

static int g_sortColumn = 4;
static bool g_sortDesc = false;
static int g_autoUnhookLimit = 100;

#define LVITEM_BUF_SIZE 256
static char g_lvItemBuf[LVITEM_BUF_SIZE];

static void InitListViewColumns(HWND hLv)
{
    LVCOLUMNA col = {};
    col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

    col.iSubItem = 0;
    col.pszText = (LPSTR)"#";
    col.cx = 45;
    SendMessageA(hLv, LVM_INSERTCOLUMNA, 0, (LPARAM)&col);

    col.iSubItem = 1;
    col.pszText = (LPSTR)"\u8c03\u7528\u6b21\u6570";
    col.cx = 65;
    SendMessageA(hLv, LVM_INSERTCOLUMNA, 1, (LPARAM)&col);

    col.iSubItem = 2;
    col.pszText = (LPSTR)"Hook";
    col.cx = 50;
    SendMessageA(hLv, LVM_INSERTCOLUMNA, 2, (LPARAM)&col);

    col.iSubItem = 3;
    col.pszText = (LPSTR)"\u8c03\u7528\u5730\u5740(VA)";
    col.cx = 130;
    SendMessageA(hLv, LVM_INSERTCOLUMNA, 3, (LPARAM)&col);

    col.iSubItem = 4;
    col.pszText = (LPSTR)"\u76ee\u6807(VA)";
    col.cx = 130;
    SendMessageA(hLv, LVM_INSERTCOLUMNA, 4, (LPARAM)&col);

    col.iSubItem = 5;
    col.pszText = (LPSTR)"\u76ee\u6807\u6a21\u5757";
    col.cx = 110;
    SendMessageA(hLv, LVM_INSERTCOLUMNA, 5, (LPARAM)&col);

    col.iSubItem = 6;
    col.pszText = (LPSTR)"API/\u6807\u7b7e";
    col.cx = 250;
    SendMessageA(hLv, LVM_INSERTCOLUMNA, 6, (LPARAM)&col);

    col.iSubItem = 7;
    col.pszText = (LPSTR)"\u6307\u4ee4";
    col.cx = 200;
    SendMessageA(hLv, LVM_INSERTCOLUMNA, 7, (LPARAM)&col);
}

static void RefreshListViewCounts()
{
    if(!hListView || g_calls.empty())
        return;
    ListView_RedrawItems(hListView, 0, (int)g_calls.size() - 1);
}

static void SortCallsByColumn(int col)
{
    for(auto& ce : g_calls)
        ce.callCount = g_callCountMap[ce.targetAddr];
    if(g_sortDesc)
    {
        switch(col)
        {
        case 1: std::sort(g_calls.begin(), g_calls.end(), [](const CallEntry& a, const CallEntry& b) { return a.callCount > b.callCount; }); break;
        case 3: std::sort(g_calls.begin(), g_calls.end(), [](const CallEntry& a, const CallEntry& b) { return a.callAddr > b.callAddr; }); break;
        case 4: std::sort(g_calls.begin(), g_calls.end(), [](const CallEntry& a, const CallEntry& b) { return a.targetAddr > b.targetAddr; }); break;
        case 5: std::sort(g_calls.begin(), g_calls.end(), [](const CallEntry& a, const CallEntry& b) { return a.targetModule > b.targetModule; }); break;
        case 6: std::sort(g_calls.begin(), g_calls.end(), [](const CallEntry& a, const CallEntry& b) { return a.targetLabel > b.targetLabel; }); break;
        case 7: std::sort(g_calls.begin(), g_calls.end(), [](const CallEntry& a, const CallEntry& b) { return a.instruction > b.instruction; }); break;
        default: std::sort(g_calls.begin(), g_calls.end(), [](const CallEntry& a, const CallEntry& b) { return a.targetAddr > b.targetAddr; }); break;
        }
    }
    else
    {
        switch(col)
        {
        case 1: std::sort(g_calls.begin(), g_calls.end(), [](const CallEntry& a, const CallEntry& b) { return a.callCount < b.callCount; }); break;
        case 3: std::sort(g_calls.begin(), g_calls.end(), [](const CallEntry& a, const CallEntry& b) { return a.callAddr < b.callAddr; }); break;
        case 4: std::sort(g_calls.begin(), g_calls.end(), [](const CallEntry& a, const CallEntry& b) { return a.targetAddr < b.targetAddr; }); break;
        case 5: std::sort(g_calls.begin(), g_calls.end(), [](const CallEntry& a, const CallEntry& b) { return a.targetModule < b.targetModule; }); break;
        case 6: std::sort(g_calls.begin(), g_calls.end(), [](const CallEntry& a, const CallEntry& b) { return a.targetLabel < b.targetLabel; }); break;
        case 7: std::sort(g_calls.begin(), g_calls.end(), [](const CallEntry& a, const CallEntry& b) { return a.instruction < b.instruction; }); break;
        default: std::sort(g_calls.begin(), g_calls.end(), [](const CallEntry& a, const CallEntry& b) { return a.targetAddr < b.targetAddr; }); break;
        }
    }
    if(hListView)
        ListView_RedrawItems(hListView, 0, (int)g_calls.size() - 1);
}

static void ScanCallInstructions(int moduleIndex)
{
    SendMessageA(hListView, LVM_SETITEMCOUNT, 0, 0);
    g_calls.clear();

    if(moduleIndex < 0 || moduleIndex >= (int)g_modules.size())
        return;

    if(!DbgIsDebugging())
    {
        SetWindowTextA(hLabel, "\u672a\u8c03\u8bd5\u65e0\u6cd5\u626b\u63cf");
        return;
    }

    duint modBase = g_modules[moduleIndex].base;

    BridgeList<Script::Module::ModuleSectionInfo> sections;
    if(!Script::Module::SectionListFromAddr(modBase, &sections))
    {
        SetWindowTextA(hLabel, "\u83b7\u53d6\u6bb5\u5217\u8868\u5931\u8d25");
        return;
    }

    SetWindowTextA(hLabel, "\u6b63\u5728\u626b\u63cf\u8bf7\u7b49\u5f85...");
    GuiProcessEvents();

    std::set<duint> seenTargets;

    int secCount = sections.Count();
    for(int s = 0; s < secCount; s++)
    {
        auto& sec = sections[s];

        MEMORY_BASIC_INFORMATION mbi = {};
        if(!VirtualQueryEx(DbgGetProcessHandle(), (LPCVOID)sec.addr, &mbi, sizeof(mbi)))
            continue;

        bool isExecutable = (mbi.Protect & PAGE_EXECUTE) ||
                            (mbi.Protect & PAGE_EXECUTE_READ) ||
                            (mbi.Protect & PAGE_EXECUTE_READWRITE) ||
                            (mbi.Protect & PAGE_EXECUTE_WRITECOPY);

        if(!isExecutable)
        {
            bool nameHint = (_stricmp(sec.name, ".text") == 0) ||
                            (_stricmp(sec.name, "CODE") == 0) ||
                            (_stricmp(sec.name, ".code") == 0);
            if(!nameHint)
                continue;
        }

        duint addr = sec.addr;
        duint end = sec.addr + sec.size;

        while(addr < end)
        {
            BASIC_INSTRUCTION_INFO info = {};
            DbgDisasmFastAt(addr, &info);

            if(info.size == 0)
            {
                addr++;
                continue;
            }

            if(info.call && info.branch && info.addr != 0)
            {
                duint target = info.addr;

                if(seenTargets.find(target) == seenTargets.end())
                {
                    seenTargets.insert(target);

                    CallEntry ce;
                    ce.callAddr = addr;
                    ce.targetAddr = target;
                    ce.instruction = info.instruction;
                    ce.callCount = g_callCountMap[target];
                    ce.hooked = g_hookedAddrs.count(target) != 0;

                    char labelBuf[MAX_LABEL_SIZE] = {};
                    if(DbgGetLabelAt(target, SEG_DEFAULT, labelBuf) && labelBuf[0] != '\0')
                        ce.targetLabel = labelBuf;
                    else
                        ce.targetLabel = "(unknown)";

                    char modName[MAX_MODULE_SIZE] = {};
                    if(DbgGetModuleAt(target, modName))
                        ce.targetModule = modName;

                    g_calls.push_back(std::move(ce));
                }
            }

            addr += info.size;
        }
    }

    SortCallsByColumn(g_sortColumn);

    int count = (int)g_calls.size();
    char label[512];
    sprintf_s(label, "\u6a21\u5757:%s  |  \u57fa\u5740:%016llX  |  CALL\u76ee\u6807\u6570:%d",
        g_modules[moduleIndex].name,
        (unsigned long long)modBase,
        count);
    SetWindowTextA(hLabel, label);

    if(count == 0)
        return;

    SendMessageA(hListView, LVM_SETITEMCOUNT, count, LVSICF_NOINVALIDATEALL);
    InvalidateRect(hListView, NULL, TRUE);
}

static void PopulateModules()
{
    g_modules.clear();
    g_calls.clear();
    SendMessageA(hCombo, CB_RESETCONTENT, 0, 0);
    SendMessageA(hListView, LVM_SETITEMCOUNT, 0, 0);

    if(!DbgIsDebugging())
    {
        SetWindowTextA(hLabel, "\u672a\u8c03\u8bd5\u8bf7\u5148\u6253\u5f00\u76ee\u6807");
        return;
    }

    BridgeList<Script::Module::ModuleInfo> modules;
    if(!Script::Module::GetList(&modules))
        return;

    int count = modules.Count();
    for(int i = 0; i < count; i++)
    {
        ModuleItem mi = {};
        strcpy_s(mi.name, modules[i].name);
        mi.base = modules[i].base;
        mi.size = modules[i].size;
        mi.entry = modules[i].entry;
        g_modules.push_back(mi);

        char display[512];
        sprintf_s(display, "%s  [%016llX, Size: %llX]",
            mi.name, (unsigned long long)mi.base, (unsigned long long)mi.size);
        SendMessageA(hCombo, CB_ADDSTRING, 0, (LPARAM)display);
    }

    if(count > 0)
    {
        SendMessageA(hCombo, CB_SETCURSEL, 0, 0);
        ScanCallInstructions(0);
    }
    else
    {
        SetWindowTextA(hLabel, "\u672a\u627e\u5230\u6a21\u5757");
    }
}

static void DoHookSelected()
{
    int sel = (int)SendMessageA(hListView, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
    while(sel >= 0)
    {
        if(sel < (int)g_calls.size())
        {
            duint addr = g_calls[sel].targetAddr;
            if(g_hookedAddrs.find(addr) == g_hookedAddrs.end())
            {
                if(DbgGetBpxTypeAt(addr) != bp_none)
                    Script::Debug::DeleteBreakpoint(addr);
                if(Script::Debug::SetBreakpoint(addr))
                {
                    g_hookedAddrs.insert(addr);
                    g_calls[sel].hooked = true;
                }
            }
        }
        sel = (int)SendMessageA(hListView, LVM_GETNEXTITEM, sel, LVNI_SELECTED);
    }
    RefreshListViewCounts();
}

static void DoUnhookSelected()
{
    int sel = (int)SendMessageA(hListView, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
    while(sel >= 0)
    {
        if(sel < (int)g_calls.size())
        {
            duint addr = g_calls[sel].targetAddr;
            if(g_hookedAddrs.find(addr) != g_hookedAddrs.end())
            {
                Script::Debug::DeleteBreakpoint(addr);
                g_hookedAddrs.erase(addr);
                g_calls[sel].hooked = false;
            }
        }
        sel = (int)SendMessageA(hListView, LVM_GETNEXTITEM, sel, LVNI_SELECTED);
    }
    RefreshListViewCounts();
}

static void DoClearCountSelected()
{
    int sel = (int)SendMessageA(hListView, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
    while(sel >= 0)
    {
        if(sel < (int)g_calls.size())
            g_callCountMap[g_calls[sel].targetAddr] = 0;
        sel = (int)SendMessageA(hListView, LVM_GETNEXTITEM, sel, LVNI_SELECTED);
    }
    RefreshListViewCounts();
}

static void RefreshListViewCountsGui(void*)
{
    RefreshListViewCounts();
}

static int GetAutoUnhookLimit()
{
    if(hEditLimit)
    {
        char buf[32] = {};
        if(GetWindowTextA(hEditLimit, buf, sizeof(buf)) > 0)
        {
            int v = atoi(buf);
            if(v > 0)
                return v;
        }
    }
    return g_autoUnhookLimit;
}

static void BreakpointCallback(CBTYPE cbType, void* callbackInfo)
{
    PLUG_CB_BREAKPOINT* info = (PLUG_CB_BREAKPOINT*)callbackInfo;
    if(!info || !info->breakpoint)
        return;

    duint addr = info->breakpoint->addr;

    if(g_hookedAddrs.find(addr) == g_hookedAddrs.end())
        return;

    g_callCountMap[addr]++;
    int limit = GetAutoUnhookLimit();
    if(limit > 0 && g_callCountMap[addr] >= limit)
    {
        Script::Debug::DeleteBreakpoint(addr);
        g_hookedAddrs.erase(addr);
    }

    if(hListView && IsWindowVisible(hPluginWnd))
        GuiExecuteOnGuiThreadEx(RefreshListViewCountsGui, NULL);

    DbgCmdExec("run");
}

static LRESULT CALLBACK PluginWndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch(uMsg)
    {
    case WM_CREATE:
    {
        HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

        hLabel = CreateWindowExA(0, "STATIC", "\u9009\u62e9\u6a21\u5757\u626b\u63cfCALL\u6307\u4ee4",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            10, 10, 940, 20, hWnd, (HMENU)IDC_LABEL, hInst, NULL);
        SendMessageA(hLabel, WM_SETFONT, (WPARAM)hFont, TRUE);

        hCombo = CreateWindowExA(0, "COMBOBOX", "",
            WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | CBS_HASSTRINGS | WS_VSCROLL,
            10, 35, 780, 300, hWnd, (HMENU)IDC_COMBO_MODULES, hInst, NULL);
        SendMessageA(hCombo, WM_SETFONT, (WPARAM)hFont, TRUE);

        HWND hStaticLimit = CreateWindowExA(0, "STATIC", "\u8c03\u7528\u6b21\u6570>\u65f6\u89e3\u9664Hook",
            WS_CHILD | WS_VISIBLE | SS_RIGHT,
            800, 38, 110, 18, hWnd, (HMENU)IDC_STATIC_LIMIT, hInst, NULL);
        SendMessageA(hStaticLimit, WM_SETFONT, (WPARAM)hFont, TRUE);

        hEditLimit = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "100",
            WS_CHILD | WS_VISIBLE | ES_NUMBER,
            915, 35, 55, 20, hWnd, (HMENU)IDC_EDIT_LIMIT, hInst, NULL);
        SendMessageA(hEditLimit, WM_SETFONT, (WPARAM)hFont, TRUE);

        hListView = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_OWNERDATA,
            10, 65, 940, 485, hWnd, (HMENU)IDC_LISTVIEW, hInst, NULL);
        SendMessageA(hListView, WM_SETFONT, (WPARAM)hFont, TRUE);

        ListView_SetExtendedListViewStyle(hListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
        InitListViewColumns(hListView);

        hContextMenu = CreatePopupMenu();
        AppendMenuA(hContextMenu, MF_STRING, IDM_HOOK, "\u8bbe\u7f6eHook");
        AppendMenuA(hContextMenu, MF_STRING, IDM_UNHOOK, "\u89e3\u9664Hook");
        AppendMenuA(hContextMenu, MF_STRING, IDM_CLEAR_COUNT, "\u6e05\u96f6\u8c03\u7528\u6b21\u6570");

        PopulateModules();
        return 0;
    }

    case WM_SIZE:
    {
        int w = LOWORD(lParam);
        int h = HIWORD(lParam);
        if(hLabel)
            MoveWindow(hLabel, 10, 10, w - 180, 20, TRUE);
        if(hCombo)
            MoveWindow(hCombo, 10, 35, w - 180, 300, TRUE);
        if(hEditLimit)
            MoveWindow(hEditLimit, w - 65, 35, 55, 20, TRUE);
        HWND hStaticLimit = GetDlgItem(hWnd, IDC_STATIC_LIMIT);
        if(hStaticLimit)
            MoveWindow(hStaticLimit, w - 180, 38, 110, 18, TRUE);
        if(hListView)
            MoveWindow(hListView, 10, 65, w - 20, h - 75, TRUE);
        return 0;
    }

    case WM_NOTIFY:
    {
        NMHDR* nmhdr = (NMHDR*)lParam;
        if(nmhdr->idFrom == IDC_LISTVIEW)
        {
            if(nmhdr->code == LVN_COLUMNCLICK)
            {
                NMLISTVIEW* nmlv = (NMLISTVIEW*)lParam;
                int col = nmlv->iSubItem;
                if(col == g_sortColumn)
                    g_sortDesc = !g_sortDesc;
                else
                {
                    g_sortColumn = col;
                    g_sortDesc = (col == 1);
                }
                SortCallsByColumn(g_sortColumn);
                return 0;
            }
            if(nmhdr->code == LVN_GETDISPINFOA)
            {
                NMLVDISPINFOA* pdi = (NMLVDISPINFOA*)lParam;
                int i = pdi->item.iItem;
                int sub = pdi->item.iSubItem;
                if(i >= 0 && i < (int)g_calls.size() && (pdi->item.mask & LVIF_TEXT))
                {
                    auto& ce = g_calls[i];
                    ce.callCount = g_callCountMap[ce.targetAddr];
                    ce.hooked = g_hookedAddrs.count(ce.targetAddr) != 0;
                    switch(sub)
                    {
                    case 0: sprintf_s(g_lvItemBuf, "%d", i + 1); break;
                    case 1: sprintf_s(g_lvItemBuf, "%d", ce.callCount); break;
                    case 2: strcpy_s(g_lvItemBuf, ce.hooked ? "Yes" : ""); break;
                    case 3: sprintf_s(g_lvItemBuf, "%016llX", (unsigned long long)ce.callAddr); break;
                    case 4: sprintf_s(g_lvItemBuf, "%016llX", (unsigned long long)ce.targetAddr); break;
                    case 5: strncpy_s(g_lvItemBuf, ce.targetModule.c_str(), LVITEM_BUF_SIZE - 1); break;
                    case 6: strncpy_s(g_lvItemBuf, ce.targetLabel.c_str(), LVITEM_BUF_SIZE - 1); break;
                    case 7: strncpy_s(g_lvItemBuf, ce.instruction.c_str(), LVITEM_BUF_SIZE - 1); break;
                    default: g_lvItemBuf[0] = '\0'; break;
                    }
                    pdi->item.pszText = g_lvItemBuf;
                }
                return 0;
            }
            if(nmhdr->code == NM_DBLCLK)
            {
                NMITEMACTIVATE* nmia = (NMITEMACTIVATE*)lParam;
                int idx = nmia->iItem;
                if(idx >= 0 && idx < (int)g_calls.size())
                {
                    duint addr = g_calls[idx].callAddr;
                    if(nmia->iSubItem >= 4)
                        addr = g_calls[idx].targetAddr;
                    GuiDisasmAt(addr, addr);
                    GuiShowCpu();
                }
            }
            else if(nmhdr->code == NM_RCLICK)
            {
                NMITEMACTIVATE* nmia = (NMITEMACTIVATE*)lParam;
                int idx = nmia->iItem;
                if(idx >= 0)
                {
                    int sel = (int)SendMessageA(hListView, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
                    if(sel < 0)
                    {
                        LVITEMA lvi = {};
                        lvi.stateMask = LVIS_SELECTED | LVIS_FOCUSED;
                        lvi.state = LVIS_SELECTED | LVIS_FOCUSED;
                        SendMessageA(hListView, LVM_SETITEMSTATE, idx, (LPARAM)&lvi);
                    }
                }
                SetForegroundWindow(GetAncestor(hWnd, GA_ROOT));
                POINT pt;
                GetCursorPos(&pt);
                int cmd = (int)TrackPopupMenu(hContextMenu, TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RETURNCMD, pt.x, pt.y, 0, hWnd, NULL);
                if(cmd == IDM_HOOK)
                    DoHookSelected();
                else if(cmd == IDM_UNHOOK)
                    DoUnhookSelected();
                else if(cmd == IDM_CLEAR_COUNT)
                    DoClearCountSelected();
                return 0;
            }
        }
        return 0;
    }

    case WM_COMMAND:
        if(LOWORD(wParam) == IDC_COMBO_MODULES && HIWORD(wParam) == CBN_SELCHANGE)
        {
            int sel = (int)SendMessageA(hCombo, CB_GETCURSEL, 0, 0);
            ScanCallInstructions(sel);
        }
        else if(LOWORD(wParam) == IDM_HOOK)
            DoHookSelected();
        else if(LOWORD(wParam) == IDM_UNHOOK)
            DoUnhookSelected();
        else if(LOWORD(wParam) == IDM_CLEAR_COUNT)
            DoClearCountSelected();
        return 0;

    case WM_CLOSE:
        ShowWindow(hWnd, SW_HIDE);
        return 0;

    case WM_DESTROY:
        hPluginWnd = NULL;
        hCombo = NULL;
        hListView = NULL;
        hLabel = NULL;
        hEditLimit = NULL;
        if(hContextMenu)
        {
            DestroyMenu(hContextMenu);
            hContextMenu = NULL;
        }
        g_calls.clear();
        return 0;
    }
    return DefWindowProcA(hWnd, uMsg, wParam, lParam);
}

void ShowCallScannerWindow()
{
    if(hPluginWnd)
    {
        if(!IsWindowVisible(hPluginWnd))
        {
            ShowWindow(hPluginWnd, SW_SHOW);
            PopulateModules();
        }
        SetForegroundWindow(hPluginWnd);
        return;
    }

    WNDCLASSEXA wc = { sizeof(WNDCLASSEXA) };
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = PluginWndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = "MyPluginWindowClass";
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    RegisterClassExA(&wc);

    hPluginWnd = CreateWindowExA(0, "MyPluginWindowClass", "MyPlugin - CALL\u626b\u63cf",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1050, 650,
        hwndDlg, NULL, hInst, NULL);

    ShowWindow(hPluginWnd, SW_SHOW);
    UpdateWindow(hPluginWnd);
}

void CallScanner_RegisterCallbacks(int pluginHandle)
{
    _plugin_registercallback(pluginHandle, CB_BREAKPOINT, BreakpointCallback);
}

void CallScanner_Cleanup()
{
    for(duint addr : g_hookedAddrs)
        Script::Debug::DeleteBreakpoint(addr);
    g_hookedAddrs.clear();
    g_callCountMap.clear();

    if(hPluginWnd)
    {
        DestroyWindow(hPluginWnd);
        hPluginWnd = NULL;
    }
    g_calls.clear();
    g_modules.clear();
}
