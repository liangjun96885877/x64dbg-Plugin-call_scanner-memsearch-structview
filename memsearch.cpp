#include "plugin.h"
#include "memsearch.h"
#include <cmath>
#include <cstring>

// Control IDs
#define IDC_MS_VALUE_TYPE       4001
#define IDC_MS_VALUE_EDIT       4002
#define IDC_MS_FIRST_SCAN       4004
#define IDC_MS_NEW_SCAN         4005
#define IDC_MS_LIST             4007
#define IDC_MS_LABEL            4008
#define IDC_MS_UNDO             4010
#define IDC_MS_HEX              4011
#define IDC_MS_SCAN_TYPE        4012
#define IDC_MS_VALUE2           4013
#define IDC_MS_WRITABLE         4014
#define IDC_MS_ADD_MONITOR      4016
#define IDC_MS_ADD_MANUAL       4017
#define IDC_MS_MONITOR_LIST     4018
#define IDC_MS_MODULE_FILTER    4019
#define IDC_MS_STATIC_SCANCTRL  4020
#define IDC_MS_STATIC_DATATYPE  4021
#define IDC_MS_STATIC_VALUE     4022
#define IDC_MS_STATIC_SCANTYPE  4023
#define IDC_MS_STATIC_VALUE2    4024
#define IDC_MS_STATIC_MODULE    4025
#define IDC_MS_STATIC_MONITOR   4027
#define IDC_MS_AUTO_REFRESH     4028
#define IDC_MS_PROGRESS         4029
#define IDC_MS_FAST_SCAN        4030
#define IDC_MS_ALIGN_EDIT       4031
#define IDC_MS_STATIC_ALIGN     4032
#define IDC_MS_STATIC_ADDRLIST  4033
#define IDC_MS_NOT              4040
#define IDC_MS_ROUND_DEFAULT    4041
#define IDC_MS_ROUND_ROUNDED    4042
#define IDC_MS_ROUND_TRUNC      4043
#define IDC_MS_START_ADDR       4044
#define IDC_MS_STOP_ADDR        4045
#define IDC_MS_EXECUTABLE       4046
#define IDC_MS_FSM_ALIGNED      4047
#define IDC_MS_FSM_LASTDIGITS   4048
#define IDC_MS_STATIC_START     4049
#define IDC_MS_STATIC_STOP      4050
#define IDC_MS_STATIC_MEMOPT    4051

// Context menu IDs
#define IDM_MS_GOTO_DUMP        5001
#define IDM_MS_WRITE            5002
#define IDM_MS_ADD_MONITOR      5003
#define IDM_MS_FREEZE           5004
#define IDM_MS_DEL_MONITOR      5006
#define IDM_MS_SEARCH_ADDR      5007
#define IDM_MS_COPY_ADDR        5008
#define IDM_MS_COPY_VALUE       5009
#define IDM_MS_GOTO_DISASM      5010
#define IDM_MS_EDIT_DESC        5011
#define IDM_MS_EDIT_VALUE       5012
#define IDM_MS_FREEZE_NORMAL    5013
#define IDM_MS_FREEZE_ALLOW_INC 5014
#define IDM_MS_FREEZE_ALLOW_DEC 5015
#define IDM_MS_MON_GOTO_DUMP    5016
#define IDM_MS_MON_GOTO_DISASM  5017
#define IDM_MS_MON_COPY_ADDR    5018
#define IDM_MS_MON_VT_1BYTE     5020
#define IDM_MS_MON_VT_2BYTE     5021
#define IDM_MS_MON_VT_4BYTE     5022
#define IDM_MS_MON_VT_8BYTE     5023
#define IDM_MS_MON_VT_FLOAT     5024
#define IDM_MS_MON_VT_DOUBLE    5025
#define IDM_MS_MON_VT_ANSI     5026
#define IDM_MS_MON_VT_UTF8     5027
#define IDM_MS_MON_VT_UNICODE  5028
#define IDM_MS_MON_VT_AOB      5029

// Timer IDs
#define IDT_FREEZE              6001
#define IDT_AUTO_REFRESH        6002

// Enums
enum MemScanType {
    SCAN_EXACT, SCAN_BIGGER, SCAN_SMALLER, SCAN_BETWEEN, SCAN_UNKNOWN,
    SCAN_INCREASED, SCAN_INCREASED_BY, SCAN_DECREASED, SCAN_DECREASED_BY,
    SCAN_CHANGED, SCAN_UNCHANGED
};
enum MemValueType {
    VT_1BYTE, VT_2BYTE, VT_4BYTE, VT_8BYTE, VT_FLOAT, VT_DOUBLE,
    VT_STRING_ANSI, VT_STRING_UTF8, VT_STRING_UNICODE, VT_AOB
};
enum FreezeMode { FREEZE_NORMAL, FREEZE_ALLOW_INC, FREEZE_ALLOW_DEC };

// Structs
struct MemSearchResult { duint addr; duint prevValue; duint curValue; };
struct MonitoredAddr {
    duint addr; duint freezeValue; int valueType; bool frozen;
    FreezeMode freezeMode; std::string description;
    size_t dataLen; // for String/AoB: byte length
};

// Globals - state
static std::vector<MonitoredAddr> g_monitoredAddrs;
static std::vector<MemSearchResult> g_memSearchResults;
static std::vector<std::vector<MemSearchResult>> g_memSearchHistory;
static int g_memSearchValueType = VT_4BYTE;
static int g_memSearchScanType = SCAN_EXACT;
static bool g_memSearchHasPrev = false;
static bool g_memSearchHex = false;
static bool g_memSearchWritableOnly = false;
static bool g_memSearchFastScan = true;
static int g_memSearchModuleFilter = -1;
static bool g_isNextScanMode = false;
static bool g_memSearchAutoRefresh = false;
static bool g_scanNot = false;
static int g_roundingType = 0; // 0=default, 1=rounded, 2=truncated
static bool g_memSearchExecutableOnly = false;
static int g_fastScanMethod = 0; // 0=aligned, 1=lastdigits
static duint g_startAddr = 0;
static duint g_stopAddr = 0x00007fffffffffff;

// AoB globals
static std::vector<uint8_t> g_aobPattern;
static std::vector<bool> g_aobWildcard;
static size_t g_aobPatternLen = 0;

// String search globals
static std::vector<unsigned char> g_stringPattern;

// Globals - window handles
static HWND hMemSearchWnd = NULL;
static HWND hMsValueEdit = NULL;
static HWND hMsValueTypeCombo = NULL;
static HWND hMsScanTypeCombo = NULL;
static HWND hMsValue2Edit = NULL;
static HWND hMsValue2Label = NULL;
static HWND hMsList = NULL;
static HWND hMsMonitorList = NULL;
static HWND hMsLabel = NULL;
static HWND hMsHexCheck = NULL;
static HWND hMsWritableCheck = NULL;
static HWND hMsModuleCombo = NULL;
static HWND hMsAutoRefreshCheck = NULL;
static HWND hMsProgress = NULL;
static HWND hMsFastScanCheck = NULL;
static HWND hMsAlignEdit = NULL;
static HWND hMsFirstScanBtn = NULL;
static HWND hMsNewScanBtn = NULL;
static HWND hMsUndoBtn = NULL;
static HMENU hMsContextMenu = NULL;
static HMENU hMsMonitorContextMenu = NULL;
static HWND hMsNotCheck = NULL;
static HWND hMsRoundDefault = NULL;
static HWND hMsRoundRounded = NULL;
static HWND hMsRoundTrunc = NULL;
static HWND hMsStartAddr = NULL;
static HWND hMsStopAddr = NULL;
static HWND hMsExecutableCheck = NULL;
static HWND hMsFsmAligned = NULL;
static HWND hMsFsmLastDigits = NULL;

static std::vector<ModuleItem> g_msModuleList;

#define MS_LV_BUF 512
static char g_msLvBuf[MS_LV_BUF];
static char g_msLvBuf2[MS_LV_BUF]; // for monitor list (avoid collision)

static const int MAX_DISPLAY_RESULTS = 50000;
static const size_t MAX_STORED_RESULTS = 10000000;
static const size_t UNDO_MAX_FOR_HISTORY = 1000000;

// ============================================================
// Helper functions
// ============================================================

static bool IsStringType() {
    return g_memSearchValueType == VT_STRING_ANSI || g_memSearchValueType == VT_STRING_UTF8 || g_memSearchValueType == VT_STRING_UNICODE;
}
static bool IsAoBType() { return g_memSearchValueType == VT_AOB; }
static bool IsFloatType() { return g_memSearchValueType == VT_FLOAT || g_memSearchValueType == VT_DOUBLE; }

static int GetValueTypeSize() {
    switch(g_memSearchValueType) {
    case VT_1BYTE: return 1; case VT_2BYTE: return 2; case VT_4BYTE: return 4;
    case VT_8BYTE: return 8; case VT_FLOAT: return 4; case VT_DOUBLE: return 8;
    default: return 4;
    }
}

static int GetValueTypeSizeByType(int vt) {
    switch(vt) {
    case VT_1BYTE: return 1; case VT_2BYTE: return 2; case VT_4BYTE: return 4;
    case VT_8BYTE: return 8; case VT_FLOAT: return 4; case VT_DOUBLE: return 8;
    default: return 4;
    }
}

static int GetDefaultAlignment() {
    if(IsStringType() || IsAoBType()) return 1;
    // CE aligns QWord and Double to 4, not 8
    switch(g_memSearchValueType) {
    case VT_1BYTE: return 1;
    case VT_2BYTE: return 2;
    case VT_4BYTE: case VT_FLOAT: return 4;
    case VT_8BYTE: case VT_DOUBLE: return 4;
    default: return 4;
    }
}

static int GetScanAlignment() {
    if(!g_memSearchFastScan) return 1;
    if(IsStringType() || IsAoBType()) return 1;
    if(hMsAlignEdit) {
        char buf[16] = {};
        GetWindowTextA(hMsAlignEdit, buf, sizeof(buf));
        if(buf[0]) {
            int a = atoi(buf);
            if(a > 0) return a;
        }
    }
    return GetDefaultAlignment();
}

static bool EncodeStringToBytes(const char* src, std::vector<unsigned char>& out, int encoding, bool includeNull = false) {
    if(!src || src[0] == '\0') return false;
    out.clear();
    if(encoding == VT_STRING_ANSI) {
        for(const char* p = src; *p; p++) out.push_back((unsigned char)*p);
        if(includeNull) out.push_back(0);
        return out.size() >= 1;
    }
    int wlen = MultiByteToWideChar(CP_ACP, 0, src, -1, NULL, 0);
    if(wlen <= 0) return false;
    std::vector<wchar_t> wbuf(wlen);
    MultiByteToWideChar(CP_ACP, 0, src, -1, wbuf.data(), wlen);
    if(encoding == VT_STRING_UTF8) {
        int len = WideCharToMultiByte(CP_UTF8, 0, wbuf.data(), -1, NULL, 0, NULL, NULL);
        if(len <= 0) return false;
        out.resize(len);
        WideCharToMultiByte(CP_UTF8, 0, wbuf.data(), -1, (char*)out.data(), len, NULL, NULL);
        if(!includeNull && out.size() > 0) out.pop_back();
        return out.size() >= 1;
    }
    if(encoding == VT_STRING_UNICODE) {
        for(int i = 0; wbuf[i]; i++) {
            out.push_back((unsigned char)(wbuf[i] & 0xFF));
            out.push_back((unsigned char)(wbuf[i] >> 8));
        }
        if(includeNull) { out.push_back(0); out.push_back(0); }
        return out.size() >= 2;
    }
    return false;
}

static std::string DecodeBytesToString(const unsigned char* data, size_t maxLen, int encoding) {
    std::string out;
    if(encoding == VT_STRING_ANSI) {
        for(size_t i = 0; i < maxLen && data[i]; i++) out += (char)data[i];
        return out;
    }
    if(encoding == VT_STRING_UTF8) {
        std::string s((const char*)data, strnlen((const char*)data, maxLen));
        int wlen = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, NULL, 0);
        if(wlen <= 0) return s;
        std::vector<wchar_t> wbuf(wlen);
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, wbuf.data(), wlen);
        int alen = WideCharToMultiByte(CP_ACP, 0, wbuf.data(), -1, NULL, 0, NULL, NULL);
        if(alen <= 0) return s;
        std::vector<char> abuf(alen);
        WideCharToMultiByte(CP_ACP, 0, wbuf.data(), -1, abuf.data(), alen, NULL, NULL);
        return abuf.data();
    }
    if(encoding == VT_STRING_UNICODE) {
        std::vector<wchar_t> wbuf;
        for(size_t i = 0; i + 1 < maxLen && (data[i] || data[i+1]); i += 2)
            wbuf.push_back((wchar_t)(data[i] | (data[i+1] << 8)));
        wbuf.push_back(0);
        int alen = WideCharToMultiByte(CP_ACP, 0, wbuf.data(), -1, NULL, 0, NULL, NULL);
        if(alen <= 0) return "";
        std::vector<char> abuf(alen);
        WideCharToMultiByte(CP_ACP, 0, wbuf.data(), -1, abuf.data(), alen, NULL, NULL);
        return abuf.data();
    }
    return "";
}

static duint ReadValueAt(duint addr) {
    duint v = 0;
    int sz = GetValueTypeSize();
    if(!DbgMemRead(addr, &v, sz)) return 0;
    return v;
}

static duint ReadValueAtByType(duint addr, int vt) {
    duint v = 0;
    int sz = GetValueTypeSizeByType(vt);
    if(sz <= 0) sz = 4;
    if(!DbgMemRead(addr, &v, sz)) return 0;
    return v;
}

static bool ParseSearchValue(const char* buf, duint* outVal) {
    if(!buf || buf[0] == '\0') return false;
    if(hMsHexCheck) g_memSearchHex = (SendMessageA(hMsHexCheck, BM_GETCHECK, 0, 0) == BST_CHECKED);
    if(IsFloatType()) {
        double d = 0;
        if(sscanf(buf, "%lf", &d) != 1) return false;
        if(g_memSearchValueType == VT_FLOAT) { float f = (float)d; memcpy(outVal, &f, 4); }
        else { memcpy(outVal, &d, 8); }
        return true;
    }
    if(g_memSearchHex)
        return sscanf(buf, "%llx", (unsigned long long*)outVal) == 1;
    return sscanf(buf, "%llu", (unsigned long long*)outVal) == 1 || sscanf(buf, "%lld", (long long*)outVal) == 1;
}

static bool ParseAoBPattern(const char* input, std::vector<uint8_t>& pattern, std::vector<bool>& wildcard) {
    pattern.clear(); wildcard.clear();
    if(!input || !*input) return false;
    const char* p = input;
    while(*p) {
        while(*p == ' ' || *p == '\t') p++;
        if(!*p) break;
        if((p[0] == '?' && p[1] == '?') || (p[0] == '?' && (p[1] == ' ' || p[1] == '\0'))) {
            pattern.push_back(0);
            wildcard.push_back(true);
            p += (p[0] == '?' && p[1] == '?') ? 2 : 1;
        } else {
            unsigned int val = 0;
            if(sscanf(p, "%02x", &val) != 1) return false;
            pattern.push_back((uint8_t)val);
            wildcard.push_back(false);
            while(*p && *p != ' ' && *p != '\t') p++;
        }
    }
    return !pattern.empty();
}

static bool IsPageReadable(DWORD protect) {
    return (protect & PAGE_READONLY) || (protect & PAGE_READWRITE) ||
           (protect & PAGE_WRITECOPY) || (protect & PAGE_EXECUTE_READ) ||
           (protect & PAGE_EXECUTE_READWRITE) || (protect & PAGE_EXECUTE_WRITECOPY);
}

static bool IsPageWritable(DWORD protect) {
    return (protect & PAGE_READWRITE) || (protect & PAGE_WRITECOPY) ||
           (protect & PAGE_EXECUTE_READWRITE) || (protect & PAGE_EXECUTE_WRITECOPY);
}

static bool IsPageExecutable(DWORD protect) {
    return (protect & PAGE_EXECUTE) || (protect & PAGE_EXECUTE_READ) ||
           (protect & PAGE_EXECUTE_READWRITE) || (protect & PAGE_EXECUTE_WRITECOPY);
}

static bool MatchModuleFilter(duint addr) {
    if(g_memSearchModuleFilter < 0 || g_memSearchModuleFilter >= (int)g_msModuleList.size()) return true;
    const auto& m = g_msModuleList[g_memSearchModuleFilter];
    return addr >= m.base && addr < m.base + m.size;
}

static bool PageInModuleFilter(duint base, duint size) {
    if(g_memSearchModuleFilter < 0 || g_memSearchModuleFilter >= (int)g_msModuleList.size()) return true;
    const auto& m = g_msModuleList[g_memSearchModuleFilter];
    duint modEnd = m.base + m.size;
    return base < modEnd && (base + size) > m.base;
}

// ============================================================
// Dropdown management
// ============================================================

static void PopulateScanTypeDropdown(bool nextScanMode) {
    if(!hMsScanTypeCombo) return;
    SendMessageA(hMsScanTypeCombo, CB_RESETCONTENT, 0, 0);
    if(!nextScanMode) {
        SendMessageA(hMsScanTypeCombo, CB_ADDSTRING, 0, (LPARAM)"精确数值");
        SendMessageA(hMsScanTypeCombo, CB_ADDSTRING, 0, (LPARAM)"大于...");
        SendMessageA(hMsScanTypeCombo, CB_ADDSTRING, 0, (LPARAM)"小于...");
        SendMessageA(hMsScanTypeCombo, CB_ADDSTRING, 0, (LPARAM)"介于两值之间");
        SendMessageA(hMsScanTypeCombo, CB_ADDSTRING, 0, (LPARAM)"未知的初始值");
    } else {
        SendMessageA(hMsScanTypeCombo, CB_ADDSTRING, 0, (LPARAM)"精确数值");
        SendMessageA(hMsScanTypeCombo, CB_ADDSTRING, 0, (LPARAM)"大于...");
        SendMessageA(hMsScanTypeCombo, CB_ADDSTRING, 0, (LPARAM)"小于...");
        SendMessageA(hMsScanTypeCombo, CB_ADDSTRING, 0, (LPARAM)"介于两值之间");
        SendMessageA(hMsScanTypeCombo, CB_ADDSTRING, 0, (LPARAM)"增大的数值");
        SendMessageA(hMsScanTypeCombo, CB_ADDSTRING, 0, (LPARAM)"增大了指定的值");
        SendMessageA(hMsScanTypeCombo, CB_ADDSTRING, 0, (LPARAM)"减小的数值");
        SendMessageA(hMsScanTypeCombo, CB_ADDSTRING, 0, (LPARAM)"减小了指定的值");
        SendMessageA(hMsScanTypeCombo, CB_ADDSTRING, 0, (LPARAM)"变动的数值");
        SendMessageA(hMsScanTypeCombo, CB_ADDSTRING, 0, (LPARAM)"未变动的数值");
    }
    SendMessageA(hMsScanTypeCombo, CB_SETCURSEL, 0, 0);
}

static MemScanType DropdownIndexToScanType(int index, bool nextScanMode) {
    if(!nextScanMode) {
        switch(index) {
        case 0: return SCAN_EXACT; case 1: return SCAN_BIGGER; case 2: return SCAN_SMALLER;
        case 3: return SCAN_BETWEEN; case 4: return SCAN_UNKNOWN; default: return SCAN_EXACT;
        }
    } else {
        switch(index) {
        case 0: return SCAN_EXACT; case 1: return SCAN_BIGGER; case 2: return SCAN_SMALLER;
        case 3: return SCAN_BETWEEN; case 4: return SCAN_INCREASED; case 5: return SCAN_INCREASED_BY;
        case 6: return SCAN_DECREASED; case 7: return SCAN_DECREASED_BY;
        case 8: return SCAN_CHANGED; case 9: return SCAN_UNCHANGED; default: return SCAN_EXACT;
        }
    }
}

static void UpdateValue2Visibility() {
    int idx = (int)SendMessageA(hMsScanTypeCombo, CB_GETCURSEL, 0, 0);
    MemScanType st = DropdownIndexToScanType(idx, g_isNextScanMode);
    bool show = (st == SCAN_BETWEEN || st == SCAN_INCREASED_BY || st == SCAN_DECREASED_BY);
    if(hMsValue2Edit) ShowWindow(hMsValue2Edit, show ? SW_SHOW : SW_HIDE);
    if(hMsValue2Label) ShowWindow(hMsValue2Label, show ? SW_SHOW : SW_HIDE);
}

static void UpdateRoundingVisibility() {
    bool show = IsFloatType();
    if(hMsRoundDefault) EnableWindow(hMsRoundDefault, show);
    if(hMsRoundRounded) EnableWindow(hMsRoundRounded, show);
    if(hMsRoundTrunc) EnableWindow(hMsRoundTrunc, show);
}

static void UpdateButtonStates() {
    if(!hMsFirstScanBtn) return;
    if(!g_isNextScanMode) {
        SetWindowTextA(hMsFirstScanBtn, "首次扫描");
        EnableWindow(hMsNewScanBtn, FALSE);
        EnableWindow(hMsUndoBtn, FALSE);
        if(hMsValueTypeCombo) EnableWindow(hMsValueTypeCombo, TRUE);
        if(hMsFastScanCheck) EnableWindow(hMsFastScanCheck, TRUE);
        if(hMsAlignEdit) EnableWindow(hMsAlignEdit, TRUE);
        if(hMsWritableCheck) EnableWindow(hMsWritableCheck, TRUE);
        if(hMsExecutableCheck) EnableWindow(hMsExecutableCheck, TRUE);
        if(hMsModuleCombo) EnableWindow(hMsModuleCombo, TRUE);
        if(hMsStartAddr) EnableWindow(hMsStartAddr, TRUE);
        if(hMsStopAddr) EnableWindow(hMsStopAddr, TRUE);
        if(hMsNotCheck) EnableWindow(hMsNotCheck, TRUE);
    } else {
        SetWindowTextA(hMsFirstScanBtn, "新的扫描");
        EnableWindow(hMsNewScanBtn, TRUE);
        EnableWindow(hMsUndoBtn, !g_memSearchHistory.empty());
        if(hMsValueTypeCombo) EnableWindow(hMsValueTypeCombo, FALSE);
        if(hMsFastScanCheck) EnableWindow(hMsFastScanCheck, FALSE);
        if(hMsAlignEdit) EnableWindow(hMsAlignEdit, FALSE);
        if(hMsWritableCheck) EnableWindow(hMsWritableCheck, FALSE);
        if(hMsExecutableCheck) EnableWindow(hMsExecutableCheck, FALSE);
        if(hMsModuleCombo) EnableWindow(hMsModuleCombo, FALSE);
        if(hMsStartAddr) EnableWindow(hMsStartAddr, FALSE);
        if(hMsStopAddr) EnableWindow(hMsStopAddr, FALSE);
    }
}

// ============================================================
// Value formatting
// ============================================================

static void FormatValueForDisplay(duint v, char* buf, size_t bufSize) {
    if(IsFloatType()) {
        if(g_memSearchValueType == VT_FLOAT) { float f; memcpy(&f, &v, 4); sprintf_s(buf, bufSize, "%.6g", f); }
        else { double d; memcpy(&d, &v, 8); sprintf_s(buf, bufSize, "%.6g", d); }
    } else {
        sprintf_s(buf, bufSize, "%llX", (unsigned long long)v);
    }
}

static void FormatAoBForDisplay(duint addr, size_t len, char* buf, size_t bufSize) {
    unsigned char tmp[64] = {};
    size_t toRead = (len < 64) ? len : 64;
    if(!DbgMemRead(addr, tmp, (duint)toRead)) { buf[0] = '?'; buf[1] = 0; return; }
    buf[0] = 0;
    for(size_t i = 0; i < toRead && (i * 3 + 3) < bufSize; i++) {
        char hex[4];
        sprintf_s(hex, "%02X ", tmp[i]);
        strcat_s(buf, bufSize, hex);
    }
    size_t slen = strlen(buf);
    if(slen > 0 && buf[slen - 1] == ' ') buf[slen - 1] = 0;
}

static void FormatValueByType(duint v, int vt, char* buf, size_t bufSize) {
    if(vt == VT_FLOAT) { float f; memcpy(&f, &v, 4); sprintf_s(buf, bufSize, "%.6g", f); }
    else if(vt == VT_DOUBLE) { double d; memcpy(&d, &v, 8); sprintf_s(buf, bufSize, "%.6g", d); }
    else sprintf_s(buf, bufSize, "%llX", (unsigned long long)v);
}

static const char* GetValueTypeName(int vt) {
    switch(vt) {
    case VT_1BYTE: return "字节"; case VT_2BYTE: return "2字节"; case VT_4BYTE: return "4字节";
    case VT_8BYTE: return "8字节"; case VT_FLOAT: return "浮点数"; case VT_DOUBLE: return "双浮点数";
    case VT_STRING_ANSI: return "ANSI"; case VT_STRING_UTF8: return "UTF-8";
    case VT_STRING_UNICODE: return "Unicode"; case VT_AOB: return "字节数组";
    default: return "4字节";
    }
}

// ============================================================
// First scan matching
// ============================================================

static bool MatchFirstScan(duint v, duint searchVal, duint searchVal2) {
    bool result = false;
    if(IsFloatType()) {
        if(g_memSearchValueType == VT_FLOAT) {
            float fv, f1, f2;
            memcpy(&fv, &v, 4); memcpy(&f1, &searchVal, 4); memcpy(&f2, &searchVal2, 4);
            switch(g_memSearchScanType) {
            case SCAN_EXACT:
                if(g_roundingType == 1) result = (fabs(fv - f1) < 0.5f);
                else if(g_roundingType == 2) result = ((long long)fv == (long long)f1);
                else result = (memcmp(&v, &searchVal, 4) == 0);
                break;
            case SCAN_BIGGER: result = fv > f1; break;
            case SCAN_SMALLER: result = fv < f1; break;
            case SCAN_BETWEEN: result = fv >= f1 && fv <= f2; break;
            case SCAN_UNKNOWN: result = true; break;
            default: result = (memcmp(&v, &searchVal, 4) == 0); break;
            }
        } else {
            double dv, d1, d2;
            memcpy(&dv, &v, 8); memcpy(&d1, &searchVal, 8); memcpy(&d2, &searchVal2, 8);
            switch(g_memSearchScanType) {
            case SCAN_EXACT:
                if(g_roundingType == 1) result = (fabs(dv - d1) < 0.5);
                else if(g_roundingType == 2) result = ((long long)dv == (long long)d1);
                else result = (memcmp(&v, &searchVal, 8) == 0);
                break;
            case SCAN_BIGGER: result = dv > d1; break;
            case SCAN_SMALLER: result = dv < d1; break;
            case SCAN_BETWEEN: result = dv >= d1 && dv <= d2; break;
            case SCAN_UNKNOWN: result = true; break;
            default: result = (memcmp(&v, &searchVal, 8) == 0); break;
            }
        }
    } else {
        switch(g_memSearchScanType) {
        case SCAN_EXACT: result = v == searchVal; break;
        case SCAN_BIGGER: result = v > searchVal; break;
        case SCAN_SMALLER: result = v < searchVal; break;
        case SCAN_BETWEEN: result = v >= searchVal && v <= searchVal2; break;
        case SCAN_UNKNOWN: result = true; break;
        default: result = v == searchVal; break;
        }
    }
    if(g_scanNot && g_memSearchScanType != SCAN_UNKNOWN) result = !result;
    return result;
}

// ============================================================
// Next scan matching (enhanced)
// ============================================================

static bool MatchNextScan(duint cur, duint prev, duint searchVal, duint searchVal2) {
    bool result = false;
    if(IsFloatType()) {
        if(g_memSearchValueType == VT_FLOAT) {
            float fc, fp, fs, fs2;
            memcpy(&fc, &cur, 4); memcpy(&fp, &prev, 4); memcpy(&fs, &searchVal, 4); memcpy(&fs2, &searchVal2, 4);
            const float eps = 0.0001f;
            switch(g_memSearchScanType) {
            case SCAN_EXACT:
                if(g_roundingType == 1) result = (fabs(fc - fs) < 0.5f);
                else if(g_roundingType == 2) result = ((long long)fc == (long long)fs);
                else result = (memcmp(&cur, &searchVal, 4) == 0);
                break;
            case SCAN_BIGGER: result = fc > fs; break;
            case SCAN_SMALLER: result = fc < fs; break;
            case SCAN_BETWEEN: result = fc >= fs && fc <= fs2; break;
            case SCAN_INCREASED: result = fc > fp; break;
            case SCAN_DECREASED: result = fc < fp; break;
            case SCAN_INCREASED_BY: result = fabs((fc - fp) - fs) < eps; break;
            case SCAN_DECREASED_BY: result = fabs((fp - fc) - fs) < eps; break;
            case SCAN_CHANGED: result = (memcmp(&cur, &prev, 4) != 0); break;
            case SCAN_UNCHANGED: result = (memcmp(&cur, &prev, 4) == 0); break;
            default: result = (cur == searchVal); break;
            }
        } else {
            double dc, dp, ds, ds2;
            memcpy(&dc, &cur, 8); memcpy(&dp, &prev, 8); memcpy(&ds, &searchVal, 8); memcpy(&ds2, &searchVal2, 8);
            const double eps = 0.0000001;
            switch(g_memSearchScanType) {
            case SCAN_EXACT:
                if(g_roundingType == 1) result = (fabs(dc - ds) < 0.5);
                else if(g_roundingType == 2) result = ((long long)dc == (long long)ds);
                else result = (memcmp(&cur, &searchVal, 8) == 0);
                break;
            case SCAN_BIGGER: result = dc > ds; break;
            case SCAN_SMALLER: result = dc < ds; break;
            case SCAN_BETWEEN: result = dc >= ds && dc <= ds2; break;
            case SCAN_INCREASED: result = dc > dp; break;
            case SCAN_DECREASED: result = dc < dp; break;
            case SCAN_INCREASED_BY: result = fabs((dc - dp) - ds) < eps; break;
            case SCAN_DECREASED_BY: result = fabs((dp - dc) - ds) < eps; break;
            case SCAN_CHANGED: result = (memcmp(&cur, &prev, 8) != 0); break;
            case SCAN_UNCHANGED: result = (memcmp(&cur, &prev, 8) == 0); break;
            default: result = (cur == searchVal); break;
            }
        }
        if(g_scanNot) result = !result;
        return result;
    }
    // Integer types
    result = false;
    switch(g_memSearchScanType) {
    case SCAN_EXACT: result = cur == searchVal; break;
    case SCAN_BIGGER: result = cur > searchVal; break;
    case SCAN_SMALLER: result = cur < searchVal; break;
    case SCAN_BETWEEN: result = cur >= searchVal && cur <= searchVal2; break;
    case SCAN_INCREASED: result = cur > prev; break;
    case SCAN_DECREASED: result = cur < prev; break;
    case SCAN_INCREASED_BY: result = (cur - prev) == searchVal; break;
    case SCAN_DECREASED_BY: result = (prev - cur) == searchVal; break;
    case SCAN_CHANGED: result = cur != prev; break;
    case SCAN_UNCHANGED: result = cur == prev; break;
    default: result = cur == searchVal; break;
    }
    if(g_scanNot) result = !result;
    return result;
}

// ============================================================
// Module list population
// ============================================================

static void PopulateMsModuleList() {
    g_msModuleList.clear();
    if(!DbgIsDebugging()) return;
    BridgeList<Script::Module::ModuleInfo> modules;
    if(!Script::Module::GetList(&modules)) return;
    for(int i = 0; i < modules.Count(); i++) {
        ModuleItem mi = {};
        strcpy_s(mi.name, modules[i].name);
        mi.base = modules[i].base; mi.size = modules[i].size; mi.entry = modules[i].entry;
        g_msModuleList.push_back(mi);
    }
}

// ============================================================
// Update label with result count
// ============================================================

static void UpdateResultLabel() {
    size_t count = g_memSearchResults.size();
    char label[256];
    if(count > MAX_DISPLAY_RESULTS)
        sprintf_s(label, "找到: %zu (显示前 %d 条)", count, MAX_DISPLAY_RESULTS);
    else
        sprintf_s(label, "找到: %zu", count);
    SetWindowTextA(hMsLabel, label);
}

static void UpdateListCount() {
    size_t count = g_memSearchResults.size();
    int display = (count > MAX_DISPLAY_RESULTS) ? MAX_DISPLAY_RESULTS : (int)count;
    SendMessageA(hMsList, LVM_SETITEMCOUNT, display, LVSICF_NOINVALIDATEALL);
    InvalidateRect(hMsList, NULL, TRUE);
}

// ============================================================
// First Scan
// ============================================================

static void MemSearchFirstScan() {
    g_memSearchHistory.clear();
    g_memSearchResults.clear();
    g_memSearchHasPrev = false;

    if(!DbgIsDebugging()) { SetWindowTextA(hMsLabel, "未在调试"); return; }

    // Read UI state
    if(hMsNotCheck) g_scanNot = (SendMessageA(hMsNotCheck, BM_GETCHECK, 0, 0) == BST_CHECKED);
    if(hMsRoundDefault && SendMessageA(hMsRoundDefault, BM_GETCHECK, 0, 0) == BST_CHECKED) g_roundingType = 0;
    if(hMsRoundRounded && SendMessageA(hMsRoundRounded, BM_GETCHECK, 0, 0) == BST_CHECKED) g_roundingType = 1;
    if(hMsRoundTrunc && SendMessageA(hMsRoundTrunc, BM_GETCHECK, 0, 0) == BST_CHECKED) g_roundingType = 2;
    if(hMsExecutableCheck) g_memSearchExecutableOnly = (SendMessageA(hMsExecutableCheck, BM_GETCHECK, 0, 0) == BST_CHECKED);

    // Read address range
    char addrBuf[32] = {};
    if(hMsStartAddr) { GetWindowTextA(hMsStartAddr, addrBuf, sizeof(addrBuf)); sscanf(addrBuf, "%llx", (unsigned long long*)&g_startAddr); }
    if(hMsStopAddr) { GetWindowTextA(hMsStopAddr, addrBuf, sizeof(addrBuf)); sscanf(addrBuf, "%llx", (unsigned long long*)&g_stopAddr); }

    // Read scan type
    int stIdx = (int)SendMessageA(hMsScanTypeCombo, CB_GETCURSEL, 0, 0);
    g_memSearchScanType = DropdownIndexToScanType(stIdx, false);

    // Read value edit
    char valBuf[512] = {};
    GetWindowTextA(hMsValueEdit, valBuf, sizeof(valBuf));
    duint searchVal = 0, searchVal2 = 0;

    // AoB scan
    if(IsAoBType()) {
        if(!ParseAoBPattern(valBuf, g_aobPattern, g_aobWildcard) || g_aobPattern.empty()) {
            SetWindowTextA(hMsLabel, "无效的字节数组"); return;
        }
        g_aobPatternLen = g_aobPattern.size();

        MEMMAP memmap = {};
        if(!DbgMemMap(&memmap)) { SetWindowTextA(hMsLabel, "获取内存映射失败"); return; }

        SetWindowTextA(hMsLabel, "扫描字节数组...");
        SendMessageA(hMsProgress, PBM_SETPOS, 0, 0);
        GuiProcessEvents();

        int totalPages = memmap.count;
        for(int i = 0; i < memmap.count; i++) {
            MEMPAGE& pg = memmap.page[i];
            if(pg.mbi.State != MEM_COMMIT || !IsPageReadable(pg.mbi.Protect)) continue;
            if(g_memSearchWritableOnly && !IsPageWritable(pg.mbi.Protect)) continue;
            if(g_memSearchExecutableOnly && !IsPageExecutable(pg.mbi.Protect)) continue;
            duint base = (duint)pg.mbi.BaseAddress;
            duint size = (duint)pg.mbi.RegionSize;
            if(base + size <= g_startAddr || base >= g_stopAddr) continue;
            if(!PageInModuleFilter(base, size)) continue;
            if(size < g_aobPatternLen) continue;

            std::vector<unsigned char> buf(size);
            if(!DbgMemRead(base, buf.data(), size)) continue;

            for(duint off = 0; off + g_aobPatternLen <= size; off++) {
                bool match = true;
                for(size_t k = 0; k < g_aobPatternLen; k++) {
                    if(!g_aobWildcard[k] && buf[off + k] != g_aobPattern[k]) { match = false; break; }
                }
                if(match) {
                    MemSearchResult r;
                    r.addr = base + off;
                    r.prevValue = 0; r.curValue = 0;
                    memcpy(&r.prevValue, &buf[off], (g_aobPatternLen < 8) ? g_aobPatternLen : 8);
                    r.curValue = r.prevValue;
                    g_memSearchResults.push_back(r);
                    if(g_memSearchResults.size() >= MAX_STORED_RESULTS) break;
                }
            }
            if(i % 50 == 0) {
                SendMessageA(hMsProgress, PBM_SETPOS, i * 100 / totalPages, 0);
                GuiProcessEvents();
            }
            if(g_memSearchResults.size() >= MAX_STORED_RESULTS) break;
        }
        BridgeFree(memmap.page);
        SendMessageA(hMsProgress, PBM_SETPOS, 100, 0);
        g_memSearchHasPrev = true;
        g_isNextScanMode = true;
        PopulateScanTypeDropdown(true);
        UpdateButtonStates();
        UpdateResultLabel();
        UpdateListCount();
        UpdateValue2Visibility();
        return;
    }

    // String scan
    if(IsStringType()) {
        if(!EncodeStringToBytes(valBuf, g_stringPattern, g_memSearchValueType) || g_stringPattern.empty()) {
            SetWindowTextA(hMsLabel, "请输入搜索字符串"); return;
        }
        MEMMAP memmap = {};
        if(!DbgMemMap(&memmap)) { SetWindowTextA(hMsLabel, "获取内存映射失败"); return; }

        SetWindowTextA(hMsLabel, "扫描字符串...");
        SendMessageA(hMsProgress, PBM_SETPOS, 0, 0);
        GuiProcessEvents();

        size_t patLen = g_stringPattern.size();
        int totalPages = memmap.count;
        for(int i = 0; i < memmap.count; i++) {
            MEMPAGE& pg = memmap.page[i];
            if(pg.mbi.State != MEM_COMMIT || !IsPageReadable(pg.mbi.Protect)) continue;
            if(g_memSearchWritableOnly && !IsPageWritable(pg.mbi.Protect)) continue;
            if(g_memSearchExecutableOnly && !IsPageExecutable(pg.mbi.Protect)) continue;
            duint base = (duint)pg.mbi.BaseAddress;
            duint size = (duint)pg.mbi.RegionSize;
            if(base + size <= g_startAddr || base >= g_stopAddr) continue;
            if(!PageInModuleFilter(base, size)) continue;
            if(size < patLen) continue;

            std::vector<unsigned char> buf(size);
            if(!DbgMemRead(base, buf.data(), size)) continue;

            for(duint off = 0; off + patLen <= size; off++) {
                if(memcmp(&buf[off], g_stringPattern.data(), patLen) == 0) {
                    MemSearchResult r;
                    r.addr = base + off;
                    r.prevValue = 0; r.curValue = 0;
                    memcpy(&r.prevValue, &buf[off], (patLen < 8) ? patLen : 8);
                    r.curValue = r.prevValue;
                    g_memSearchResults.push_back(r);
                    if(g_memSearchResults.size() >= MAX_STORED_RESULTS) break;
                }
            }
            if(i % 50 == 0) {
                SendMessageA(hMsProgress, PBM_SETPOS, i * 100 / totalPages, 0);
                GuiProcessEvents();
            }
            if(g_memSearchResults.size() >= MAX_STORED_RESULTS) break;
        }
        BridgeFree(memmap.page);
        SendMessageA(hMsProgress, PBM_SETPOS, 100, 0);
        g_memSearchHasPrev = true;
        g_isNextScanMode = true;
        PopulateScanTypeDropdown(true);
        UpdateButtonStates();
        UpdateResultLabel();
        UpdateListCount();
        UpdateValue2Visibility();
        return;
    }

    // Numeric scan
    if(g_memSearchScanType != SCAN_UNKNOWN) {
        if(!ParseSearchValue(valBuf, &searchVal)) { SetWindowTextA(hMsLabel, "请输入有效值"); return; }
    }
    if(g_memSearchScanType == SCAN_BETWEEN) {
        char buf2[64] = {};
        if(hMsValue2Edit) GetWindowTextA(hMsValue2Edit, buf2, sizeof(buf2));
        if(!ParseSearchValue(buf2, &searchVal2)) { SetWindowTextA(hMsLabel, "请输入范围值2"); return; }
    }

    MEMMAP memmap = {};
    if(!DbgMemMap(&memmap)) { SetWindowTextA(hMsLabel, "获取内存映射失败"); return; }

    SetWindowTextA(hMsLabel, "扫描中...");
    SendMessageA(hMsProgress, PBM_SETPOS, 0, 0);
    GuiProcessEvents();

    int valSize = GetValueTypeSize();
    int alignment = GetScanAlignment();
    int totalPages = memmap.count;

    for(int i = 0; i < memmap.count; i++) {
        MEMPAGE& pg = memmap.page[i];
        if(pg.mbi.State != MEM_COMMIT || !IsPageReadable(pg.mbi.Protect)) continue;
        if(g_memSearchWritableOnly && !IsPageWritable(pg.mbi.Protect)) continue;
        if(g_memSearchExecutableOnly && !IsPageExecutable(pg.mbi.Protect)) continue;
        duint base = (duint)pg.mbi.BaseAddress;
        duint size = (duint)pg.mbi.RegionSize;
        if(base + size <= g_startAddr || base >= g_stopAddr) continue;
        if(!PageInModuleFilter(base, size)) continue;
        if(size < (duint)valSize) continue;

        std::vector<unsigned char> buf(size);
        if(!DbgMemRead(base, buf.data(), size)) continue;

        for(duint off = 0; off + valSize <= size; off += alignment) {
            duint v = 0;
            memcpy(&v, &buf[off], valSize);
            if(MatchFirstScan(v, searchVal, searchVal2)) {
                MemSearchResult r;
                r.addr = base + off; r.prevValue = v; r.curValue = v;
                g_memSearchResults.push_back(r);
                if(g_memSearchResults.size() >= MAX_STORED_RESULTS) break;
            }
        }
        if(i % 50 == 0) {
            SendMessageA(hMsProgress, PBM_SETPOS, i * 100 / totalPages, 0);
            GuiProcessEvents();
        }
        if(g_memSearchResults.size() >= MAX_STORED_RESULTS) break;
    }
    BridgeFree(memmap.page);
    SendMessageA(hMsProgress, PBM_SETPOS, 100, 0);
    g_memSearchHasPrev = true;
    g_isNextScanMode = true;
    PopulateScanTypeDropdown(true);
    UpdateButtonStates();
    UpdateResultLabel();
    UpdateListCount();
    UpdateValue2Visibility();
}

// ============================================================
// Next Scan
// ============================================================

static void MemSearchNextScan() {
    if(!g_memSearchHasPrev || g_memSearchResults.empty()) {
        SetWindowTextA(hMsLabel, "请先进行首次扫描"); return;
    }
    if(!DbgIsDebugging()) { SetWindowTextA(hMsLabel, "未在调试"); return; }

    int stIdx = (int)SendMessageA(hMsScanTypeCombo, CB_GETCURSEL, 0, 0);
    g_memSearchScanType = DropdownIndexToScanType(stIdx, true);

    char valBuf[512] = {};
    GetWindowTextA(hMsValueEdit, valBuf, sizeof(valBuf));
    duint searchVal = 0, searchVal2 = 0;

    // For types that need a value
    bool needsValue = (g_memSearchScanType == SCAN_EXACT || g_memSearchScanType == SCAN_BIGGER ||
        g_memSearchScanType == SCAN_SMALLER || g_memSearchScanType == SCAN_BETWEEN ||
        g_memSearchScanType == SCAN_INCREASED_BY || g_memSearchScanType == SCAN_DECREASED_BY);

    // AoB next scan: only Changed/Unchanged supported
    if(IsAoBType()) {
        if(g_memSearchScanType != SCAN_CHANGED && g_memSearchScanType != SCAN_UNCHANGED) {
            SetWindowTextA(hMsLabel, "字节数组仅支持变动/未变动"); return;
        }
        // Save history
        if(g_memSearchResults.size() < UNDO_MAX_FOR_HISTORY)
            g_memSearchHistory.push_back(g_memSearchResults);

        SetWindowTextA(hMsLabel, "筛选字节数组...");
        SendMessageA(hMsProgress, PBM_SETPOS, 0, 0);
        GuiProcessEvents();

        std::vector<MemSearchResult> filtered;
        int total = (int)g_memSearchResults.size();
        for(int i = 0; i < total; i++) {
            auto& r = g_memSearchResults[i];
            duint curVal = 0;
            unsigned char tmp[8] = {};
            size_t toRead = (g_aobPatternLen < 8) ? g_aobPatternLen : 8;
            if(DbgMemRead(r.addr, tmp, (duint)toRead)) memcpy(&curVal, tmp, toRead);
            bool changed = (curVal != r.prevValue);
            bool match = (g_memSearchScanType == SCAN_CHANGED) ? changed : !changed;
            if(match) {
                MemSearchResult nr;
                nr.addr = r.addr; nr.prevValue = r.curValue; nr.curValue = curVal;
                filtered.push_back(nr);
            }
            if(i % 50000 == 0 && total > 0) {
                SendMessageA(hMsProgress, PBM_SETPOS, i * 100 / total, 0);
                GuiProcessEvents();
            }
        }
        g_memSearchResults = std::move(filtered);
        SendMessageA(hMsProgress, PBM_SETPOS, 100, 0);
        UpdateResultLabel(); UpdateListCount(); UpdateButtonStates();
        return;
    }

    // String next scan
    if(IsStringType()) {
        if(g_memSearchResults.size() < UNDO_MAX_FOR_HISTORY)
            g_memSearchHistory.push_back(g_memSearchResults);

        bool hasExact = false;
        std::vector<unsigned char> pattern;
        if(needsValue && (g_memSearchScanType == SCAN_EXACT))
            hasExact = EncodeStringToBytes(valBuf, pattern, g_memSearchValueType) && !pattern.empty();

        SetWindowTextA(hMsLabel, "筛选字符串...");
        SendMessageA(hMsProgress, PBM_SETPOS, 0, 0);
        GuiProcessEvents();

        std::vector<MemSearchResult> filtered;
        int total = (int)g_memSearchResults.size();
        for(int i = 0; i < total; i++) {
            auto& r = g_memSearchResults[i];
            unsigned char curBuf[256] = {};
            if(!DbgMemRead(r.addr, curBuf, sizeof(curBuf))) continue;
            duint curVal = 0;
            size_t patLen = g_stringPattern.size();
            if(patLen > 0) memcpy(&curVal, curBuf, (patLen < 8) ? patLen : 8);

            bool match = false;
            if(g_memSearchScanType == SCAN_EXACT && hasExact) {
                match = (memcmp(curBuf, pattern.data(), pattern.size()) == 0);
            } else if(g_memSearchScanType == SCAN_CHANGED) {
                match = (curVal != r.prevValue);
            } else if(g_memSearchScanType == SCAN_UNCHANGED) {
                match = (curVal == r.prevValue);
            }
            if(match) {
                MemSearchResult nr;
                nr.addr = r.addr; nr.prevValue = r.curValue; nr.curValue = curVal;
                filtered.push_back(nr);
            }
            if(i % 50000 == 0 && total > 0) {
                SendMessageA(hMsProgress, PBM_SETPOS, i * 100 / total, 0);
                GuiProcessEvents();
            }
        }
        g_memSearchResults = std::move(filtered);
        SendMessageA(hMsProgress, PBM_SETPOS, 100, 0);
        UpdateResultLabel(); UpdateListCount(); UpdateButtonStates();
        return;
    }

    // Numeric next scan
    if(needsValue && !IsAoBType() && !IsStringType()) {
        if(!ParseSearchValue(valBuf, &searchVal)) { SetWindowTextA(hMsLabel, "请输入有效值"); return; }
    }
    if(g_memSearchScanType == SCAN_BETWEEN) {
        char buf2[64] = {};
        if(hMsValue2Edit) GetWindowTextA(hMsValue2Edit, buf2, sizeof(buf2));
        if(!ParseSearchValue(buf2, &searchVal2)) { SetWindowTextA(hMsLabel, "请输入范围值2"); return; }
    }

    if(g_memSearchResults.size() < UNDO_MAX_FOR_HISTORY)
        g_memSearchHistory.push_back(g_memSearchResults);

    SetWindowTextA(hMsLabel, "筛选中...");
    SendMessageA(hMsProgress, PBM_SETPOS, 0, 0);
    GuiProcessEvents();

    std::vector<MemSearchResult> filtered;
    int total = (int)g_memSearchResults.size();
    int valSize = GetValueTypeSize();

    for(int i = 0; i < total; i++) {
        auto& r = g_memSearchResults[i];
        duint cur = 0;
        DbgMemRead(r.addr, &cur, valSize);
        if(MatchNextScan(cur, r.prevValue, searchVal, searchVal2)) {
            MemSearchResult nr;
            nr.addr = r.addr; nr.prevValue = cur; nr.curValue = cur;
            filtered.push_back(nr);
        }
        if(i % 50000 == 0 && total > 0) {
            SendMessageA(hMsProgress, PBM_SETPOS, i * 100 / total, 0);
            GuiProcessEvents();
        }
    }
    g_memSearchResults = std::move(filtered);
    SendMessageA(hMsProgress, PBM_SETPOS, 100, 0);
    UpdateResultLabel(); UpdateListCount(); UpdateButtonStates();
}

// ============================================================
// Undo / New Scan
// ============================================================

static void MemSearchUndo() {
    if(g_memSearchHistory.empty()) { SetWindowTextA(hMsLabel, "没有可撤销的操作"); return; }
    g_memSearchResults = std::move(g_memSearchHistory.back());
    g_memSearchHistory.pop_back();
    UpdateResultLabel(); UpdateListCount(); UpdateButtonStates();
}

static void MemSearchNewScan() {
    g_memSearchHistory.clear();
    g_memSearchResults.clear();
    g_memSearchHasPrev = false;
    g_isNextScanMode = false;
    g_aobPattern.clear(); g_aobWildcard.clear(); g_aobPatternLen = 0;
    g_stringPattern.clear();
    PopulateScanTypeDropdown(false);
    UpdateButtonStates();
    UpdateValue2Visibility();
    SetWindowTextA(hMsLabel, "找到: 0");
    SendMessageA(hMsList, LVM_SETITEMCOUNT, 0, 0);
    SendMessageA(hMsProgress, PBM_SETPOS, 0, 0);
}

// ============================================================
// Search address in memory (reference scan)
// ============================================================

static void SearchAddressInMemory(duint targetAddr) {
    if(!DbgIsDebugging()) return;
    MEMMAP memmap = {};
    if(!DbgMemMap(&memmap)) return;

    GuiReferenceInitialize("Address Reference Search");
    GuiReferenceAddColumn(18, "Address");
    GuiReferenceAddColumn(18, "Module");
    GuiReferenceAddColumn(0, "Disassembly");
    GuiReferenceSetSearchStartCol(0);

    int found = 0;
    const int ptrSize = sizeof(duint);
    for(int i = 0; i < memmap.count; i++) {
        MEMPAGE& pg = memmap.page[i];
        if(pg.mbi.State != MEM_COMMIT || !IsPageReadable(pg.mbi.Protect)) continue;
        duint base = (duint)pg.mbi.BaseAddress;
        duint size = (duint)pg.mbi.RegionSize;
        if(size < (duint)ptrSize) continue;

        std::vector<unsigned char> buf(size);
        if(!DbgMemRead(base, buf.data(), size)) continue;
        for(duint j = 0; j <= size - ptrSize; j += 4) {
            duint val = 0;
            memcpy(&val, buf.data() + j, ptrSize);
            if(val == targetAddr) {
                duint hitAddr = base + j;
                char addrStr[32], modStr[MAX_MODULE_SIZE] = {}, disasmStr[256] = {};
                sprintf_s(addrStr, "%016llX", (unsigned long long)hitAddr);
                DbgGetModuleAt(hitAddr, modStr);
                DISASM_INSTR instr = {};
                DbgDisasmAt(hitAddr, &instr);
                if(instr.instruction[0]) strncpy_s(disasmStr, instr.instruction, sizeof(disasmStr) - 1);
                GuiReferenceSetRowCount(found + 1);
                GuiReferenceSetCellContent(found, 0, addrStr);
                GuiReferenceSetCellContent(found, 1, modStr);
                GuiReferenceSetCellContent(found, 2, disasmStr);
                found++;
            }
        }
        GuiReferenceSetProgress((int)((i + 1) * 100 / memmap.count));
    }
    GuiReferenceSetProgress(100);
    GuiReferenceReloadData();
    GuiShowReferences();
    BridgeFree(memmap.page);

    char msg[128];
    sprintf_s(msg, "搜索完成, 找到 %d 个引用", found);
    if(hMsLabel) SetWindowTextA(hMsLabel, msg);
}

void MemSearch_SearchAddress(duint targetAddr) {
    SearchAddressInMemory(targetAddr);
}

// ============================================================
// Freeze logic
// ============================================================

static void ApplyFreeze() {
    if(!DbgIsDebugging()) return;
    for(auto& m : g_monitoredAddrs) {
        if(!m.frozen) continue;
        int sz = GetValueTypeSizeByType(m.valueType);
        if(m.freezeMode == FREEZE_NORMAL) {
            DbgMemWrite(m.addr, &m.freezeValue, sz);
        } else if(m.freezeMode == FREEZE_ALLOW_INC) {
            duint cur = ReadValueAtByType(m.addr, m.valueType);
            if(cur < m.freezeValue) DbgMemWrite(m.addr, &m.freezeValue, sz);
        } else if(m.freezeMode == FREEZE_ALLOW_DEC) {
            duint cur = ReadValueAtByType(m.addr, m.valueType);
            if(cur > m.freezeValue) DbgMemWrite(m.addr, &m.freezeValue, sz);
        }
    }
}

// ============================================================
// Monitor list management
// ============================================================

static void AddToMonitor(duint addr, duint value, int valueType, size_t dataLen = 0) {
    for(auto& m : g_monitoredAddrs)
        if(m.addr == addr) return;
    MonitoredAddr ma = {};
    ma.addr = addr; ma.freezeValue = value; ma.valueType = valueType;
    ma.frozen = false; ma.freezeMode = FREEZE_NORMAL; ma.dataLen = dataLen;
    g_monitoredAddrs.push_back(ma);
    if(hMsMonitorList) {
        SendMessageA(hMsMonitorList, LVM_SETITEMCOUNT, (int)g_monitoredAddrs.size(), LVSICF_NOINVALIDATEALL);
        InvalidateRect(hMsMonitorList, NULL, TRUE);
    }
}

// ============================================================
// ListView column init
// ============================================================

static void InitMemSearchListColumns(HWND hLv) {
    LVCOLUMNA col = {};
    col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    col.iSubItem = 0; col.pszText = (LPSTR)"#"; col.cx = 55;
    SendMessageA(hLv, LVM_INSERTCOLUMNA, 0, (LPARAM)&col);
    col.iSubItem = 1; col.pszText = (LPSTR)"地址"; col.cx = 200;
    SendMessageA(hLv, LVM_INSERTCOLUMNA, 1, (LPARAM)&col);
    col.iSubItem = 2; col.pszText = (LPSTR)"当前值"; col.cx = 160;
    SendMessageA(hLv, LVM_INSERTCOLUMNA, 2, (LPARAM)&col);
    col.iSubItem = 3; col.pszText = (LPSTR)"前一值"; col.cx = 160;
    SendMessageA(hLv, LVM_INSERTCOLUMNA, 3, (LPARAM)&col);
    col.iSubItem = 4; col.pszText = (LPSTR)"模块"; col.cx = 180;
    SendMessageA(hLv, LVM_INSERTCOLUMNA, 4, (LPARAM)&col);
}

static void InitMonitorListColumns(HWND hLv) {
    LVCOLUMNA col = {};
    col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    col.iSubItem = 0; col.pszText = (LPSTR)"激活"; col.cx = 55;
    SendMessageA(hLv, LVM_INSERTCOLUMNA, 0, (LPARAM)&col);
    col.iSubItem = 1; col.pszText = (LPSTR)"描述"; col.cx = 160;
    SendMessageA(hLv, LVM_INSERTCOLUMNA, 1, (LPARAM)&col);
    col.iSubItem = 2; col.pszText = (LPSTR)"地址"; col.cx = 200;
    SendMessageA(hLv, LVM_INSERTCOLUMNA, 2, (LPARAM)&col);
    col.iSubItem = 3; col.pszText = (LPSTR)"类型"; col.cx = 90;
    SendMessageA(hLv, LVM_INSERTCOLUMNA, 3, (LPARAM)&col);
    col.iSubItem = 4; col.pszText = (LPSTR)"值"; col.cx = 150;
    SendMessageA(hLv, LVM_INSERTCOLUMNA, 4, (LPARAM)&col);
}

// ============================================================
// Clipboard helper
// ============================================================

static void CopyToClipboard(HWND hWnd, const char* text) {
    if(!text || !OpenClipboard(hWnd)) return;
    EmptyClipboard();
    size_t len = strlen(text) + 1;
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, len);
    if(hMem) {
        char* p = (char*)GlobalLock(hMem);
        if(p) { memcpy(p, text, len); GlobalUnlock(hMem); }
        SetClipboardData(CF_TEXT, hMem);
    }
    CloseClipboard();
}

// ============================================================
// Window Procedure
// ============================================================

static LRESULT CALLBACK MemSearchWndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch(uMsg)
    {
    case WM_CREATE:
    {
        HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        const int panelW = 230;
        const int pad = 8;

        // Left panel - top label
        hMsLabel = CreateWindowExA(0, "STATIC", "找到: 0",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            pad, pad, 400, 20, hWnd, (HMENU)IDC_MS_LABEL, hInst, NULL);
        SendMessageA(hMsLabel, WM_SETFONT, (WPARAM)hFont, TRUE);

        // Search results list
        hMsList = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_OWNERDATA,
            pad, 32, 560, 210, hWnd, (HMENU)IDC_MS_LIST, hInst, NULL);
        SendMessageA(hMsList, WM_SETFONT, (WPARAM)hFont, TRUE);
        ListView_SetExtendedListViewStyle(hMsList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
        InitMemSearchListColumns(hMsList);

        // Buttons below search results
        HWND hAddMon = CreateWindowExA(0, "BUTTON", "添加到地址列表",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            pad, 248, 130, 24, hWnd, (HMENU)IDC_MS_ADD_MONITOR, hInst, NULL);
        SendMessageA(hAddMon, WM_SETFONT, (WPARAM)hFont, TRUE);
        HWND hAddManual = CreateWindowExA(0, "BUTTON", "手动添加地址",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            pad + 135, 248, 140, 24, hWnd, (HMENU)IDC_MS_ADD_MANUAL, hInst, NULL);
        SendMessageA(hAddManual, WM_SETFONT, (WPARAM)hFont, TRUE);

        // Address list label
        HWND hAddrLabel = CreateWindowExA(0, "STATIC", "地址列表", WS_CHILD | WS_VISIBLE,
            pad, 278, 100, 18, hWnd, (HMENU)IDC_MS_STATIC_ADDRLIST, hInst, NULL);
        SendMessageA(hAddrLabel, WM_SETFONT, (WPARAM)hFont, TRUE);

        // Monitor list
        hMsMonitorList = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_OWNERDATA,
            pad, 298, 560, 210, hWnd, (HMENU)IDC_MS_MONITOR_LIST, hInst, NULL);
        SendMessageA(hMsMonitorList, WM_SETFONT, (WPARAM)hFont, TRUE);
        ListView_SetExtendedListViewStyle(hMsMonitorList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
        InitMonitorListColumns(hMsMonitorList);

        // Right panel
        int rx = 580;
        int y = pad;
        const int pw = panelW;

        // "扫描控制" label
        HWND hScanCtrl = CreateWindowExA(0, "STATIC", "扫描控制", WS_CHILD | WS_VISIBLE | SS_LEFT,
            rx, y, 200, 18, hWnd, (HMENU)IDC_MS_STATIC_SCANCTRL, hInst, NULL);
        SendMessageA(hScanCtrl, WM_SETFONT, (WPARAM)hFont, TRUE);
        y += 22;

        // 值: label + edit + Hex checkbox
        HWND hValLbl = CreateWindowExA(0, "STATIC", "值:", WS_CHILD | WS_VISIBLE,
            rx, y + 2, 28, 20, hWnd, (HMENU)IDC_MS_STATIC_VALUE, hInst, NULL);
        SendMessageA(hValLbl, WM_SETFONT, (WPARAM)hFont, TRUE);
        hMsValueEdit = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE,
            rx + 30, y, pw - 88, 22, hWnd, (HMENU)IDC_MS_VALUE_EDIT, hInst, NULL);
        SendMessageA(hMsValueEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
        hMsHexCheck = CreateWindowExA(0, "BUTTON", "Hex", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            rx + pw - 52, y + 1, 50, 20, hWnd, (HMENU)IDC_MS_HEX, hInst, NULL);
        SendMessageA(hMsHexCheck, WM_SETFONT, (WPARAM)hFont, TRUE);
        y += 26;

        // 值2: label + edit (dynamic visibility)
        hMsValue2Label = CreateWindowExA(0, "STATIC", "值2:", WS_CHILD,
            rx, y + 2, 28, 20, hWnd, (HMENU)IDC_MS_STATIC_VALUE2, hInst, NULL);
        SendMessageA(hMsValue2Label, WM_SETFONT, (WPARAM)hFont, TRUE);
        hMsValue2Edit = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD,
            rx + 30, y, pw - 38, 22, hWnd, (HMENU)IDC_MS_VALUE2, hInst, NULL);
        SendMessageA(hMsValue2Edit, WM_SETFONT, (WPARAM)hFont, TRUE);
        y += 26;

        // 扫描类型: + 不是 checkbox
        HWND hStLbl = CreateWindowExA(0, "STATIC", "扫描类型:", WS_CHILD | WS_VISIBLE,
            rx, y + 2, 60, 20, hWnd, (HMENU)IDC_MS_STATIC_SCANTYPE, hInst, NULL);
        SendMessageA(hStLbl, WM_SETFONT, (WPARAM)hFont, TRUE);
        hMsScanTypeCombo = CreateWindowExA(0, "COMBOBOX", "", WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST,
            rx + 62, y, pw - 70, 200, hWnd, (HMENU)IDC_MS_SCAN_TYPE, hInst, NULL);
        SendMessageA(hMsScanTypeCombo, WM_SETFONT, (WPARAM)hFont, TRUE);
        PopulateScanTypeDropdown(false);
        y += 26;

        // 不是 checkbox
        hMsNotCheck = CreateWindowExA(0, "BUTTON", "不是", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            rx, y, 50, 20, hWnd, (HMENU)IDC_MS_NOT, hInst, NULL);
        SendMessageA(hMsNotCheck, WM_SETFONT, (WPARAM)hFont, TRUE);
        y += 22;

        // 数值类型:
        HWND hVtLbl = CreateWindowExA(0, "STATIC", "数值类型:", WS_CHILD | WS_VISIBLE,
            rx, y + 2, 60, 20, hWnd, (HMENU)IDC_MS_STATIC_DATATYPE, hInst, NULL);
        SendMessageA(hVtLbl, WM_SETFONT, (WPARAM)hFont, TRUE);
        hMsValueTypeCombo = CreateWindowExA(0, "COMBOBOX", "", WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST,
            rx + 62, y, pw - 70, 200, hWnd, (HMENU)IDC_MS_VALUE_TYPE, hInst, NULL);
        SendMessageA(hMsValueTypeCombo, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageA(hMsValueTypeCombo, CB_ADDSTRING, 0, (LPARAM)"字节");
        SendMessageA(hMsValueTypeCombo, CB_ADDSTRING, 0, (LPARAM)"2字节");
        SendMessageA(hMsValueTypeCombo, CB_ADDSTRING, 0, (LPARAM)"4字节");
        SendMessageA(hMsValueTypeCombo, CB_ADDSTRING, 0, (LPARAM)"8字节");
        SendMessageA(hMsValueTypeCombo, CB_ADDSTRING, 0, (LPARAM)"浮点数");
        SendMessageA(hMsValueTypeCombo, CB_ADDSTRING, 0, (LPARAM)"双浮点数");
        SendMessageA(hMsValueTypeCombo, CB_ADDSTRING, 0, (LPARAM)"字符串(ANSI)");
        SendMessageA(hMsValueTypeCombo, CB_ADDSTRING, 0, (LPARAM)"字符串(UTF-8)");
        SendMessageA(hMsValueTypeCombo, CB_ADDSTRING, 0, (LPARAM)"字符串(Unicode)");
        SendMessageA(hMsValueTypeCombo, CB_ADDSTRING, 0, (LPARAM)"字节数组");
        SendMessageA(hMsValueTypeCombo, CB_SETCURSEL, VT_4BYTE, 0);
        y += 26;

        // 浮点数取整 radio buttons
        hMsRoundDefault = CreateWindowExA(0, "BUTTON", "四舍五入(默认)", WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON | WS_GROUP,
            rx, y, 110, 20, hWnd, (HMENU)IDC_MS_ROUND_DEFAULT, hInst, NULL);
        SendMessageA(hMsRoundDefault, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageA(hMsRoundDefault, BM_SETCHECK, BST_CHECKED, 0);
        hMsRoundRounded = CreateWindowExA(0, "BUTTON", "极端", WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON,
            rx + 112, y, 50, 20, hWnd, (HMENU)IDC_MS_ROUND_ROUNDED, hInst, NULL);
        SendMessageA(hMsRoundRounded, WM_SETFONT, (WPARAM)hFont, TRUE);
        hMsRoundTrunc = CreateWindowExA(0, "BUTTON", "截断", WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON,
            rx + 164, y, 50, 20, hWnd, (HMENU)IDC_MS_ROUND_TRUNC, hInst, NULL);
        SendMessageA(hMsRoundTrunc, WM_SETFONT, (WPARAM)hFont, TRUE);
        y += 22;

        // 可写 + 可执行
        hMsWritableCheck = CreateWindowExA(0, "BUTTON", "可写", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX | WS_GROUP,
            rx, y, 60, 20, hWnd, (HMENU)IDC_MS_WRITABLE, hInst, NULL);
        SendMessageA(hMsWritableCheck, WM_SETFONT, (WPARAM)hFont, TRUE);
        hMsExecutableCheck = CreateWindowExA(0, "BUTTON", "可执行", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            rx + 65, y, 70, 20, hWnd, (HMENU)IDC_MS_EXECUTABLE, hInst, NULL);
        SendMessageA(hMsExecutableCheck, WM_SETFONT, (WPARAM)hFont, TRUE);
        y += 22;

        // 快速扫描 + 对齐
        hMsFastScanCheck = CreateWindowExA(0, "BUTTON", "快速扫描", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            rx, y, 72, 20, hWnd, (HMENU)IDC_MS_FAST_SCAN, hInst, NULL);
        SendMessageA(hMsFastScanCheck, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageA(hMsFastScanCheck, BM_SETCHECK, BST_CHECKED, 0);
        HWND hAlignLbl = CreateWindowExA(0, "STATIC", "对齐:", WS_CHILD | WS_VISIBLE,
            rx + 76, y + 2, 35, 18, hWnd, (HMENU)IDC_MS_STATIC_ALIGN, hInst, NULL);
        SendMessageA(hAlignLbl, WM_SETFONT, (WPARAM)hFont, TRUE);
        hMsAlignEdit = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "4", WS_CHILD | WS_VISIBLE,
            rx + 112, y, 36, 20, hWnd, (HMENU)IDC_MS_ALIGN_EDIT, hInst, NULL);
        SendMessageA(hMsAlignEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
        y += 24;

        // 模块:
        HWND hModLbl = CreateWindowExA(0, "STATIC", "模块:", WS_CHILD | WS_VISIBLE,
            rx, y + 2, 40, 20, hWnd, (HMENU)IDC_MS_STATIC_MODULE, hInst, NULL);
        SendMessageA(hModLbl, WM_SETFONT, (WPARAM)hFont, TRUE);
        hMsModuleCombo = CreateWindowExA(0, "COMBOBOX", "",
            WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | CBS_HASSTRINGS | WS_VSCROLL,
            rx + 42, y, pw - 50, 300, hWnd, (HMENU)IDC_MS_MODULE_FILTER, hInst, NULL);
        SendMessageA(hMsModuleCombo, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageA(hMsModuleCombo, CB_ADDSTRING, 0, (LPARAM)"全部");
        PopulateMsModuleList();
        for(const auto& m : g_msModuleList)
            SendMessageA(hMsModuleCombo, CB_ADDSTRING, 0, (LPARAM)m.name);
        SendMessageA(hMsModuleCombo, CB_SETCURSEL, 0, 0);
        y += 26;

        // 起始地址 / 终止地址 (模块下方)
        HWND hStartLbl = CreateWindowExA(0, "STATIC", "起始:", WS_CHILD | WS_VISIBLE,
            rx, y + 2, 35, 18, hWnd, (HMENU)IDC_MS_STATIC_START, hInst, NULL);
        SendMessageA(hStartLbl, WM_SETFONT, (WPARAM)hFont, TRUE);
        hMsStartAddr = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "0", WS_CHILD | WS_VISIBLE,
            rx + 36, y, pw - 44, 20, hWnd, (HMENU)IDC_MS_START_ADDR, hInst, NULL);
        SendMessageA(hMsStartAddr, WM_SETFONT, (WPARAM)hFont, TRUE);
        y += 24;

        HWND hStopLbl = CreateWindowExA(0, "STATIC", "终止:", WS_CHILD | WS_VISIBLE,
            rx, y + 2, 35, 18, hWnd, (HMENU)IDC_MS_STATIC_STOP, hInst, NULL);
        SendMessageA(hStopLbl, WM_SETFONT, (WPARAM)hFont, TRUE);
        hMsStopAddr = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "7FFFFFFFFFFF", WS_CHILD | WS_VISIBLE,
            rx + 36, y, pw - 44, 20, hWnd, (HMENU)IDC_MS_STOP_ADDR, hInst, NULL);
        SendMessageA(hMsStopAddr, WM_SETFONT, (WPARAM)hFont, TRUE);
        y += 24;

        // Progress bar
        hMsProgress = CreateWindowExA(0, PROGRESS_CLASSA, "",
            WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
            rx, y, pw - 10, 16, hWnd, (HMENU)IDC_MS_PROGRESS, hInst, NULL);
        SendMessageA(hMsProgress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
        SendMessageA(hMsProgress, PBM_SETPOS, 0, 0);
        y += 22;

        // 首次扫描/新的扫描 button
        hMsFirstScanBtn = CreateWindowExA(0, "BUTTON", "首次扫描",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            rx, y, pw - 10, 28, hWnd, (HMENU)IDC_MS_FIRST_SCAN, hInst, NULL);
        SendMessageA(hMsFirstScanBtn, WM_SETFONT, (WPARAM)hFont, TRUE);
        y += 32;

        // 下一次扫描 button
        hMsNewScanBtn = CreateWindowExA(0, "BUTTON", "下一次扫描",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            rx, y, pw - 10, 28, hWnd, (HMENU)IDC_MS_NEW_SCAN, hInst, NULL);
        SendMessageA(hMsNewScanBtn, WM_SETFONT, (WPARAM)hFont, TRUE);
        y += 32;

        // 撤销扫描 button
        hMsUndoBtn = CreateWindowExA(0, "BUTTON", "撤销扫描",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            rx, y, pw - 10, 28, hWnd, (HMENU)IDC_MS_UNDO, hInst, NULL);
        SendMessageA(hMsUndoBtn, WM_SETFONT, (WPARAM)hFont, TRUE);
        y += 32;

        // 自动刷新 checkbox
        hMsAutoRefreshCheck = CreateWindowExA(0, "BUTTON", "自动刷新", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            rx, y, pw - 10, 20, hWnd, (HMENU)IDC_MS_AUTO_REFRESH, hInst, NULL);
        SendMessageA(hMsAutoRefreshCheck, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageA(hMsAutoRefreshCheck, BM_SETCHECK, BST_CHECKED, 0);
        g_memSearchAutoRefresh = true;
        SetTimer(hWnd, IDT_AUTO_REFRESH, 500, NULL);

        // Initial button states
        UpdateButtonStates();
        UpdateValue2Visibility();
        UpdateRoundingVisibility();

        // Context menus
        hMsContextMenu = CreatePopupMenu();
        AppendMenuA(hMsContextMenu, MF_STRING, IDM_MS_COPY_ADDR, "复制地址");
        AppendMenuA(hMsContextMenu, MF_STRING, IDM_MS_COPY_VALUE, "复制值");
        AppendMenuA(hMsContextMenu, MF_SEPARATOR, 0, NULL);
        AppendMenuA(hMsContextMenu, MF_STRING, IDM_MS_GOTO_DUMP, "转到内存窗口");
        AppendMenuA(hMsContextMenu, MF_STRING, IDM_MS_GOTO_DISASM, "转到反汇编窗口");
        AppendMenuA(hMsContextMenu, MF_SEPARATOR, 0, NULL);
        AppendMenuA(hMsContextMenu, MF_STRING, IDM_MS_ADD_MONITOR, "添加到地址列表");
        AppendMenuA(hMsContextMenu, MF_STRING, IDM_MS_WRITE, "写入值");
        AppendMenuA(hMsContextMenu, MF_SEPARATOR, 0, NULL);
        AppendMenuA(hMsContextMenu, MF_STRING, IDM_MS_SEARCH_ADDR, "在内存中搜索地址");

        // Monitor context menu (built dynamically)
        hMsMonitorContextMenu = NULL;

        SetTimer(hWnd, IDT_FREEZE, 100, NULL);
        return 0;
    }

    case WM_TIMER:
        if(wParam == IDT_FREEZE)
            ApplyFreeze();
        else if(wParam == IDT_AUTO_REFRESH) {
            if(hMsList && g_memSearchResults.size() > 0) InvalidateRect(hMsList, NULL, FALSE);
            if(hMsMonitorList && g_monitoredAddrs.size() > 0) InvalidateRect(hMsMonitorList, NULL, FALSE);
        }
        return 0;

    case WM_SIZE:
    {
        int w = LOWORD(lParam);
        int h = HIWORD(lParam);
        const int panelW = 230;
        int leftW = w - panelW - 16;
        if(leftW < 100) leftW = 100;
        int rx = leftW + 8;
        int resultsH = (h - 110) / 2;
        if(resultsH < 60) resultsH = 60;

        if(hMsLabel) MoveWindow(hMsLabel, 8, 8, leftW - 8, 20, TRUE);
        if(hMsList) MoveWindow(hMsList, 8, 32, leftW - 8, resultsH - 10, TRUE);

        int btnY = 32 + resultsH - 6;
        HWND hAddMon = GetDlgItem(hWnd, IDC_MS_ADD_MONITOR);
        HWND hAddManual = GetDlgItem(hWnd, IDC_MS_ADD_MANUAL);
        if(hAddMon) MoveWindow(hAddMon, 8, btnY, 130, 24, TRUE);
        if(hAddManual) MoveWindow(hAddManual, 143, btnY, 140, 24, TRUE);

        int addrLblY = btnY + 28;
        HWND hAddrLabel = GetDlgItem(hWnd, IDC_MS_STATIC_ADDRLIST);
        if(hAddrLabel) MoveWindow(hAddrLabel, 8, addrLblY, 100, 18, TRUE);

        int monTop = addrLblY + 20;
        if(hMsMonitorList) MoveWindow(hMsMonitorList, 8, monTop, leftW - 8, h - monTop - 8, TRUE);

        // Right panel layout
        int y = 8;
        int pw = panelW;
        HWND hCtrl;
        hCtrl = GetDlgItem(hWnd, IDC_MS_STATIC_SCANCTRL);
        if(hCtrl) MoveWindow(hCtrl, rx, y, 200, 18, TRUE);
        y += 22;

        // 值: + edit + Hex
        hCtrl = GetDlgItem(hWnd, IDC_MS_STATIC_VALUE);
        if(hCtrl) MoveWindow(hCtrl, rx, y + 2, 28, 20, TRUE);
        if(hMsValueEdit) MoveWindow(hMsValueEdit, rx + 30, y, pw - 88, 22, TRUE);
        if(hMsHexCheck) MoveWindow(hMsHexCheck, rx + pw - 52, y + 1, 50, 20, TRUE);
        y += 26;

        // 值2:
        if(hMsValue2Label) MoveWindow(hMsValue2Label, rx, y + 2, 28, 20, TRUE);
        if(hMsValue2Edit) MoveWindow(hMsValue2Edit, rx + 30, y, pw - 38, 22, TRUE);
        y += 26;

        // 扫描类型:
        hCtrl = GetDlgItem(hWnd, IDC_MS_STATIC_SCANTYPE);
        if(hCtrl) MoveWindow(hCtrl, rx, y + 2, 60, 20, TRUE);
        if(hMsScanTypeCombo) MoveWindow(hMsScanTypeCombo, rx + 62, y, pw - 70, 200, TRUE);
        y += 26;

        // 不是
        if(hMsNotCheck) MoveWindow(hMsNotCheck, rx, y, 50, 20, TRUE);
        y += 22;

        // 数值类型:
        hCtrl = GetDlgItem(hWnd, IDC_MS_STATIC_DATATYPE);
        if(hCtrl) MoveWindow(hCtrl, rx, y + 2, 60, 20, TRUE);
        if(hMsValueTypeCombo) MoveWindow(hMsValueTypeCombo, rx + 62, y, pw - 70, 200, TRUE);
        y += 26;

        // 浮点取整
        if(hMsRoundDefault) MoveWindow(hMsRoundDefault, rx, y, 110, 20, TRUE);
        if(hMsRoundRounded) MoveWindow(hMsRoundRounded, rx + 112, y, 50, 20, TRUE);
        if(hMsRoundTrunc) MoveWindow(hMsRoundTrunc, rx + 164, y, 50, 20, TRUE);
        y += 22;

        // 可写 + 可执行
        if(hMsWritableCheck) MoveWindow(hMsWritableCheck, rx, y, 60, 20, TRUE);
        if(hMsExecutableCheck) MoveWindow(hMsExecutableCheck, rx + 65, y, 70, 20, TRUE);
        y += 22;

        // 快速扫描 + 对齐
        if(hMsFastScanCheck) MoveWindow(hMsFastScanCheck, rx, y, 72, 20, TRUE);
        hCtrl = GetDlgItem(hWnd, IDC_MS_STATIC_ALIGN);
        if(hCtrl) MoveWindow(hCtrl, rx + 76, y + 2, 35, 18, TRUE);
        if(hMsAlignEdit) MoveWindow(hMsAlignEdit, rx + 112, y, 36, 20, TRUE);
        y += 24;

        // 模块:
        hCtrl = GetDlgItem(hWnd, IDC_MS_STATIC_MODULE);
        if(hCtrl) MoveWindow(hCtrl, rx, y + 2, 40, 20, TRUE);
        if(hMsModuleCombo) MoveWindow(hMsModuleCombo, rx + 42, y, pw - 50, 300, TRUE);
        y += 26;

        // 起始/终止地址
        hCtrl = GetDlgItem(hWnd, IDC_MS_STATIC_START);
        if(hCtrl) MoveWindow(hCtrl, rx, y + 2, 35, 18, TRUE);
        if(hMsStartAddr) MoveWindow(hMsStartAddr, rx + 36, y, pw - 44, 20, TRUE);
        y += 24;
        hCtrl = GetDlgItem(hWnd, IDC_MS_STATIC_STOP);
        if(hCtrl) MoveWindow(hCtrl, rx, y + 2, 35, 18, TRUE);
        if(hMsStopAddr) MoveWindow(hMsStopAddr, rx + 36, y, pw - 44, 20, TRUE);
        y += 24;

        if(hMsProgress) MoveWindow(hMsProgress, rx, y, pw - 10, 16, TRUE);
        y += 22;

        if(hMsFirstScanBtn) MoveWindow(hMsFirstScanBtn, rx, y, pw - 10, 28, TRUE);
        y += 32;
        if(hMsNewScanBtn) MoveWindow(hMsNewScanBtn, rx, y, pw - 10, 28, TRUE);
        y += 32;
        if(hMsUndoBtn) MoveWindow(hMsUndoBtn, rx, y, pw - 10, 28, TRUE);
        y += 32;
        if(hMsAutoRefreshCheck) MoveWindow(hMsAutoRefreshCheck, rx, y, pw - 10, 20, TRUE);
        return 0;
    }

    case WM_NOTIFY:
    {
        NMHDR* nmhdr = (NMHDR*)lParam;

        // Custom draw for red highlight on changed values in search results
        if(nmhdr->idFrom == IDC_MS_LIST && nmhdr->code == NM_CUSTOMDRAW) {
            NMLVCUSTOMDRAW* pcd = (NMLVCUSTOMDRAW*)lParam;
            switch(pcd->nmcd.dwDrawStage) {
            case CDDS_PREPAINT:
                return CDRF_NOTIFYITEMDRAW;
            case CDDS_ITEMPREPAINT:
            {
                int idx = (int)pcd->nmcd.dwItemSpec;
                if(idx >= 0 && idx < (int)g_memSearchResults.size()) {
                    auto& r = g_memSearchResults[idx];
                    if(r.curValue != r.prevValue)
                        pcd->clrText = RGB(255, 0, 0);
                }
                return CDRF_DODEFAULT;
            }
            }
            return CDRF_DODEFAULT;
        }

        if(nmhdr->idFrom == IDC_MS_LIST) {
            if(nmhdr->code == LVN_GETDISPINFOA) {
                NMLVDISPINFOA* pdi = (NMLVDISPINFOA*)lParam;
                int i = pdi->item.iItem;
                int sub = pdi->item.iSubItem;
                if(i >= 0 && i < (int)g_memSearchResults.size() && (pdi->item.mask & LVIF_TEXT)) {
                    auto& r = g_memSearchResults[i];
                    // Read current value for display
                    if(IsAoBType()) {
                        unsigned char tmp[8] = {};
                        size_t toRead = (g_aobPatternLen < 8) ? g_aobPatternLen : 8;
                        if(DbgMemRead(r.addr, tmp, (duint)toRead)) memcpy(&r.curValue, tmp, toRead);
                    } else if(IsStringType()) {
                        unsigned char tmp[8] = {};
                        size_t patLen = g_stringPattern.size();
                        if(patLen > 0 && patLen <= 8 && DbgMemRead(r.addr, tmp, (duint)patLen))
                            memcpy(&r.curValue, tmp, patLen);
                    } else {
                        r.curValue = ReadValueAt(r.addr);
                    }

                    char modName[MAX_MODULE_SIZE] = {};
                    switch(sub) {
                    case 0: sprintf_s(g_msLvBuf, "%d", i + 1); break;
                    case 1: sprintf_s(g_msLvBuf, "%016llX", (unsigned long long)r.addr); break;
                    case 2:
                        if(IsAoBType()) FormatAoBForDisplay(r.addr, g_aobPatternLen, g_msLvBuf, MS_LV_BUF);
                        else if(IsStringType()) {
                            unsigned char sbuf[256] = {};
                            if(DbgMemRead(r.addr, sbuf, sizeof(sbuf))) {
                                std::string s = DecodeBytesToString(sbuf, sizeof(sbuf), g_memSearchValueType);
                                strncpy_s(g_msLvBuf, s.c_str(), MS_LV_BUF - 1);
                                for(size_t k = 0; g_msLvBuf[k]; k++)
                                    if((unsigned char)g_msLvBuf[k] < 32) g_msLvBuf[k] = '.';
                            } else g_msLvBuf[0] = 0;
                        } else FormatValueForDisplay(r.curValue, g_msLvBuf, MS_LV_BUF);
                        break;
                    case 3:
                        if(IsAoBType()) {
                            // Show previous first 8 bytes as hex
                            unsigned char prev[8] = {};
                            memcpy(prev, &r.prevValue, 8);
                            g_msLvBuf[0] = 0;
                            size_t show = (g_aobPatternLen < 8) ? g_aobPatternLen : 8;
                            for(size_t k = 0; k < show; k++) {
                                char hex[4]; sprintf_s(hex, "%02X ", prev[k]);
                                strcat_s(g_msLvBuf, MS_LV_BUF, hex);
                            }
                        } else if(IsStringType()) {
                            strcpy_s(g_msLvBuf, "(string)");
                        } else FormatValueForDisplay(r.prevValue, g_msLvBuf, MS_LV_BUF);
                        break;
                    case 4:
                        DbgGetModuleAt(r.addr, modName);
                        strncpy_s(g_msLvBuf, modName, MS_LV_BUF - 1);
                        break;
                    default: g_msLvBuf[0] = 0; break;
                    }
                    pdi->item.pszText = g_msLvBuf;
                }
                return 0;
            }
            if(nmhdr->code == NM_DBLCLK) {
                NMITEMACTIVATE* nmia = (NMITEMACTIVATE*)lParam;
                int idx = nmia->iItem;
                if(idx >= 0 && idx < (int)g_memSearchResults.size()) {
                    GuiDumpAt(g_memSearchResults[idx].addr);
                    GuiShowCpu();
                }
            }
            if(nmhdr->code == NM_RCLICK) {
                NMITEMACTIVATE* nmia = (NMITEMACTIVATE*)lParam;
                int idx = nmia->iItem;
                if(idx >= 0) {
                    int sel = (int)SendMessageA(hMsList, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
                    if(sel < 0) {
                        LVITEMA lvi = {};
                        lvi.stateMask = LVIS_SELECTED | LVIS_FOCUSED;
                        lvi.state = LVIS_SELECTED | LVIS_FOCUSED;
                        SendMessageA(hMsList, LVM_SETITEMSTATE, idx, (LPARAM)&lvi);
                    }
                }
                SetForegroundWindow(GetAncestor(hWnd, GA_ROOT));
                POINT pt; GetCursorPos(&pt);
                int cmd = (int)TrackPopupMenu(hMsContextMenu, TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RETURNCMD,
                    pt.x, pt.y, 0, hWnd, NULL);
                int sel = (int)SendMessageA(hMsList, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
                if(sel >= 0 && sel < (int)g_memSearchResults.size()) {
                    duint addr = g_memSearchResults[sel].addr;
                    if(cmd == IDM_MS_COPY_ADDR) {
                        char buf[32]; sprintf_s(buf, "%016llX", (unsigned long long)addr);
                        CopyToClipboard(hWnd, buf);
                    } else if(cmd == IDM_MS_COPY_VALUE) {
                        char buf[256];
                        if(IsAoBType()) FormatAoBForDisplay(addr, g_aobPatternLen, buf, sizeof(buf));
                        else if(IsStringType()) {
                            unsigned char sbuf[256] = {};
                            DbgMemRead(addr, sbuf, sizeof(sbuf));
                            std::string s = DecodeBytesToString(sbuf, sizeof(sbuf), g_memSearchValueType);
                            strncpy_s(buf, s.c_str(), sizeof(buf) - 1);
                        } else FormatValueForDisplay(g_memSearchResults[sel].curValue, buf, sizeof(buf));
                        CopyToClipboard(hWnd, buf);
                    } else if(cmd == IDM_MS_GOTO_DUMP) {
                        GuiDumpAt(addr); GuiShowCpu();
                    } else if(cmd == IDM_MS_GOTO_DISASM) {
                        GuiDisasmAt(addr, 0); GuiShowCpu();
                    } else if(cmd == IDM_MS_ADD_MONITOR) {
                        if(IsAoBType()) {
                            AddToMonitor(addr, 0, g_memSearchValueType, g_aobPatternLen);
                        } else if(IsStringType()) {
                            AddToMonitor(addr, 0, g_memSearchValueType, g_stringPattern.size());
                        } else {
                            duint cur = ReadValueAt(addr);
                            AddToMonitor(addr, cur, g_memSearchValueType);
                        }
                    } else if(cmd == IDM_MS_WRITE) {
                        char valStr[512] = {};
                        GetWindowTextA(hMsValueEdit, valStr, sizeof(valStr));
                        if(IsStringType()) {
                            std::vector<unsigned char> pattern;
                            if(EncodeStringToBytes(valStr, pattern, g_memSearchValueType) && !pattern.empty())
                                DbgMemWrite(addr, pattern.data(), (duint)pattern.size());
                            else SetWindowTextA(hMsLabel, "请输入有效字符串");
                        } else if(IsAoBType()) {
                            std::vector<uint8_t> pat; std::vector<bool> wc;
                            if(ParseAoBPattern(valStr, pat, wc) && !pat.empty())
                                DbgMemWrite(addr, pat.data(), (duint)pat.size());
                            else SetWindowTextA(hMsLabel, "请输入有效字节数组");
                        } else {
                            duint newVal = 0;
                            if(ParseSearchValue(valStr, &newVal)) {
                                DbgMemWrite(addr, &newVal, GetValueTypeSize());
                                g_memSearchResults[sel].curValue = newVal;
                            } else SetWindowTextA(hMsLabel, "请在输入框中输入值");
                        }
                        InvalidateRect(hMsList, NULL, FALSE);
                    } else if(cmd == IDM_MS_SEARCH_ADDR) {
                        SetWindowTextA(hMsLabel, "搜索引用中...");
                        GuiProcessEvents();
                        SearchAddressInMemory(addr);
                    }
                }
            }
        }
        else if(nmhdr->idFrom == IDC_MS_MONITOR_LIST) {
            if(nmhdr->code == LVN_GETDISPINFOA) {
                NMLVDISPINFOA* pdi = (NMLVDISPINFOA*)lParam;
                int i = pdi->item.iItem;
                int sub = pdi->item.iSubItem;
                if(i >= 0 && i < (int)g_monitoredAddrs.size() && (pdi->item.mask & LVIF_TEXT)) {
                    auto& m = g_monitoredAddrs[i];
                    bool isStr = (m.valueType == VT_STRING_ANSI || m.valueType == VT_STRING_UTF8 || m.valueType == VT_STRING_UNICODE);
                    bool isAoB = (m.valueType == VT_AOB);
                    if(!isStr && !isAoB) {
                        duint curVal = ReadValueAtByType(m.addr, m.valueType);
                        if(!m.frozen) m.freezeValue = curVal;
                    }
                    switch(sub) {
                    case 0:
                        if(m.frozen) {
                            if(m.freezeMode == FREEZE_ALLOW_INC) strcpy_s(g_msLvBuf2, "Inc");
                            else if(m.freezeMode == FREEZE_ALLOW_DEC) strcpy_s(g_msLvBuf2, "Dec");
                            else strcpy_s(g_msLvBuf2, "Yes");
                        } else g_msLvBuf2[0] = 0;
                        break;
                    case 1: strncpy_s(g_msLvBuf2, m.description.c_str(), MS_LV_BUF - 1); break;
                    case 2: sprintf_s(g_msLvBuf2, "%016llX", (unsigned long long)m.addr); break;
                    case 3: strncpy_s(g_msLvBuf2, GetValueTypeName(m.valueType), MS_LV_BUF - 1); break;
                    case 4:
                        if(isAoB) {
                            size_t len = m.dataLen > 0 ? m.dataLen : 8;
                            FormatAoBForDisplay(m.addr, len, g_msLvBuf2, MS_LV_BUF);
                        } else if(isStr) {
                            unsigned char sbuf[256] = {};
                            if(DbgMemRead(m.addr, sbuf, sizeof(sbuf))) {
                                std::string s = DecodeBytesToString(sbuf, sizeof(sbuf), m.valueType);
                                strncpy_s(g_msLvBuf2, s.c_str(), MS_LV_BUF - 1);
                                for(size_t k = 0; g_msLvBuf2[k]; k++)
                                    if((unsigned char)g_msLvBuf2[k] < 32) g_msLvBuf2[k] = '.';
                            } else g_msLvBuf2[0] = 0;
                        } else {
                            duint curVal = ReadValueAtByType(m.addr, m.valueType);
                            FormatValueByType(curVal, m.valueType, g_msLvBuf2, MS_LV_BUF);
                        }
                        break;
                    default: g_msLvBuf2[0] = 0; break;
                    }
                    pdi->item.pszText = g_msLvBuf2;
                }
                return 0;
            }
            if(nmhdr->code == NM_DBLCLK) {
                NMITEMACTIVATE* nmia = (NMITEMACTIVATE*)lParam;
                int idx = nmia->iItem;
                if(idx >= 0 && idx < (int)g_monitoredAddrs.size()) {
                    GuiDumpAt(g_monitoredAddrs[idx].addr); GuiShowCpu();
                }
            }
            if(nmhdr->code == NM_RCLICK) {
                NMITEMACTIVATE* nmia = (NMITEMACTIVATE*)lParam;
                int idx = nmia->iItem;
                if(idx >= 0) {
                    int sel = (int)SendMessageA(hMsMonitorList, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
                    if(sel < 0) {
                        LVITEMA lvi = {};
                        lvi.stateMask = LVIS_SELECTED | LVIS_FOCUSED;
                        lvi.state = LVIS_SELECTED | LVIS_FOCUSED;
                        SendMessageA(hMsMonitorList, LVM_SETITEMSTATE, idx, (LPARAM)&lvi);
                    }
                }
                // Build dynamic context menu
                HMENU hMenu = CreatePopupMenu();
                AppendMenuA(hMenu, MF_STRING, IDM_MS_FREEZE, "切换冻结");
                HMENU hFreezeMode = CreatePopupMenu();
                AppendMenuA(hFreezeMode, MF_STRING, IDM_MS_FREEZE_NORMAL, "正常");
                AppendMenuA(hFreezeMode, MF_STRING, IDM_MS_FREEZE_ALLOW_INC, "允许增加");
                AppendMenuA(hFreezeMode, MF_STRING, IDM_MS_FREEZE_ALLOW_DEC, "允许减少");
                AppendMenuA(hMenu, MF_POPUP, (UINT_PTR)hFreezeMode, "冻结模式");
                AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);
                AppendMenuA(hMenu, MF_STRING, IDM_MS_EDIT_DESC, "编辑描述");
                AppendMenuA(hMenu, MF_STRING, IDM_MS_EDIT_VALUE, "编辑值");
                HMENU hVtMenu = CreatePopupMenu();
                AppendMenuA(hVtMenu, MF_STRING, IDM_MS_MON_VT_1BYTE, "字节");
                AppendMenuA(hVtMenu, MF_STRING, IDM_MS_MON_VT_2BYTE, "2字节");
                AppendMenuA(hVtMenu, MF_STRING, IDM_MS_MON_VT_4BYTE, "4字节");
                AppendMenuA(hVtMenu, MF_STRING, IDM_MS_MON_VT_8BYTE, "8字节");
                AppendMenuA(hVtMenu, MF_STRING, IDM_MS_MON_VT_FLOAT, "浮点数");
                AppendMenuA(hVtMenu, MF_STRING, IDM_MS_MON_VT_DOUBLE, "双浮点数");
                AppendMenuA(hVtMenu, MF_SEPARATOR, 0, NULL);
                AppendMenuA(hVtMenu, MF_STRING, IDM_MS_MON_VT_ANSI, "字符串(ANSI)");
                AppendMenuA(hVtMenu, MF_STRING, IDM_MS_MON_VT_UTF8, "字符串(UTF-8)");
                AppendMenuA(hVtMenu, MF_STRING, IDM_MS_MON_VT_UNICODE, "字符串(Unicode)");
                AppendMenuA(hVtMenu, MF_STRING, IDM_MS_MON_VT_AOB, "字节数组");
                AppendMenuA(hMenu, MF_POPUP, (UINT_PTR)hVtMenu, "更改数值类型");
                AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);
                AppendMenuA(hMenu, MF_STRING, IDM_MS_MON_GOTO_DUMP, "转到内存窗口");
                AppendMenuA(hMenu, MF_STRING, IDM_MS_MON_GOTO_DISASM, "转到反汇编窗口");
                AppendMenuA(hMenu, MF_STRING, IDM_MS_MON_COPY_ADDR, "复制地址");
                AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);
                AppendMenuA(hMenu, MF_STRING, IDM_MS_DEL_MONITOR, "删除");

                SetForegroundWindow(GetAncestor(hWnd, GA_ROOT));
                POINT pt; GetCursorPos(&pt);
                int cmd = (int)TrackPopupMenu(hMenu, TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RETURNCMD,
                    pt.x, pt.y, 0, hWnd, NULL);
                DestroyMenu(hMenu);

                int sel = (int)SendMessageA(hMsMonitorList, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
                if(sel >= 0 && sel < (int)g_monitoredAddrs.size()) {
                    auto& mon = g_monitoredAddrs[sel];
                    if(cmd == IDM_MS_FREEZE) {
                        mon.frozen = !mon.frozen;
                        if(mon.frozen) mon.freezeValue = ReadValueAtByType(mon.addr, mon.valueType);
                        InvalidateRect(hMsMonitorList, NULL, FALSE);
                    } else if(cmd == IDM_MS_FREEZE_NORMAL) {
                        mon.freezeMode = FREEZE_NORMAL;
                        InvalidateRect(hMsMonitorList, NULL, FALSE);
                    } else if(cmd == IDM_MS_FREEZE_ALLOW_INC) {
                        mon.freezeMode = FREEZE_ALLOW_INC;
                        InvalidateRect(hMsMonitorList, NULL, FALSE);
                    } else if(cmd == IDM_MS_FREEZE_ALLOW_DEC) {
                        mon.freezeMode = FREEZE_ALLOW_DEC;
                        InvalidateRect(hMsMonitorList, NULL, FALSE);
                    } else if(cmd == IDM_MS_EDIT_DESC) {
                        char valStr[256] = {};
                        GetWindowTextA(hMsValueEdit, valStr, sizeof(valStr));
                        mon.description = valStr;
                        InvalidateRect(hMsMonitorList, NULL, FALSE);
                    } else if(cmd == IDM_MS_EDIT_VALUE) {
                        char valStr[64] = {};
                        GetWindowTextA(hMsValueEdit, valStr, sizeof(valStr));
                        duint newVal = 0;
                        int savedVt = g_memSearchValueType;
                        g_memSearchValueType = mon.valueType;
                        if(ParseSearchValue(valStr, &newVal)) {
                            mon.freezeValue = newVal;
                            DbgMemWrite(mon.addr, &newVal, GetValueTypeSizeByType(mon.valueType));
                        }
                        g_memSearchValueType = savedVt;
                        InvalidateRect(hMsMonitorList, NULL, FALSE);
                    } else if(cmd == IDM_MS_MON_VT_1BYTE) { mon.valueType = VT_1BYTE; InvalidateRect(hMsMonitorList, NULL, FALSE); }
                    else if(cmd == IDM_MS_MON_VT_2BYTE) { mon.valueType = VT_2BYTE; InvalidateRect(hMsMonitorList, NULL, FALSE); }
                    else if(cmd == IDM_MS_MON_VT_4BYTE) { mon.valueType = VT_4BYTE; InvalidateRect(hMsMonitorList, NULL, FALSE); }
                    else if(cmd == IDM_MS_MON_VT_8BYTE) { mon.valueType = VT_8BYTE; InvalidateRect(hMsMonitorList, NULL, FALSE); }
                    else if(cmd == IDM_MS_MON_VT_FLOAT) { mon.valueType = VT_FLOAT; InvalidateRect(hMsMonitorList, NULL, FALSE); }
                    else if(cmd == IDM_MS_MON_VT_DOUBLE) { mon.valueType = VT_DOUBLE; InvalidateRect(hMsMonitorList, NULL, FALSE); }
                    else if(cmd == IDM_MS_MON_VT_ANSI) { mon.valueType = VT_STRING_ANSI; InvalidateRect(hMsMonitorList, NULL, FALSE); }
                    else if(cmd == IDM_MS_MON_VT_UTF8) { mon.valueType = VT_STRING_UTF8; InvalidateRect(hMsMonitorList, NULL, FALSE); }
                    else if(cmd == IDM_MS_MON_VT_UNICODE) { mon.valueType = VT_STRING_UNICODE; InvalidateRect(hMsMonitorList, NULL, FALSE); }
                    else if(cmd == IDM_MS_MON_VT_AOB) { mon.valueType = VT_AOB; InvalidateRect(hMsMonitorList, NULL, FALSE); }
                    else if(cmd == IDM_MS_MON_GOTO_DUMP) { GuiDumpAt(mon.addr); GuiShowCpu(); }
                    else if(cmd == IDM_MS_MON_GOTO_DISASM) { GuiDisasmAt(mon.addr, 0); GuiShowCpu(); }
                    else if(cmd == IDM_MS_MON_COPY_ADDR) {
                        char buf[32]; sprintf_s(buf, "%016llX", (unsigned long long)mon.addr);
                        CopyToClipboard(hWnd, buf);
                    } else if(cmd == IDM_MS_DEL_MONITOR) {
                        g_monitoredAddrs.erase(g_monitoredAddrs.begin() + sel);
                        SendMessageA(hMsMonitorList, LVM_SETITEMCOUNT, (int)g_monitoredAddrs.size(), LVSICF_NOINVALIDATEALL);
                        InvalidateRect(hMsMonitorList, NULL, TRUE);
                    }
                }
            }
        }
        return 0;
    }

    case WM_COMMAND:
    {
        WORD id = LOWORD(wParam);
        WORD notify = HIWORD(wParam);

        if(id == IDC_MS_VALUE_TYPE && notify == CBN_SELCHANGE) {
            g_memSearchValueType = (int)SendMessageA(hMsValueTypeCombo, CB_GETCURSEL, 0, 0);
            if(hMsAlignEdit && !IsStringType() && !IsAoBType()) {
                char buf[8]; sprintf_s(buf, "%d", GetDefaultAlignment());
                SetWindowTextA(hMsAlignEdit, buf);
            }
            UpdateRoundingVisibility();
        }
        else if(id == IDC_MS_SCAN_TYPE && notify == CBN_SELCHANGE) {
            int idx = (int)SendMessageA(hMsScanTypeCombo, CB_GETCURSEL, 0, 0);
            g_memSearchScanType = DropdownIndexToScanType(idx, g_isNextScanMode);
            UpdateValue2Visibility();
        }
        else if(id == IDC_MS_HEX)
            g_memSearchHex = (SendMessageA(hMsHexCheck, BM_GETCHECK, 0, 0) == BST_CHECKED);
        else if(id == IDC_MS_WRITABLE)
            g_memSearchWritableOnly = (SendMessageA(hMsWritableCheck, BM_GETCHECK, 0, 0) == BST_CHECKED);
        else if(id == IDC_MS_FAST_SCAN)
            g_memSearchFastScan = (SendMessageA(hMsFastScanCheck, BM_GETCHECK, 0, 0) == BST_CHECKED);
        else if(id == IDC_MS_MODULE_FILTER && notify == CBN_SELCHANGE) {
            g_memSearchModuleFilter = (int)SendMessageA(hMsModuleCombo, CB_GETCURSEL, 0, 0) - 1;
            if(g_memSearchModuleFilter >= 0 && g_memSearchModuleFilter < (int)g_msModuleList.size()) {
                const auto& mod = g_msModuleList[g_memSearchModuleFilter];
                char buf[32];
                sprintf_s(buf, "%llX", (unsigned long long)mod.base);
                if(hMsStartAddr) SetWindowTextA(hMsStartAddr, buf);
                sprintf_s(buf, "%llX", (unsigned long long)(mod.base + mod.size));
                if(hMsStopAddr) SetWindowTextA(hMsStopAddr, buf);
            } else {
                if(hMsStartAddr) SetWindowTextA(hMsStartAddr, "0");
                if(hMsStopAddr) SetWindowTextA(hMsStopAddr, "7FFFFFFFFFFF");
            }
        }
        else if(id == IDC_MS_AUTO_REFRESH) {
            g_memSearchAutoRefresh = (SendMessageA(hMsAutoRefreshCheck, BM_GETCHECK, 0, 0) == BST_CHECKED);
            if(g_memSearchAutoRefresh) SetTimer(hWnd, IDT_AUTO_REFRESH, 500, NULL);
            else KillTimer(hWnd, IDT_AUTO_REFRESH);
        }
        else if(id == IDC_MS_FIRST_SCAN) {
            // CE behavior: this button is "First Scan" initially, becomes "New Scan" (reset)
            if(!g_isNextScanMode)
                MemSearchFirstScan();
            else
                MemSearchNewScan();
        }
        else if(id == IDC_MS_NEW_SCAN) {
            // CE behavior: this is the "Next Scan" button
            MemSearchNextScan();
        }
        else if(id == IDC_MS_UNDO)
            MemSearchUndo();
        else if(id == IDC_MS_EXECUTABLE)
            g_memSearchExecutableOnly = (SendMessageA(hMsExecutableCheck, BM_GETCHECK, 0, 0) == BST_CHECKED);
        else if(id == IDC_MS_NOT)
            g_scanNot = (SendMessageA(hMsNotCheck, BM_GETCHECK, 0, 0) == BST_CHECKED);
        else if(id == IDC_MS_ROUND_DEFAULT) g_roundingType = 0;
        else if(id == IDC_MS_ROUND_ROUNDED) g_roundingType = 1;
        else if(id == IDC_MS_ROUND_TRUNC) g_roundingType = 2;
        else if(id == IDC_MS_ADD_MONITOR) {
            int sel = (int)SendMessageA(hMsList, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
            int n = 0;
            while(sel >= 0 && sel < (int)g_memSearchResults.size()) {
                auto& r = g_memSearchResults[sel];
                if(IsAoBType())
                    AddToMonitor(r.addr, 0, g_memSearchValueType, g_aobPatternLen);
                else if(IsStringType())
                    AddToMonitor(r.addr, 0, g_memSearchValueType, g_stringPattern.size());
                else {
                    duint cur = ReadValueAt(r.addr);
                    AddToMonitor(r.addr, cur, g_memSearchValueType);
                }
                n++;
                sel = (int)SendMessageA(hMsList, LVM_GETNEXTITEM, sel, LVNI_SELECTED);
            }
            if(n > 0) { char msg[64]; sprintf_s(msg, "已添加 %d 条到地址列表", n); SetWindowTextA(hMsLabel, msg); }
        }
        else if(id == IDC_MS_ADD_MANUAL) {
            char buf[64] = {};
            GetWindowTextA(hMsValueEdit, buf, sizeof(buf));
            duint addr = 0;
            if(sscanf(buf, "%llx", (unsigned long long*)&addr) == 1 && addr != 0) {
                int vt = g_memSearchValueType;
                if(IsStringType() || IsAoBType()) vt = VT_4BYTE;
                duint cur = ReadValueAtByType(addr, vt);
                AddToMonitor(addr, cur, vt);
                SetWindowTextA(hMsLabel, "已添加到地址列表");
            } else {
                SetWindowTextA(hMsLabel, "请在值框中输入地址(十六进制)");
            }
        }
        return 0;
    }

    case WM_CLOSE:
        ShowWindow(hWnd, SW_HIDE);
        return 0;

    case WM_DESTROY:
        KillTimer(hWnd, IDT_FREEZE);
        KillTimer(hWnd, IDT_AUTO_REFRESH);
        g_memSearchAutoRefresh = false;
        hMemSearchWnd = NULL; hMsValueEdit = NULL; hMsValueTypeCombo = NULL;
        hMsScanTypeCombo = NULL; hMsValue2Edit = NULL; hMsValue2Label = NULL;
        hMsList = NULL; hMsMonitorList = NULL; hMsModuleCombo = NULL;
        hMsLabel = NULL; hMsHexCheck = NULL; hMsWritableCheck = NULL;
        hMsProgress = NULL; hMsFastScanCheck = NULL; hMsAlignEdit = NULL;
        hMsFirstScanBtn = NULL; hMsNewScanBtn = NULL; hMsUndoBtn = NULL;
        hMsAutoRefreshCheck = NULL;
        hMsNotCheck = NULL; hMsRoundDefault = NULL; hMsRoundRounded = NULL;
        hMsRoundTrunc = NULL; hMsStartAddr = NULL; hMsStopAddr = NULL;
        hMsExecutableCheck = NULL; hMsFsmAligned = NULL; hMsFsmLastDigits = NULL;
        if(hMsContextMenu) { DestroyMenu(hMsContextMenu); hMsContextMenu = NULL; }
        // hMsMonitorContextMenu is created dynamically per-click, no static handle
        return 0;
    }
    return DefWindowProcA(hWnd, uMsg, wParam, lParam);
}

// ============================================================
// Exported functions
// ============================================================

void ShowMemSearchWindow()
{
    if(hMemSearchWnd) {
        if(!IsWindowVisible(hMemSearchWnd)) ShowWindow(hMemSearchWnd, SW_SHOW);
        // Refresh module list
        PopulateMsModuleList();
        if(hMsModuleCombo && g_msModuleList.size() > 0) {
            int cur = (int)SendMessageA(hMsModuleCombo, CB_GETCURSEL, 0, 0);
            SendMessageA(hMsModuleCombo, CB_RESETCONTENT, 0, 0);
            SendMessageA(hMsModuleCombo, CB_ADDSTRING, 0, (LPARAM)"全部");
            for(const auto& m : g_msModuleList)
                SendMessageA(hMsModuleCombo, CB_ADDSTRING, 0, (LPARAM)m.name);
            int n = (int)g_msModuleList.size() + 1;
            SendMessageA(hMsModuleCombo, CB_SETCURSEL, (cur >= 0 && cur < n) ? cur : 0, 0);
            g_memSearchModuleFilter = (int)SendMessageA(hMsModuleCombo, CB_GETCURSEL, 0, 0) - 1;
        }
        SetForegroundWindow(hMemSearchWnd);
        return;
    }

    WNDCLASSEXA wc = { sizeof(WNDCLASSEXA) };
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = MemSearchWndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = "MyPluginMemSearchClass";
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    RegisterClassExA(&wc);

    hMemSearchWnd = CreateWindowExA(0, "MyPluginMemSearchClass", "内存搜索",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1275, 620,
        hwndDlg, NULL, hInst, NULL);

    ShowWindow(hMemSearchWnd, SW_SHOW);
    UpdateWindow(hMemSearchWnd);
}

void MemSearch_RegisterCallbacks(int pluginHandle)
{
    (void)pluginHandle;
}

void MemSearch_Cleanup()
{
    if(hMemSearchWnd) {
        DestroyWindow(hMemSearchWnd);
        hMemSearchWnd = NULL;
    }
    g_memSearchResults.clear();
    g_memSearchHistory.clear();
    g_monitoredAddrs.clear();
    g_msModuleList.clear();
    g_aobPattern.clear();
    g_aobWildcard.clear();
    g_stringPattern.clear();
}
