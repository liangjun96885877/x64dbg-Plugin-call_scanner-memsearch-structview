#include "plugin.h"
#include "structview.h"
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

// ============================================================
// Control IDs
// ============================================================
#define IDC_SV_ADDR_EDIT    7001
#define IDC_SV_REFRESH      7002
#define IDC_SV_STRUCT_COMBO 7003
#define IDC_SV_RELOAD_JSON  7004
#define IDC_SV_TREE         7005

// Context menu IDs
#define IDM_SV_COPY_ADDR    7101
#define IDM_SV_COPY_VALUE   7102
#define IDM_SV_GOTO_DISASM  7103
#define IDM_SV_GOTO_DUMP    7104
#define IDM_SV_FOLLOW_PTR   7105

static const char* SV_WNDCLASS = "StructViewerWndClass";
static HWND g_svHwnd = NULL;

// ============================================================
// Data Structures
// ============================================================
struct FieldDef {
    std::string name;
    int offset;
    std::string type;       // "byte","word","dword","qword","float","double","pointer","pointer_array","string","wstring","bytes"
    std::string structRef;  // pointer/pointer_array 引用的结构体名
    int countOffset;        // pointer_array: 数组长度偏移
    int countDivide;        // pointer_array: 除数
    int size;               // string/wstring/bytes 长度
    std::string encoding;   // string: "auto","ansi","utf8","utf16" (默认auto)
    bool isPointer;         // true: 该偏移存的是指针，需要先解引用再读值
};

struct StructDef {
    std::string name;
    std::vector<FieldDef> fields;
};

static std::map<std::string, StructDef> g_structDefs;
static std::vector<std::string> g_structNames; // 保持顺序

// Per-node data stored via TVITEM.lParam
struct TreeNodeData {
    duint addr;         // 节点对应的内存地址
    std::string value;  // 显示的值文本
    std::string type;   // 字段类型
    duint ptrTarget;    // pointer类型指向的地址
};
static std::vector<TreeNodeData*> g_nodeData;

static void FreeAllNodeData()
{
    for(auto* p : g_nodeData) delete p;
    g_nodeData.clear();
}

// ============================================================
// Simple JSON Parser
// ============================================================
namespace json {

struct Value;
using Object = std::map<std::string, Value>;
using Array = std::vector<Value>;

enum Type { T_NULL, T_STRING, T_NUMBER, T_OBJECT, T_ARRAY };

struct Value {
    Type type = T_NULL;
    std::string str;
    double num = 0;
    Object obj;
    Array arr;

    const Value& operator[](const char* key) const {
        static Value null_val;
        if(type != T_OBJECT) return null_val;
        auto it = obj.find(key);
        return it != obj.end() ? it->second : null_val;
    }
    const Value& operator[](int idx) const {
        static Value null_val;
        if(type != T_ARRAY || idx < 0 || idx >= (int)arr.size()) return null_val;
        return arr[idx];
    }
    std::string getString(const char* def = "") const { return type == T_STRING ? str : def; }
    int getInt(int def = 0) const { return type == T_NUMBER ? (int)num : def; }
    double getDouble(double def = 0) const { return type == T_NUMBER ? num : def; }
    bool isNull() const { return type == T_NULL; }
};

struct Parser {
    const char* s;
    int pos;
    int len;

    Parser(const char* data, int length) : s(data), pos(0), len(length) {}

    void skipWS() {
        while(pos < len && (s[pos] == ' ' || s[pos] == '\t' || s[pos] == '\n' || s[pos] == '\r'))
            pos++;
    }

    char peek() { skipWS(); return pos < len ? s[pos] : 0; }
    char next() { skipWS(); return pos < len ? s[pos++] : 0; }

    bool parseValue(Value& out) {
        char c = peek();
        if(c == '"') return parseString(out);
        if(c == '{') return parseObject(out);
        if(c == '[') return parseArray(out);
        if(c == '-' || (c >= '0' && c <= '9')) return parseNumber(out);
        if(pos + 4 <= len && strncmp(s + pos, "null", 4) == 0) { pos += 4; out.type = T_NULL; return true; }
        if(pos + 4 <= len && strncmp(s + pos, "true", 4) == 0) { pos += 4; out.type = T_NUMBER; out.num = 1; return true; }
        if(pos + 5 <= len && strncmp(s + pos, "false", 5) == 0) { pos += 5; out.type = T_NUMBER; out.num = 0; return true; }
        return false;
    }

    bool parseString(Value& out) {
        if(next() != '"') return false;
        out.type = T_STRING;
        out.str.clear();
        while(pos < len) {
            char c = s[pos++];
            if(c == '"') return true;
            if(c == '\\' && pos < len) {
                char e = s[pos++];
                switch(e) {
                case '"': out.str += '"'; break;
                case '\\': out.str += '\\'; break;
                case '/': out.str += '/'; break;
                case 'n': out.str += '\n'; break;
                case 't': out.str += '\t'; break;
                case 'r': out.str += '\r'; break;
                case 'u': {
                    // skip 4 hex digits, output '?'
                    if(pos + 4 <= len) { pos += 4; out.str += '?'; }
                    break;
                }
                default: out.str += e; break;
                }
            } else {
                out.str += c;
            }
        }
        return false;
    }

    bool parseRawString(std::string& result) {
        Value v;
        if(!parseString(v)) return false;
        result = v.str;
        return true;
    }

    bool parseNumber(Value& out) {
        skipWS();
        out.type = T_NUMBER;
        int start = pos;
        // 支持 "0x" 十六进制
        if(pos + 2 < len && s[pos] == '0' && (s[pos+1] == 'x' || s[pos+1] == 'X')) {
            pos += 2;
            while(pos < len && ((s[pos] >= '0' && s[pos] <= '9') ||
                  (s[pos] >= 'a' && s[pos] <= 'f') || (s[pos] >= 'A' && s[pos] <= 'F')))
                pos++;
            out.num = (double)strtoull(s + start, NULL, 16);
        } else {
            if(s[pos] == '-') pos++;
            while(pos < len && s[pos] >= '0' && s[pos] <= '9') pos++;
            if(pos < len && s[pos] == '.') { pos++; while(pos < len && s[pos] >= '0' && s[pos] <= '9') pos++; }
            if(pos < len && (s[pos] == 'e' || s[pos] == 'E')) {
                pos++;
                if(pos < len && (s[pos] == '+' || s[pos] == '-')) pos++;
                while(pos < len && s[pos] >= '0' && s[pos] <= '9') pos++;
            }
            out.num = strtod(s + start, NULL);
        }
        return pos > start;
    }

    bool parseObject(Value& out) {
        if(next() != '{') return false;
        out.type = T_OBJECT;
        if(peek() == '}') { pos++; return true; }
        while(true) {
            std::string key;
            if(!parseRawString(key)) return false;
            if(next() != ':') return false;
            Value val;
            if(!parseValue(val)) return false;
            out.obj[key] = val;
            char c = next();
            if(c == '}') return true;
            if(c != ',') return false;
        }
    }

    bool parseArray(Value& out) {
        if(next() != '[') return false;
        out.type = T_ARRAY;
        if(peek() == ']') { pos++; return true; }
        while(true) {
            Value val;
            if(!parseValue(val)) return false;
            out.arr.push_back(val);
            char c = next();
            if(c == ']') return true;
            if(c != ',') return false;
        }
    }
};

bool parse(const char* data, int len, Value& out) {
    Parser p(data, len);
    return p.parseValue(out);
}

} // namespace json

// ============================================================
// Load Struct Definitions from JSON
// ============================================================
static bool GetPluginDir(char* buf, int bufSize)
{
    GetModuleFileNameA(hInst, buf, bufSize);
    char* slash = strrchr(buf, '\\');
    if(slash) *(slash + 1) = 0;
    return true;
}

static bool LoadStructDefs(const char* jsonPath)
{
    HANDLE hFile = CreateFileA(jsonPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if(hFile == INVALID_HANDLE_VALUE) return false;

    DWORD fileSize = GetFileSize(hFile, NULL);
    if(fileSize == 0 || fileSize > 10 * 1024 * 1024) { CloseHandle(hFile); return false; }

    std::vector<char> buf(fileSize + 1);
    DWORD bytesRead = 0;
    ReadFile(hFile, buf.data(), fileSize, &bytesRead, NULL);
    CloseHandle(hFile);
    buf[bytesRead] = 0;

    // Skip UTF-8 BOM
    const char* data = buf.data();
    int dataLen = (int)bytesRead;
    if(dataLen >= 3 && (unsigned char)data[0] == 0xEF && (unsigned char)data[1] == 0xBB && (unsigned char)data[2] == 0xBF) {
        data += 3;
        dataLen -= 3;
    }

    json::Value root;
    if(!json::parse(data, dataLen, root)) return false;

    g_structDefs.clear();
    g_structNames.clear();

    const auto& structs = root["structs"];
    if(structs.type != json::T_OBJECT) return false;

    for(auto& kv : structs.obj) {
        StructDef sd;
        sd.name = kv.first;
        const auto& fields = kv.second["fields"];
        if(fields.type != json::T_ARRAY) continue;

        for(int i = 0; i < (int)fields.arr.size(); i++) {
            const auto& f = fields.arr[i];
            FieldDef fd;
            fd.name = f["name"].getString();
            // offset 支持字符串 "0x70" 或数字 112
            if(f["offset"].type == json::T_STRING)
                fd.offset = (int)strtoul(f["offset"].getString().c_str(), NULL, 0);
            else
                fd.offset = f["offset"].getInt();
            fd.type = f["type"].getString();
            fd.structRef = f["struct"].getString();
            if(f["count_offset"].type == json::T_STRING)
                fd.countOffset = (int)strtoul(f["count_offset"].getString().c_str(), NULL, 0);
            else
                fd.countOffset = f["count_offset"].getInt();
            fd.countDivide = f["count_divide"].getInt(1);
            if(fd.countDivide <= 0) fd.countDivide = 1;
            fd.size = f["size"].getInt(64);
            fd.encoding = f["encoding"].getString("auto");
            fd.isPointer = (f["pointer"].getInt(0) != 0);
            sd.fields.push_back(fd);
        }
        g_structDefs[sd.name] = sd;
        g_structNames.push_back(sd.name);
    }
    return !g_structDefs.empty();
}

// ============================================================
// Memory Read Helpers
// ============================================================
static bool ReadMem(duint addr, void* buf, duint size)
{
    return DbgMemRead(addr, (unsigned char*)buf, size);
}

static duint ReadQword(duint addr)
{
    duint val = 0;
    ReadMem(addr, &val, 8);
    return val;
}

static DWORD ReadDword(duint addr)
{
    DWORD val = 0;
    ReadMem(addr, &val, 4);
    return val;
}

static WORD ReadWord(duint addr)
{
    WORD val = 0;
    ReadMem(addr, &val, 2);
    return val;
}

static BYTE ReadByte(duint addr)
{
    BYTE val = 0;
    ReadMem(addr, &val, 1);
    return val;
}

static float ReadFloat(duint addr)
{
    float val = 0;
    ReadMem(addr, &val, 4);
    return val;
}

static double ReadDouble(duint addr)
{
    double val = 0;
    ReadMem(addr, &val, 8);
    return val;
}

// ============================================================
// String Encoding Detection & Decoding
// ============================================================

// 检测是否为合法 UTF-8 且包含多字节序列
static bool IsValidUtf8WithMultibyte(const unsigned char* data, int len)
{
    bool hasMultibyte = false;
    int i = 0;
    while(i < len && data[i] != 0) {
        unsigned char c = data[i];
        int seqLen = 0;
        if(c < 0x80) { i++; continue; }
        else if((c & 0xE0) == 0xC0) seqLen = 2;
        else if((c & 0xF0) == 0xE0) seqLen = 3;
        else if((c & 0xF8) == 0xF0) seqLen = 4;
        else return false; // 非法首字节
        if(i + seqLen > len) return false;
        for(int j = 1; j < seqLen; j++) {
            if((data[i + j] & 0xC0) != 0x80) return false;
        }
        hasMultibyte = true;
        i += seqLen;
    }
    return hasMultibyte;
}

// 检测是否像 UTF-16LE（ASCII范围文本的特征：交替出现 \0）
static bool LooksLikeUtf16LE(const unsigned char* data, int len)
{
    if(len < 4) return false;
    // BOM 检测
    if(data[0] == 0xFF && data[1] == 0xFE) return true;
    // 统计模式：ASCII范围字符后跟 \0
    int pairs = 0, matches = 0;
    for(int i = 0; i + 1 < len && pairs < 16; i += 2, pairs++) {
        if(data[i] == 0 && data[i+1] == 0) break; // null terminator
        if(data[i] >= 0x20 && data[i] < 0x7F && data[i+1] == 0) matches++;
        // 也检测常见中文范围 (CJK Unified Ideographs: U+4E00-U+9FFF)
        else if(data[i+1] >= 0x4E && data[i+1] <= 0x9F) matches++;
    }
    return pairs > 0 && matches * 2 >= pairs; // 超过一半匹配则认为是 UTF-16LE
}

// 自动检测编码
static const char* DetectEncoding(const unsigned char* data, int len)
{
    if(LooksLikeUtf16LE(data, len)) return "utf16";
    if(IsValidUtf8WithMultibyte(data, len)) return "utf8";
    return "ansi";
}

// 将原始字节按指定编码解码为 ANSI 显示字符串
// 返回: 解码后的文本, detectedEnc: 实际使用的编码名
static std::string DecodeString(const unsigned char* raw, int rawLen, const std::string& encoding, std::string& detectedEnc)
{
    const char* enc = encoding.c_str();
    if(encoding.empty() || encoding == "auto") {
        enc = DetectEncoding(raw, rawLen);
    }
    detectedEnc = enc;

    if(strcmp(enc, "utf16") == 0) {
        const wchar_t* wdata = (const wchar_t*)raw;
        int wcharCount = rawLen / 2;
        // 找到 null terminator
        int wlen = 0;
        while(wlen < wcharCount && wdata[wlen] != 0) wlen++;
        // 转为当前代码页显示
        int needed = WideCharToMultiByte(CP_ACP, 0, wdata, wlen, NULL, 0, NULL, NULL);
        std::string result(needed, 0);
        WideCharToMultiByte(CP_ACP, 0, wdata, wlen, &result[0], needed, NULL, NULL);
        return result;
    }
    else if(strcmp(enc, "utf8") == 0) {
        // 找到 null terminator
        int slen = 0;
        while(slen < rawLen && raw[slen] != 0) slen++;
        // UTF-8 -> UTF-16 -> ANSI
        int wNeeded = MultiByteToWideChar(CP_UTF8, 0, (const char*)raw, slen, NULL, 0);
        std::vector<wchar_t> wbuf(wNeeded + 1, 0);
        MultiByteToWideChar(CP_UTF8, 0, (const char*)raw, slen, wbuf.data(), wNeeded);
        int aNeeded = WideCharToMultiByte(CP_ACP, 0, wbuf.data(), wNeeded, NULL, 0, NULL, NULL);
        std::string result(aNeeded, 0);
        WideCharToMultiByte(CP_ACP, 0, wbuf.data(), wNeeded, &result[0], aNeeded, NULL, NULL);
        return result;
    }
    else {
        // ANSI: 直接截取到 null
        int slen = 0;
        while(slen < rawLen && raw[slen] != 0) slen++;
        return std::string((const char*)raw, slen);
    }
}

// ============================================================
// TreeView Helpers
// ============================================================
static HWND g_hTree = NULL;

static HTREEITEM InsertTreeItem(HTREEITEM hParent, const char* text, TreeNodeData* data)
{
    g_nodeData.push_back(data);

    TVINSERTSTRUCTA tvis = {};
    tvis.hParent = hParent;
    tvis.hInsertAfter = TVI_LAST;
    tvis.item.mask = TVIF_TEXT | TVIF_PARAM;
    tvis.item.pszText = (LPSTR)text;
    tvis.item.lParam = (LPARAM)data;
    return (HTREEITEM)SendMessageA(g_hTree, TVM_INSERTITEMA, 0, (LPARAM)&tvis);
}

// ============================================================
// Populate TreeView
// ============================================================
static void PopulateStruct(HTREEITEM hParent, duint baseAddr, const std::string& structName, int depth)
{
    if(depth > 8) return;
    auto it = g_structDefs.find(structName);
    if(it == g_structDefs.end()) return;

    for(auto& field : it->second.fields) {
        duint fieldAddr = baseAddr + field.offset;
        char text[512];

        // "pointer": true — 该偏移存的是指针，先解引用得到实际数据地址
        duint dataAddr = fieldAddr;
        if(field.isPointer && field.type != "pointer" && field.type != "pointer_array") {
            dataAddr = ReadQword(fieldAddr);
        }

        if(field.type == "pointer") {
            duint ptrVal = ReadQword(fieldAddr);
            sprintf_s(text, "%s  +0x%X  pointer  -> 0x%llX", field.name.c_str(), field.offset, (unsigned long long)ptrVal);

            auto* nd = new TreeNodeData();
            nd->addr = fieldAddr;
            nd->value = "";
            sprintf_s(text + 0, 64, "0x%llX", (unsigned long long)ptrVal);
            nd->value = text;
            nd->type = "pointer";
            nd->ptrTarget = ptrVal;
            // 重新格式化完整文本
            sprintf_s(text, "%s  +0x%X  pointer  -> 0x%llX", field.name.c_str(), field.offset, (unsigned long long)ptrVal);

            HTREEITEM hItem = InsertTreeItem(hParent, text, nd);
            if(ptrVal && !field.structRef.empty())
                PopulateStruct(hItem, ptrVal, field.structRef, depth + 1);
        }
        else if(field.type == "pointer_array") {
            duint arrayPtr = ReadQword(fieldAddr);
            duint byteLen = ReadQword(baseAddr + field.countOffset);
            int count = (int)(byteLen / field.countDivide);
            if(count < 0) count = 0;
            if(count > 256) count = 256;

            sprintf_s(text, "%s  +0x%X  pointer_array  (%d个元素)  -> 0x%llX",
                field.name.c_str(), field.offset, count, (unsigned long long)arrayPtr);

            auto* nd = new TreeNodeData();
            nd->addr = fieldAddr;
            char tmp[64]; sprintf_s(tmp, "0x%llX", (unsigned long long)arrayPtr);
            nd->value = tmp;
            nd->type = "pointer_array";
            nd->ptrTarget = arrayPtr;

            HTREEITEM hArrayItem = InsertTreeItem(hParent, text, nd);

            for(int i = 0; i < count; i++) {
                duint elemPtr = ReadQword(arrayPtr + (duint)i * 8);
                sprintf_s(text, "[%d]  -> 0x%llX", i, (unsigned long long)elemPtr);

                auto* end2 = new TreeNodeData();
                end2->addr = arrayPtr + (duint)i * 8;
                sprintf_s(tmp, "0x%llX", (unsigned long long)elemPtr);
                end2->value = tmp;
                end2->type = "pointer";
                end2->ptrTarget = elemPtr;

                HTREEITEM hElem = InsertTreeItem(hArrayItem, text, end2);
                if(elemPtr && !field.structRef.empty())
                    PopulateStruct(hElem, elemPtr, field.structRef, depth + 1);
            }
        }
        else if(field.type == "byte") {
            BYTE val = ReadByte(dataAddr);
            if(field.isPointer)
                sprintf_s(text, "%s  +0x%X  *byte  [0x%llX]  0x%02X (%u)", field.name.c_str(), field.offset, (unsigned long long)dataAddr, val, val);
            else
                sprintf_s(text, "%s  +0x%X  byte  0x%02X (%u)", field.name.c_str(), field.offset, val, val);
            auto* nd = new TreeNodeData();
            nd->addr = dataAddr;
            char tmp[32]; sprintf_s(tmp, "0x%02X", val); nd->value = tmp;
            nd->type = "byte"; nd->ptrTarget = 0;
            InsertTreeItem(hParent, text, nd);
        }
        else if(field.type == "word") {
            WORD val = ReadWord(dataAddr);
            if(field.isPointer)
                sprintf_s(text, "%s  +0x%X  *word  [0x%llX]  0x%04X (%u)", field.name.c_str(), field.offset, (unsigned long long)dataAddr, val, val);
            else
                sprintf_s(text, "%s  +0x%X  word  0x%04X (%u)", field.name.c_str(), field.offset, val, val);
            auto* nd = new TreeNodeData();
            nd->addr = dataAddr;
            char tmp[32]; sprintf_s(tmp, "0x%04X", val); nd->value = tmp;
            nd->type = "word"; nd->ptrTarget = 0;
            InsertTreeItem(hParent, text, nd);
        }
        else if(field.type == "dword") {
            DWORD val = ReadDword(dataAddr);
            if(field.isPointer)
                sprintf_s(text, "%s  +0x%X  *dword  [0x%llX]  0x%08X (%u)", field.name.c_str(), field.offset, (unsigned long long)dataAddr, val, val);
            else
                sprintf_s(text, "%s  +0x%X  dword  0x%08X (%u)", field.name.c_str(), field.offset, val, val);
            auto* nd = new TreeNodeData();
            nd->addr = dataAddr;
            char tmp[32]; sprintf_s(tmp, "0x%08X", val); nd->value = tmp;
            nd->type = "dword"; nd->ptrTarget = 0;
            InsertTreeItem(hParent, text, nd);
        }
        else if(field.type == "qword") {
            duint val = ReadQword(dataAddr);
            if(field.isPointer)
                sprintf_s(text, "%s  +0x%X  *qword  [0x%llX]  0x%llX", field.name.c_str(), field.offset, (unsigned long long)dataAddr, (unsigned long long)val);
            else
                sprintf_s(text, "%s  +0x%X  qword  0x%llX", field.name.c_str(), field.offset, (unsigned long long)val);
            auto* nd = new TreeNodeData();
            nd->addr = dataAddr;
            char tmp[64]; sprintf_s(tmp, "0x%llX", (unsigned long long)val); nd->value = tmp;
            nd->type = "qword"; nd->ptrTarget = 0;
            InsertTreeItem(hParent, text, nd);
        }
        else if(field.type == "float") {
            float val = ReadFloat(dataAddr);
            if(field.isPointer)
                sprintf_s(text, "%s  +0x%X  *float  [0x%llX]  %g", field.name.c_str(), field.offset, (unsigned long long)dataAddr, val);
            else
                sprintf_s(text, "%s  +0x%X  float  %g", field.name.c_str(), field.offset, val);
            auto* nd = new TreeNodeData();
            nd->addr = dataAddr;
            char tmp[64]; sprintf_s(tmp, "%g", val); nd->value = tmp;
            nd->type = "float"; nd->ptrTarget = 0;
            InsertTreeItem(hParent, text, nd);
        }
        else if(field.type == "double") {
            double val = ReadDouble(dataAddr);
            if(field.isPointer)
                sprintf_s(text, "%s  +0x%X  *double  [0x%llX]  %g", field.name.c_str(), field.offset, (unsigned long long)dataAddr, val);
            else
                sprintf_s(text, "%s  +0x%X  double  %g", field.name.c_str(), field.offset, val);
            auto* nd = new TreeNodeData();
            nd->addr = dataAddr;
            char tmp[64]; sprintf_s(tmp, "%g", val); nd->value = tmp;
            nd->type = "double"; nd->ptrTarget = 0;
            InsertTreeItem(hParent, text, nd);
        }
        else if(field.type == "string" || field.type == "wstring") {
            int maxBytes = field.size > 0 ? field.size : 128;
            if(maxBytes > 8192) maxBytes = 8192;
            std::vector<unsigned char> raw(maxBytes + 2, 0);
            ReadMem(dataAddr, raw.data(), maxBytes);

            // wstring 强制 utf16, string 用字段指定的 encoding
            std::string enc = (field.type == "wstring") ? "utf16" : field.encoding;
            std::string detectedEnc;
            std::string decoded = DecodeString(raw.data(), maxBytes, enc, detectedEnc);

            const char* encLabel = detectedEnc.c_str();
            if(field.isPointer)
                sprintf_s(text, "%s  +0x%X  *string[%s]  [0x%llX]  \"%s\"",
                    field.name.c_str(), field.offset, encLabel, (unsigned long long)dataAddr, decoded.c_str());
            else
                sprintf_s(text, "%s  +0x%X  string[%s]  \"%s\"",
                    field.name.c_str(), field.offset, encLabel, decoded.c_str());
            auto* nd = new TreeNodeData();
            nd->addr = dataAddr;
            nd->value = decoded;
            nd->type = "string"; nd->ptrTarget = 0;
            InsertTreeItem(hParent, text, nd);
        }
        else if(field.type == "bytes") {
            int sz = field.size > 0 ? field.size : 16;
            if(sz > 256) sz = 256;
            std::vector<BYTE> raw(sz);
            ReadMem(dataAddr, raw.data(), sz);
            std::string hexStr;
            char tmp[4];
            for(int i = 0; i < sz; i++) {
                if(i > 0) hexStr += ' ';
                sprintf_s(tmp, "%02X", raw[i]);
                hexStr += tmp;
            }
            if(field.isPointer)
                sprintf_s(text, "%s  +0x%X  *bytes  [0x%llX]  %s", field.name.c_str(), field.offset, (unsigned long long)dataAddr, hexStr.c_str());
            else
                sprintf_s(text, "%s  +0x%X  bytes  %s", field.name.c_str(), field.offset, hexStr.c_str());
            auto* nd = new TreeNodeData();
            nd->addr = dataAddr;
            nd->value = hexStr;
            nd->type = "bytes"; nd->ptrTarget = 0;
            InsertTreeItem(hParent, text, nd);
        }
        else {
            duint val = ReadQword(dataAddr);
            if(field.isPointer)
                sprintf_s(text, "%s  +0x%X  *%s  [0x%llX]  0x%llX", field.name.c_str(), field.offset, field.type.c_str(), (unsigned long long)dataAddr, (unsigned long long)val);
            else
                sprintf_s(text, "%s  +0x%X  %s  0x%llX", field.name.c_str(), field.offset, field.type.c_str(), (unsigned long long)val);
            auto* nd = new TreeNodeData();
            nd->addr = dataAddr;
            char tmp[64]; sprintf_s(tmp, "0x%llX", (unsigned long long)val); nd->value = tmp;
            nd->type = field.type; nd->ptrTarget = 0;
            InsertTreeItem(hParent, text, nd);
        }
    }
}

// ============================================================
// Refresh the TreeView
// ============================================================
static HWND g_hAddrEdit = NULL;
static HWND g_hCombo = NULL;

static void RefreshTree()
{
    SendMessageA(g_hTree, WM_SETREDRAW, FALSE, 0);
    TreeView_DeleteAllItems(g_hTree);
    FreeAllNodeData();

    // Get base address
    char addrBuf[64] = {};
    GetWindowTextA(g_hAddrEdit, addrBuf, sizeof(addrBuf));
    duint baseAddr = (duint)strtoull(addrBuf, NULL, 16);
    if(!baseAddr) {
        SendMessageA(g_hTree, WM_SETREDRAW, TRUE, 0);
        return;
    }

    // Get selected struct
    int sel = (int)SendMessageA(g_hCombo, CB_GETCURSEL, 0, 0);
    if(sel < 0 || sel >= (int)g_structNames.size()) {
        SendMessageA(g_hTree, WM_SETREDRAW, TRUE, 0);
        return;
    }

    const std::string& structName = g_structNames[sel];

    // Root node
    char rootText[256];
    sprintf_s(rootText, "%s @ 0x%llX", structName.c_str(), (unsigned long long)baseAddr);
    auto* rootND = new TreeNodeData();
    rootND->addr = baseAddr;
    rootND->value = "";
    rootND->type = "struct";
    rootND->ptrTarget = 0;
    HTREEITEM hRoot = InsertTreeItem(TVI_ROOT, rootText, rootND);

    PopulateStruct(hRoot, baseAddr, structName, 0);

    // Expand root
    TreeView_Expand(g_hTree, hRoot, TVE_EXPAND);

    SendMessageA(g_hTree, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_hTree, NULL, TRUE);
}

// ============================================================
// Reload JSON and refresh combo
// ============================================================
static void ReloadJSON(HWND hwnd)
{
    char path[MAX_PATH];
    GetPluginDir(path, MAX_PATH);
    strcat_s(path, "structs.json");

    if(!LoadStructDefs(path)) {
        MessageBoxA(hwnd, "无法加载 structs.json\n请检查文件是否存在且格式正确。", "结构体查看器", MB_OK | MB_ICONWARNING);
        return;
    }

    // Refresh combo
    SendMessageA(g_hCombo, CB_RESETCONTENT, 0, 0);
    for(auto& name : g_structNames)
        SendMessageA(g_hCombo, CB_ADDSTRING, 0, (LPARAM)name.c_str());
    if(!g_structNames.empty())
        SendMessageA(g_hCombo, CB_SETCURSEL, 0, 0);
}

// ============================================================
// Clipboard helper
// ============================================================
static void CopyToClipboard(HWND hwnd, const char* text)
{
    if(!OpenClipboard(hwnd)) return;
    EmptyClipboard();
    size_t len = strlen(text) + 1;
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, len);
    if(hMem) {
        memcpy(GlobalLock(hMem), text, len);
        GlobalUnlock(hMem);
        SetClipboardData(CF_TEXT, hMem);
    }
    CloseClipboard();
}

// ============================================================
// WndProc
// ============================================================
static LRESULT CALLBACK StructViewWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch(msg)
    {
    case WM_CREATE:
    {
        HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

        // Row 1: 地址
        CreateWindowExA(0, "STATIC", "地址:", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
            8, 8, 36, 24, hwnd, NULL, hInst, NULL);
        g_hAddrEdit = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            48, 8, 280, 24, hwnd, (HMENU)IDC_SV_ADDR_EDIT, hInst, NULL);
        HWND hRefresh = CreateWindowExA(0, "BUTTON", "刷新",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            336, 8, 60, 24, hwnd, (HMENU)IDC_SV_REFRESH, hInst, NULL);

        // Row 2: 结构体
        CreateWindowExA(0, "STATIC", "结构体:", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
            8, 38, 48, 24, hwnd, NULL, hInst, NULL);
        g_hCombo = CreateWindowExA(0, "COMBOBOX", "",
            WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
            58, 38, 270, 200, hwnd, (HMENU)IDC_SV_STRUCT_COMBO, hInst, NULL);
        HWND hReloadBtn = CreateWindowExA(0, "BUTTON", "重新加载JSON",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            336, 38, 100, 24, hwnd, (HMENU)IDC_SV_RELOAD_JSON, hInst, NULL);

        // TreeView
        g_hTree = CreateWindowExA(WS_EX_CLIENTEDGE, WC_TREEVIEWA, "",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL |
            TVS_HASLINES | TVS_HASBUTTONS | TVS_LINESATROOT | TVS_DISABLEDRAGDROP,
            8, 68, 420, 400, hwnd, (HMENU)IDC_SV_TREE, hInst, NULL);

        // Set font
        SendMessageA(g_hAddrEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageA(g_hCombo, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageA(hRefresh, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageA(hReloadBtn, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageA(g_hTree, WM_SETFONT, (WPARAM)hFont, TRUE);

        // Load JSON
        ReloadJSON(hwnd);
        return 0;
    }

    case WM_SIZE:
    {
        int w = LOWORD(lParam);
        int h = HIWORD(lParam);
        int margin = 8;
        int btnW = 60;
        int reloadW = 100;

        // Row 1
        MoveWindow(GetDlgItem(hwnd, 0), margin, margin, 36, 24, TRUE); // static won't work with 0 id
        MoveWindow(g_hAddrEdit, 48, margin, w - 48 - btnW - margin * 2 - 4, 24, TRUE);
        MoveWindow(GetDlgItem(hwnd, IDC_SV_REFRESH), w - btnW - margin, margin, btnW, 24, TRUE);

        // Row 2
        MoveWindow(g_hCombo, 58, 38, w - 58 - reloadW - margin * 2 - 4, 200, TRUE);
        MoveWindow(GetDlgItem(hwnd, IDC_SV_RELOAD_JSON), w - reloadW - margin, 38, reloadW, 24, TRUE);

        // TreeView
        MoveWindow(g_hTree, margin, 68, w - margin * 2, h - 68 - margin, TRUE);
        return 0;
    }

    case WM_COMMAND:
    {
        int id = LOWORD(wParam);
        int code = HIWORD(wParam);

        if(id == IDC_SV_REFRESH) {
            RefreshTree();
        }
        else if(id == IDC_SV_RELOAD_JSON) {
            ReloadJSON(hwnd);
        }
        else if(id == IDC_SV_STRUCT_COMBO && code == CBN_SELCHANGE) {
            // 切换结构体时自动刷新
            RefreshTree();
        }
        return 0;
    }

    case WM_NOTIFY:
    {
        NMHDR* nmhdr = (NMHDR*)lParam;
        if(nmhdr->idFrom == IDC_SV_TREE && nmhdr->code == NM_RCLICK) {
            // Get clicked item
            POINT pt;
            GetCursorPos(&pt);
            POINT clientPt = pt;
            ScreenToClient(g_hTree, &clientPt);

            TVHITTESTINFO htInfo = {};
            htInfo.pt = clientPt;
            HTREEITEM hItem = TreeView_HitTest(g_hTree, &htInfo);
            if(!hItem) return 0;

            TreeView_SelectItem(g_hTree, hItem);

            // Get node data
            TVITEMA tvi = {};
            tvi.mask = TVIF_PARAM;
            tvi.hItem = hItem;
            SendMessageA(g_hTree, TVM_GETITEMA, 0, (LPARAM)&tvi);
            TreeNodeData* nd = (TreeNodeData*)tvi.lParam;
            if(!nd) return 0;

            // Build context menu
            HMENU hMenu = CreatePopupMenu();
            AppendMenuA(hMenu, MF_STRING, IDM_SV_COPY_ADDR, "复制地址");
            AppendMenuA(hMenu, MF_STRING, IDM_SV_COPY_VALUE, "复制值");
            AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);
            AppendMenuA(hMenu, MF_STRING, IDM_SV_GOTO_DISASM, "在反汇编中跟踪");
            AppendMenuA(hMenu, MF_STRING, IDM_SV_GOTO_DUMP, "在内存中跟踪");
            if(nd->type == "pointer" || nd->type == "pointer_array") {
                AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);
                AppendMenuA(hMenu, MF_STRING, IDM_SV_FOLLOW_PTR, "跟踪指针目标");
            }

            int cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
            DestroyMenu(hMenu);

            char buf[64];
            switch(cmd) {
            case IDM_SV_COPY_ADDR:
                sprintf_s(buf, "%llX", (unsigned long long)nd->addr);
                CopyToClipboard(hwnd, buf);
                break;
            case IDM_SV_COPY_VALUE:
                CopyToClipboard(hwnd, nd->value.c_str());
                break;
            case IDM_SV_GOTO_DISASM:
                GuiDisasmAt(nd->addr, nd->addr);
                break;
            case IDM_SV_GOTO_DUMP:
                GuiDumpAt(nd->addr);
                break;
            case IDM_SV_FOLLOW_PTR:
                if(nd->ptrTarget) {
                    GuiDumpAt(nd->ptrTarget);
                }
                break;
            }
            return 0;
        }
        // 双击展开/收起已由 TreeView 默认处理
        return 0;
    }

    case WM_GETMINMAXINFO:
    {
        MINMAXINFO* mmi = (MINMAXINFO*)lParam;
        mmi->ptMinTrackSize.x = 460;
        mmi->ptMinTrackSize.y = 300;
        return 0;
    }

    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        FreeAllNodeData();
        g_hTree = NULL;
        g_hAddrEdit = NULL;
        g_hCombo = NULL;
        g_svHwnd = NULL;
        return 0;
    }

    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

// ============================================================
// Public API
// ============================================================
void ShowStructViewWindow(duint baseAddr)
{
    // If already open, bring to front and update address
    if(g_svHwnd && IsWindow(g_svHwnd)) {
        char buf[64];
        sprintf_s(buf, "%llX", (unsigned long long)baseAddr);
        SetWindowTextA(g_hAddrEdit, buf);
        SetForegroundWindow(g_svHwnd);
        RefreshTree();
        return;
    }

    // Register class once
    static bool classRegistered = false;
    if(!classRegistered) {
        WNDCLASSEXA wc = {};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = StructViewWndProc;
        wc.hInstance = hInst;
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.lpszClassName = SV_WNDCLASS;
        wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
        RegisterClassExA(&wc);
        classRegistered = true;
    }

    g_svHwnd = CreateWindowExA(
        0, SV_WNDCLASS, "结构体查看器",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 700, 500,
        hwndDlg, NULL, hInst, NULL);

    if(!g_svHwnd) return;

    // Set address
    char buf[64];
    sprintf_s(buf, "%llX", (unsigned long long)baseAddr);
    SetWindowTextA(g_hAddrEdit, buf);

    ShowWindow(g_svHwnd, SW_SHOW);
    UpdateWindow(g_svHwnd);

    RefreshTree();
}

void StructView_Cleanup()
{
    if(g_svHwnd && IsWindow(g_svHwnd))
        DestroyWindow(g_svHwnd);
    g_svHwnd = NULL;
    FreeAllNodeData();
    g_structDefs.clear();
    g_structNames.clear();
}
