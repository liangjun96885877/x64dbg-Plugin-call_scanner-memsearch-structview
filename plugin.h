#pragma once

#include <Windows.h>
#include <CommCtrl.h>
#include <cstdio>
#include <vector>
#include <string>
#include <algorithm>
#include <set>
#include <map>

#pragma comment(lib, "comctl32.lib")

#include "pluginsdk/_plugins.h"
#include "pluginsdk/bridgemain.h"
#include "pluginsdk/_scriptapi_module.h"
#include "pluginsdk/_scriptapi_debug.h"
#include "pluginsdk/_scriptapi_memory.h"

#define PLUGIN_NAME    "MyPlugin"
#define PLUGIN_VERSION 1

#define MENU_SHOW_DIALOG        1
#define MENU_ABOUT              2
#define MENU_MEMORY_SEARCH      3
#define MENU_DUMP_SEARCH_ADDR   4
#define MENU_GLOBAL_HOTKEYS     5
#define MENU_STRUCT_VIEWER      6

struct ModuleItem
{
    char name[MAX_MODULE_SIZE];
    duint base;
    duint size;
    duint entry;
};

extern int pluginHandle;
extern HWND hwndDlg;
extern int hMenu;
extern int hMenuDump;
extern HINSTANCE hInst;
