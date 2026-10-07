# -*- coding: utf-8 -*-
"""
Minecraft Mod & Cheat Detector — v4.3
- JAR анализ: строгий, без ложных (уровни уверенности)
- Memory String Scan: только реальные сигнатуры читов (без фолсов)
- Inject Scan: показывает ЛЮБЫЕ сторонние DLL (не только системные/Java)
"""

import os
import re
import sys
import json
import math
import time
import ctypes
import hashlib
import struct
import zipfile
import statistics
import urllib.request
import urllib.error
from ctypes import wintypes
from pathlib import Path
from datetime import datetime
from collections import Counter, defaultdict

# ============================================================
#  ЦВЕТА
# ============================================================
if os.name == "nt":
    os.system("")

RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
BLUE    = "\033[94m"
CYAN    = "\033[96m"
DBLUE   = "\033[34m"
LBLUE   = "\033[38;5;117m"
SKY     = "\033[38;5;39m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
MAGENTA = "\033[95m"
WHITE   = "\033[97m"

def p(t, c=BLUE, color=None):
    if color is not None:
        c = color
    return f"{c}{t}{RESET}"

LOG_LINES = []
def log(msg, to_console=True, color=None):
    ts = datetime.now().strftime("%H:%M:%S")
    raw = f"[{ts}] {msg}"
    LOG_LINES.append(raw)
    if to_console:
        print(p(raw, color) if color else raw)


# ============================================================
#  СИГНАТУРЫ ЧИТОВ
# ============================================================
HARD_CHEAT_SIGNATURES = {
    "Wurst Client":     ["net/wurstclient", "WurstClient", "wurstclient"],
    "Nova Client":      ["com/nova/NovaClient", "NovaClient"],
    "Remix Client":     ["me/remix/RemixClient", "RemixClient"],
    "CheatUtils":       ["org/cheatutils/CheatUtils", "CheatUtils"],
    "Doomsday":         ["com/doomsday/DoomsdayClient", "DoomsdayClient"],
    "Lambda Client":    ["lambda/client/LambdaClient", "LambdaClient"],
    "Meteor Client":    ["meteordevelopment/meteorclient", "MeteorClient"],
    "Impact":           ["com/impactdevelopment/impact"],
    "Aristois":         ["me/aristois/Aristois"],
    "Inertia":          ["com/inertia/Inertia"],
    "Future Client":    ["com/future/Future"],
    "Astolfo":          ["me/astolfo/Astolfo"],
    "Liminar":          ["Liminar", "liminarclient", "liminar/client"],
    "SystemDLC":        ["SystemDLC", "systemdlc", "system_dlc"],
    "Konas":            ["Konas", "konasclient"],
    "Prestige":         ["PrestigeClient"],
    "Rise":             ["RiseClient"],
    "MoonLight":        ["MoonLight", "moonlightclient"],
    "Flux":             ["FluxClient"],
    "Sigma":            ["SigmaClient", "sigmaclient"],
    "Wolfram":          ["WolframClient"],
    "NightX":           ["NightX", "nightxclient"],
    "ZeroDay":          ["ZeroDay", "zerodayclient"],
    "Vape":             ["VapeClient", "VapeV4"],
    "Entropy":          ["entropyclient"],
    "WhiteWalkers":     ["WhiteWalkers", "whitewalkers"],
    "Raven":            ["RavenClient"],
    "Exhibition":       ["Exhibition", "exhibitionclient"],
}

SOFT_MODULE_HINTS = [
    "KillAura", "AutoTotem", "CrystalAura", "AnchorAura", "BedAura",
    "AutoCrystal", "AutoAnchor", "HoleESP", "BedESP",
    "NoFall", "AntiVoid", "AntiKnockback",
    "AutoPot", "AutoHeal", "AutoMine", "Nuker",
    "AutoArmor", "AutoCraft", "AutoDisconnect", "AutoRespawn",
    "AimAssist", "TriggerBot", "BowAimbot", "AutoBow",
    "Backtrack", "FastPlace", "Scaffold",
    "clickgui", "ClickGui", "click_gui", "ClickGUI",
    "Antikick", "AntiKick", "NoSlowdown",
]

LEGIT_OBFUSCATED = {
    "optifine", "optifabric", "sodium", "lithium", "phosphor",
    "starlight", "iris", "indium", "continuity", "ferritecore",
    "krypton", "lazydfu", "hydrogen", "exordium", "c2me",
    "verymanyplayers", "vmp", "modernfix", "memoryleakfix",
    "debugify", "noisium", "fastanim",
}

KNOWN_LEGIT_IDS = {
    "minecraft", "forge", "fabricloader", "fabric-api", "fabric",
    "neoforge", "quilt_loader", "quilted_fabric_api",
    "java", "mcp", "mixinextras", "mixinextras-fabric",
    "cloth-config", "clothconfig", "architectury",
    "modmenu", "mod-menu", "yet-another-config-lib", "yacl",
    "fabric-language-kotlin", "fabric-language-scala",
    "kotlinforforge", "kotlinforfabric",
    "forgeconfigapiport", "forge-config-api-port",
    "puzzleslib", "puzzles-lib", "bookshelf-lib", "bookshelf",
    "collective", "balm", "balm-fabric", "konkrete",
    "resourceful-lib", "resourcefullib", "attributefix",
    "geckolib", "geckolib3", "player-animator",
    "trinkets", "curios", "curios_api", "curiosapi",
    "cardinal-components-api", "cca", "owo-lib", "owolib",
    "midnightlib", "fzzy_config", "jade", "wthit", "hwyla",
    "xaerolib", "xaerominimap", "xaeroworldmap",
    "journeymap-api", "journeymap", "jei", "roughlyenoughitems", "rei",
    "emi", "emi_loot", "emi-enchanting",
    "appleskin", "mouse-tweaks", "mousetweaks",
    "shulkerboxtooltip", "inventory-profiles-next", "sodium-extra",
    "litematica", "malilib", "minihud", "tweakeroo", "itemscroller",
    "worldedit", "worldeditcui", "dynmap", "create", "createaddition",
    "botania", "botania-api", "ae2", "appliedenergistics2", "appbot",
    "mekanism", "mekanismgenerators", "mekanismtools",
    "thermal", "thermalexpansion", "thermalfoundation",
    "immersiveengineering", "immersivepetroleum",
    "tconstruct", "tinkers-construct", "mantle",
    "forestry", "binnie-mods", "extrabees",
    "twilightforest", "biomesoplenty", "biomes-o-plenty",
    "quark", "quark-oddities", "autoconfig",
    "farmersdelight", "farmers-delight", "waystones", "waystone",
    "epicfight", "epic-fight", "alexsmobs", "alexs-mobs", "citadel",
    "iceandfire", "ice-and-fire", "ice-and-fire-dragons",
    "mowziesmobs", "mowzies-mobs", "betterend", "betternether",
    "better-end", "better-nether", "gemsandjewels",
    "sophisticatedbackpacks", "sophisticatedcore", "sophisticatedstorage",
    "ironchest", "ironchests", "iron-chests", "ironfurnace", "ironfurnaces",
    "enderstorage", "ender-storage", "enderchest",
    "cookingforblockheads", "comforts", "comfort", "corpse", "corpse-mod",
    "spark", "spark-fabric", "sparkweave",
    "mcjtylib", "rftools", "rftoolsbase", "rftoolscontrol",
    "xnet", "xnetgases", "deepresonance",
    "mysticalagriculture", "mysticalagradditions", "mysticalcustomization",
    "cucumber", "cucumber-lib", "extendedcrafting", "extended-crafting",
    "bigreactors", "big-reactors", "extremereactors",
    "refinedstorage", "refined-storage", "storagedrawers", "storage-drawers",
    "framed-compacting-drawers", "colossalchests", "colossal-chests",
    "ironjetpacks", "iron-jetpacks", "justenoughitems",
    "extratags", "extratags-common", "patchouli",
    "moonlight", "moonlight-lib", "supplementaries", "amendments",
    "netherportalfix", "nether-portal-fix", "cristel-lib", "cristellib",
}

MODRINTH_API = "https://api.modrinth.com/v2"


# ============================================================
#  WinAPI
# ============================================================
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ           = 0x0010

MEM_COMMIT  = 0x1000
MEM_PRIVATE = 0x20000
MEM_MAPPED  = 0x40000
MEM_IMAGE   = 0x1000000

PAGE_NOACCESS          = 0x01
PAGE_READONLY          = 0x02
PAGE_READWRITE         = 0x04
PAGE_WRITECOPY         = 0x08
PAGE_EXECUTE           = 0x10
PAGE_EXECUTE_READ      = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD             = 0x100

READABLE_PROTECTIONS = {
    PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
}

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress",       ctypes.c_void_p),
        ("AllocationBase",    ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize",        ctypes.c_size_t),
        ("State",             wintypes.DWORD),
        ("Protect",           wintypes.DWORD),
        ("Type",              wintypes.DWORD),
    ]

kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype  = wintypes.HANDLE
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.VirtualQueryEx.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t
]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t
kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
]
kernel32.ReadProcessMemory.restype = wintypes.BOOL


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def find_javaw_pid():
    try:
        import psutil
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                if proc.info["name"] and proc.info["name"].lower() == "javaw.exe":
                    return proc.info["pid"]
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except ImportError:
        import subprocess
        try:
            out = subprocess.check_output(
                ["tasklist", "/FI", "IMAGENAME eq javaw.exe", "/FO", "CSV", "/NH"],
                encoding="cp866", errors="ignore",
            )
            for line in out.splitlines():
                parts = [x.strip('"') for x in line.split('","')]
                if len(parts) >= 2 and parts[0].lower() == "javaw.exe":
                    return int(parts[1])
        except Exception:
            pass
    return None


# ============================================================
#  Извлечение строк
# ============================================================
def extract_ascii_strings(data, min_len=4):
    result = []
    buf = bytearray()
    for b in data:
        if 32 <= b < 127:
            buf.append(b)
        else:
            if len(buf) >= min_len:
                result.append(buf.decode("ascii", "ignore"))
            buf = bytearray()
    if len(buf) >= min_len:
        result.append(buf.decode("ascii", "ignore"))
    return result


def extract_utf16_strings(data, min_len=4):
    result = []
    buf = bytearray()
    i = 0
    n = len(data)
    while i + 1 < n:
        ch = data[i] | (data[i + 1] << 8)
        if (32 <= ch < 127) or (0x0400 <= ch <= 0x04FF):
            buf.append(ch & 0xFF); buf.append((ch >> 8) & 0xFF)
        else:
            if len(buf) >= min_len * 2:
                try:
                    s = buf.decode("utf-16-le", "ignore")
                    if len(s) >= min_len:
                        result.append(s)
                except Exception:
                    pass
            buf = bytearray()
        i += 2
    if len(buf) >= min_len * 2:
        try:
            s = buf.decode("utf-16-le", "ignore")
            if len(s) >= min_len:
                result.append(s)
        except Exception:
            pass
    return result


def scan_process_strings(pid, region_types=(MEM_PRIVATE, MEM_MAPPED),
                         min_len=4, max_bytes=2 * 1024 * 1024 * 1024,
                         progress_cb=None):
    h = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid
    )
    if not h:
        err = ctypes.get_last_error()
        raise OSError(f"OpenProcess failed (PID={pid}, err={err}). Нужны права администратора.")

    all_strings = []
    mbi = MEMORY_BASIC_INFORMATION()
    addr = 0
    total_read = 0
    region_count = 0

    try:
        while True:
            if total_read >= max_bytes:
                break
            written = kernel32.VirtualQueryEx(
                h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)
            )
            if written == 0:
                break
            base = mbi.BaseAddress or 0
            size = mbi.RegionSize or 0
            next_addr = base + size
            if next_addr <= addr:
                addr += 0x1000; continue

            is_ok = (
                mbi.State == MEM_COMMIT
                and (mbi.Protect & 0xFF) in READABLE_PROTECTIONS
                and not (mbi.Protect & PAGE_GUARD)
                and mbi.Type in region_types
                and 0 < size <= 256 * 1024 * 1024
            )
            if not is_ok:
                addr = next_addr; continue

            region_count += 1
            chunk_size = 1 << 20
            off = 0
            while off < size:
                if total_read >= max_bytes:
                    break
                to_read = min(chunk_size, size - off)
                buf = ctypes.create_string_buffer(to_read)
                bytes_read = ctypes.c_size_t(0)
                ok = kernel32.ReadProcessMemory(
                    h, ctypes.c_void_p(base + off), buf, to_read,
                    ctypes.byref(bytes_read),
                )
                if not ok or bytes_read.value == 0:
                    break
                data = buf.raw[: bytes_read.value]
                total_read += len(data)
                chunk_addr = base + off

                for s in extract_ascii_strings(data, min_len):
                    all_strings.append(("ASCII", s, chunk_addr, mbi.Type))
                for s in extract_utf16_strings(data, min_len):
                    all_strings.append(("UTF16", s, chunk_addr, mbi.Type))

                if progress_cb:
                    progress_cb(total_read, region_count, chunk_addr)
                off += bytes_read.value
            addr = next_addr
    finally:
        kernel32.CloseHandle(h)

    return all_strings, total_read, region_count


# ============================================================
#  Инжекты: показываем ЛЮБЫЕ сторонние DLL
# ============================================================
def list_process_modules(pid):
    TH32CS_SNAPMODULE = 0x00000008
    TH32CS_SNAPMODULE32 = 0x00000010
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    MAX_PATH = 260

    class MODULEENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD), ("th32ModuleID", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("GlblcntUsage", wintypes.DWORD), ("ProccntUsage", wintypes.DWORD),
            ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
            ("modBaseSize", wintypes.DWORD),
            ("hModule", wintypes.HMODULE),
            ("szModule", ctypes.c_char * (MAX_PATH + 1)),
            ("szExePath", ctypes.c_char * (MAX_PATH + 1)),
        ]

    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Module32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32)]
    kernel32.Module32First.restype = wintypes.BOOL
    kernel32.Module32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32)]
    kernel32.Module32Next.restype = wintypes.BOOL

    snapshot = kernel32.CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid
    )
    if snapshot == INVALID_HANDLE_VALUE:
        raise OSError("CreateToolhelp32Snapshot failed")

    modules = []
    me = MODULEENTRY32()
    me.dwSize = ctypes.sizeof(MODULEENTRY32)
    try:
        ok = kernel32.Module32First(snapshot, ctypes.byref(me))
        while ok:
            modules.append({
                "name": me.szModule.decode("utf-8", "ignore"),
                "path": me.szExePath.decode("utf-8", "ignore"),
                "base": ctypes.cast(me.modBaseAddr, ctypes.c_void_p).value or 0,
                "size": me.modBaseSize,
            })
            ok = kernel32.Module32Next(snapshot, ctypes.byref(me))
    finally:
        kernel32.CloseHandle(snapshot)
    return modules


# --- Белый список ПУТЕЙ. Всё, что не отсюда и не из Java — подозрительно ---
TRUSTED_PATH_PREFIXES = [
    # Windows
    "c:\\windows\\system32",
    "c:\\windows\\syswow64",
    "c:\\windows\\winsxs",
    "c:\\windows\\microsoft.net",
    "c:\\windows\\assembly",
    # Java (все основные вендоры)
    "c:\\program files\\java",
    "c:\\program files (x86)\\java",
    "c:\\program files\\eclipse adoptium",
    "c:\\program files (x86)\\eclipse adoptium",
    "c:\\program files\\bellsoft",
    "c:\\program files (x86)\\bellsoft",
    "c:\\program files\\zulu",
    "c:\\program files (x86)\\zulu",
    "c:\\program files\\microsoft\\jdk",
    "c:\\program files (x86)\\microsoft\\jdk",
    "c:\\program files\\amazon corretto",
    "c:\\program files\\semeru",
    "c:\\program files\\graalvm",
    "c:\\program files\\liberica",
    # Лаунчеры
    "c:\\program files\\minecraft launcher",
    "c:\\program files (x86)\\minecraft launcher",
    "c:\\xboxgames",
    "c:\\program files\\modrinth",
    "c:\\program files (x86)\\modrinth",
    "c:\\program files\\prismlauncher",
    "c:\\program files (x86)\\prismlauncher",
    "c:\\program files\\multimc",
    "c:\\program files\\gdlauncher",
    "c:\\program files\\atlauncher",
    "c:\\program files (x86)\\atlauncher",
    "c:\\program files\\technic",
]

# Ключевые слова в имени модуля, которые считаем безопасными
# (системные библиотеки Windows, стандартный JVM-набор, LWJGL/OpenGL).
# Всё остальное — показываем как стороннее.
TRUSTED_NAME_KEYWORDS = [
    # Windows core
    "kernel32", "kernelbase", "ntdll", "user32", "gdi32", "gdiplus",
    "advapi32", "ole32", "oleaut32", "shell32", "shlwapi", "combase",
    "comctl32", "comdlg32", "rpcrt4", "sechost", "bcrypt", "crypt32",
    "winhttp", "wininet", "ws2_32", "mswsock", "dnsapi", "iphlpapi",
    "dwmapi", "uxtheme", "imm32", "msctf", "msvcrt", "ucrtbase",
    "vcruntime", "msvcp", "concrt", "vccorlib", "api-ms-win",
    "kernel.appcore", "textinputframework", "inputhost", "coremessaging",
    "wintrust", "wintypes", "wtsapi32", "version", "psapi",
    "propsys", "windows.storage", "winmm", "dsound", "msacm",
    "avrt", "mfplat", "mfreadwrite", "mfuuid", "d3d", "dxgi",
    "d3d11", "d3d9", "opengl32", "glu32",
    # Java runtime / LWJGL / OpenGL / OpenAL
    "jvm", "java", "nio", "zip", "management", "security", "awt", "fontmanager",
    "lwjgl", "glfw", "openal", "jawt", "net.dll", "verify",
    "jimage", "jli", "instrument", "extnet", "management_ext",
    # Game stack
    "sodium", "nvidium", "mesa",
]

# Явно подозрительные ключи (если встретились — точно сторонний инжект)
SUSPICIOUS_NAME_KEYWORDS = [
    "inject", "cheat", "hack", "hackclient", "client_loader",
    "loader_hack", "dll_injector", "detour", "hook", "hookdll",
    "bypass", "anticheat_bypass", "xhook", "minhook", "easyhook",
]


def classify_module(mod):
    """
    Возвращает ("trusted"|"suspicious"|"external", причина).
    - trusted: системный путь ИЛИ имя из белого списка
    - suspicious: имя содержит явные чит/инжект-маркеры
    - external: всё остальное (сторонняя DLL — может быть читом, оверлеем и т.п.)
    """
    path = (mod["path"] or "").lower()
    name = (mod["name"] or "").lower()

    # 1. Явно подозрительные маркеры имени
    for kw in SUSPICIOUS_NAME_KEYWORDS:
        if kw in name:
            return "suspicious", f"имя содержит '{kw}'"

    # 2. Доверенный путь
    for pref in TRUSTED_PATH_PREFIXES:
        if path.startswith(pref):
            return "trusted", "системный/Java путь"

    # 3. Доверенное имя (только если и путь не пустой, и имя совпало)
    for kw in TRUSTED_NAME_KEYWORDS:
        if kw in name:
            return "trusted", f"системная библиотека ({kw})"

    # 4. Всё остальное — сторонняя DLL
    return "external", "сторонний DLL (не из Windows/Java/Minecraft)"


# ============================================================
#  Modrinth
# ============================================================
_modrinth_cache = {}

def modrinth_lookup(sha1):
    if sha1 in _modrinth_cache:
        return _modrinth_cache[sha1]
    url = f"{MODRINTH_API}/version_file/{sha1}"
    req = urllib.request.Request(url, headers={"User-Agent": "mod-checker/4.3"})
    result = None
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            version = json.loads(r.read().decode())
            proj_id = version.get("project_id")
            if proj_id:
                url2 = f"{MODRINTH_API}/project/{proj_id}"
                req2 = urllib.request.Request(url2, headers={"User-Agent": "mod-checker/4.3"})
                with urllib.request.urlopen(req2, timeout=15) as r2:
                    proj = json.loads(r2.read().decode())
                result = {
                    "project_id": proj_id, "title": proj.get("title"),
                    "slug": proj.get("slug"),
                    "downloads": proj.get("downloads", 0),
                }
    except Exception:
        result = None
    _modrinth_cache[sha1] = result
    return result


# ============================================================
#  Утилиты
# ============================================================
def human_size(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} TB"

def entropy(seq):
    if not seq:
        return 0.0
    c = Counter(seq); t = len(seq)
    return -sum((v / t) * math.log2(v / t) for v in c.values())

def sha1_file(path, chunk=1 << 20):
    h = hashlib.sha1()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(chunk), b""):
            h.update(b)
    return h.hexdigest()

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def press_enter():
    try:
        input(p("\n  Нажми Enter, чтобы вернуться в меню... ", DIM + CYAN))
    except (EOFError, KeyboardInterrupt):
        pass

def back_to_menu_hint():
    try:
        s = input(p("\n  [0] Вернуться в меню > ", BOLD + CYAN)).strip()
        return s
    except (EOFError, KeyboardInterrupt):
        return "0"


# ============================================================
#  JAR парсер
# ============================================================
def parse_class_file(data):
    result = {
        "valid": False, "utf8_strings": [],
        "method_names": [], "has_line_numbers": False,
        "has_source_file": False, "package": "", "class_name": "",
    }
    if len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
        return result
    try:
        result["valid"] = True
        cp_count = struct.unpack(">H", data[8:10])[0]
    except struct.error:
        return result

    cp = [None] * cp_count
    idx = 10
    i = 1
    while i < cp_count:
        if idx >= len(data):
            return result
        tag = data[idx]; idx += 1
        if tag == 1:
            if idx + 2 > len(data): return result
            ln = struct.unpack(">H", data[idx:idx+2])[0]; idx += 2
            s = data[idx:idx+ln].decode("utf-8", "ignore"); idx += ln
            cp[i] = (1, s)
            result["utf8_strings"].append(s)
        elif tag in (7, 8, 16, 19, 20):
            if tag == 7:
                if idx + 2 > len(data): return result
                cp[i] = (7, struct.unpack(">H", data[idx:idx+2])[0])
            else:
                cp[i] = (tag, None)
            idx += 2
        elif tag == 15:
            idx += 3; cp[i] = (15, None)
        elif tag in (3, 4, 9, 10, 11, 12, 17, 18):
            idx += 4; cp[i] = (tag, None)
        elif tag in (5, 6):
            idx += 8; cp[i] = (tag, None); i += 1
        else:
            return result
        i += 1

    try:
        if idx + 8 > len(data): return result
        idx += 2
        this_class = struct.unpack(">H", data[idx:idx+2])[0]; idx += 2
        idx += 2
        def rcn(ci):
            if ci == 0 or ci >= cp_count: return ""
            e = cp[ci]
            if not e or e[0] != 7: return ""
            ne = cp[e[1]]
            return ne[1] if ne and ne[0] == 1 else ""
        result["class_name"] = rcn(this_class)
        if "/" in result["class_name"]:
            result["package"] = result["class_name"].rsplit("/", 1)[0]
        iface_count = struct.unpack(">H", data[idx:idx+2])[0]; idx += 2
        idx += iface_count * 2
    except Exception:
        return result

    try:
        field_count = struct.unpack(">H", data[idx:idx+2])[0]; idx += 2
        for _ in range(field_count):
            if idx + 8 > len(data): break
            idx += 6
            attr_count = struct.unpack(">H", data[idx:idx+2])[0]; idx += 2
            for _ in range(attr_count):
                if idx + 6 > len(data): break
                idx += 2
                ln = struct.unpack(">I", data[idx:idx+4])[0]; idx += 4
                idx += ln
    except Exception:
        pass

    try:
        method_count = struct.unpack(">H", data[idx:idx+2])[0]; idx += 2
        for _ in range(method_count):
            if idx + 8 > len(data): break
            idx += 2
            name_idx = struct.unpack(">H", data[idx:idx+2])[0]; idx += 2
            idx += 2
            if 0 < name_idx < cp_count and cp[name_idx] and cp[name_idx][0] == 1:
                result["method_names"].append(cp[name_idx][1])
            attr_count = struct.unpack(">H", data[idx:idx+2])[0]; idx += 2
            for _ in range(attr_count):
                if idx + 6 > len(data): break
                an_idx = struct.unpack(">H", data[idx:idx+2])[0]; idx += 2
                ln = struct.unpack(">I", data[idx:idx+4])[0]; idx += 4
                an = ""
                if 0 < an_idx < cp_count and cp[an_idx] and cp[an_idx][0] == 1:
                    an = cp[an_idx][1]
                if an == "LineNumberTable":
                    result["has_line_numbers"] = True
                idx += ln
    except Exception:
        pass

    try:
        attr_count = struct.unpack(">H", data[idx:idx+2])[0]; idx += 2
        for _ in range(attr_count):
            if idx + 6 > len(data): break
            an_idx = struct.unpack(">H", data[idx:idx+2])[0]; idx += 2
            ln = struct.unpack(">I", data[idx:idx+4])[0]; idx += 4
            an = ""
            if 0 < an_idx < cp_count and cp[an_idx] and cp[an_idx][0] == 1:
                an = cp[an_idx][1]
            if an == "SourceFile":
                result["has_source_file"] = True
            idx += ln
    except Exception:
        pass

    return result


# ============================================================
#  Анализ JAR
# ============================================================
def analyze_jar(path: Path, verbose=False):
    r = {
        "path": path, "name": path.name, "size": path.stat().st_size,
        "sha1": None, "modrinth": None, "trusted": False,
        "mod_id": None, "mod_name": None, "loader": None,
        "class_count": 0, "short_classes": 0, "obf_ratio": 0.0,
        "method_count": 0, "short_methods": 0,
        "line_numbers_ratio": 0.0, "source_file_ratio": 0.0,
        "unique_packages": 0, "single_letter_packages": 0,
        "entropy": 0.0, "hard_cheat_hits": [], "soft_cheat_hits": [],
        "suspicious_api_hits": [], "suspicious_strings_found": [],
        "issues": [], "signals": [], "confidence": "OK", "score": 0.0,
        "size_anomaly_z": 0.0, "size_anomaly_pct": 0.0, "size_anomaly_label": "",
    }

    try:
        r["sha1"] = sha1_file(path)
        mr = modrinth_lookup(r["sha1"])
        if mr:
            r["modrinth"] = mr
            r["trusted"] = True
    except Exception as e:
        if verbose:
            log(f"  SHA-1 ошибка: {e}", color=RED)

    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()

            for cand in ("fabric.mod.json", "quilt.mod.json"):
                if cand in names:
                    try:
                        d = json.loads(zf.read(cand).decode("utf-8", "ignore"))
                        r["mod_id"] = d.get("id")
                        r["mod_name"] = d.get("name") or d.get("id")
                        r["loader"] = "fabric/quilt"
                        break
                    except Exception:
                        pass
            for n in names:
                if n.endswith("mods.toml"):
                    try:
                        t = zf.read(n).decode("utf-8", "ignore")
                        m = re.search(r'modId\s*=\s*"([^"]+)"', t)
                        if m: r["mod_id"] = m.group(1)
                        m = re.search(r'displayName\s*=\s*"([^"]+)"', t)
                        if m: r["mod_name"] = m.group(1)
                        r["loader"] = "forge/neoforge"
                        break
                    except Exception:
                        pass
            if "mcmod.info" in names and not r["mod_id"]:
                try:
                    t = zf.read("mcmod.info").decode("utf-8", "ignore").strip()
                    if t.startswith("["):
                        d = json.loads(t)
                        if d:
                            r["mod_id"] = d[0].get("modid")
                            r["mod_name"] = d[0].get("name")
                            r["loader"] = "forge (legacy)"
                except Exception:
                    pass

            class_basenames = []
            all_methods = []
            packages = set()
            with_line_numbers = 0
            with_source_file = 0
            all_utf8_blob = []

            for n in names:
                if not n.endswith(".class"):
                    continue
                class_basenames.append(n)
                try:
                    info = parse_class_file(zf.read(n))
                    if info["valid"]:
                        all_methods.extend(info["method_names"])
                        if info["package"]:
                            packages.add(info["package"])
                        if info["has_line_numbers"]:
                            with_line_numbers += 1
                        if info["has_source_file"]:
                            with_source_file += 1
                        all_utf8_blob.append("\n".join(info["utf8_strings"]))
                except Exception:
                    pass

            r["class_count"] = len(class_basenames)
            r["method_count"] = len(all_methods)
            r["unique_packages"] = len(packages)

            slp = 0
            for pkg in packages:
                parts = pkg.split("/")
                short_parts = sum(1 for x in parts if len(x) <= 2)
                if short_parts >= max(1, len(parts) - 1) and len(parts) >= 2:
                    slp += 1
            r["single_letter_packages"] = slp

            def short_name(s):
                return bool(re.match(r"^[a-zA-Z]{1,2}$", s))

            r["short_classes"] = sum(
                1 for cn in class_basenames if short_name(cn.rsplit("/", 1)[-1][:-6])
            )
            r["short_methods"] = sum(1 for m in all_methods if short_name(m))

            if class_basenames:
                r["obf_ratio"] = r["short_classes"] / len(class_basenames)
                r["entropy"] = entropy("".join(class_basenames))
                r["line_numbers_ratio"] = with_line_numbers / len(class_basenames)
                r["source_file_ratio"] = with_source_file / len(class_basenames)

            full_blob = "\n".join(all_utf8_blob)
            flat_hard = [s for sigs in HARD_CHEAT_SIGNATURES.values() for s in sigs]
            for sig in flat_hard:
                if sig in full_blob:
                    r["hard_cheat_hits"].append(sig)
            for sig in SOFT_MODULE_HINTS:
                if sig in full_blob:
                    r["soft_cheat_hits"].append(sig)

            suspicious_api = [
                b"Runtime.getRuntime().exec", b"ProcessBuilder",
                b"defineClass", b"URLClassLoader",
            ]
            web_apis = [
                b"java/net/URL", b"java/net/Socket",
                b"java/net/HttpURLConnection",
            ]
            for n in names:
                if not n.endswith(".class"):
                    continue
                data = zf.read(n)
                for s in suspicious_api:
                    if s in data and s.decode() not in r["suspicious_api_hits"]:
                        r["suspicious_api_hits"].append(s.decode())
                for s in web_apis:
                    if s in data and s.decode() not in r["suspicious_strings_found"]:
                        r["suspicious_strings_found"].append(s.decode())

    except zipfile.BadZipFile:
        r["issues"].append("Некорректный JAR/ZIP")
        r["confidence"] = "LOW"
        return r
    except Exception as e:
        r["issues"].append(f"Ошибка чтения: {e}")
        r["confidence"] = "LOW"
        return r

    signals = []
    if r["hard_cheat_hits"]:
        signals.append((100, f"ЖЁСТКАЯ СИГНАТУРА ЧИТА: {', '.join(r['hard_cheat_hits'])}"))

    if r["trusted"]:
        r["signals"] = signals
        r["confidence"] = "CERTAIN_CHEAT" if r["hard_cheat_hits"] else "OK"
        return r

    mid_lower = (r["mod_id"] or "").lower()
    is_known_legit = mid_lower in KNOWN_LEGIT_IDS
    is_legit_obf = mid_lower in LEGIT_OBFUSCATED

    obf_suspicious = False
    if not is_known_legit and not is_legit_obf:
        if (r["class_count"] >= 40 and r["obf_ratio"] >= 0.6
                and r["line_numbers_ratio"] < 0.2 and r["unique_packages"] <= 3):
            signals.append((40, f"Сильная обфускация: {r['short_classes']}/{r['class_count']}"))
            obf_suspicious = True
        elif (r["class_count"] >= 100 and r["obf_ratio"] >= 0.45
                and r["line_numbers_ratio"] < 0.1):
            signals.append((30, f"Обфускация: {r['obf_ratio']*100:.0f}% коротких имён"))
            obf_suspicious = True

    if r["method_count"] >= 50:
        msr = r["short_methods"] / r["method_count"]
        if msr >= 0.7 and not is_known_legit and not is_legit_obf:
            signals.append((25, f"Методы обфусцированы: {msr*100:.0f}%"))

    if r["unique_packages"] > 0 and r["single_letter_packages"] / max(1, r["unique_packages"]) > 0.6:
        if r["class_count"] >= 30 and not is_legit_obf:
            signals.append((20, f"Пакеты обфусцированы ({r['single_letter_packages']}/{r['unique_packages']})"))

    if r["suspicious_api_hits"]:
        if "ProcessBuilder" in r["suspicious_api_hits"] or "Runtime.getRuntime().exec" in r["suspicious_api_hits"]:
            signals.append((35, f"Вызовы процесса: {', '.join(r['suspicious_api_hits'])}"))
        else:
            signals.append((15, f"Подозрительные API: {', '.join(r['suspicious_api_hits'])}"))

    if r["suspicious_strings_found"]:
        signals.append((10, f"Сетевые API: {', '.join(r['suspicious_strings_found'])}"))

    if r["soft_cheat_hits"] and (obf_suspicious or r["suspicious_api_hits"]):
        signals.append((25, f"Модули читов + обфускация: {', '.join(r['soft_cheat_hits'][:5])}"))

    if not r["mod_id"] and not r["mod_name"] and not is_known_legit:
        signals.append((15, "Нет метаданных мода и нет в Modrinth"))

    if r["size"] < 4096 and not is_known_legit:
        signals.append((15, f"Аномально маленький размер: {human_size(r['size'])}"))

    total_score = sum(w for w, _ in signals)
    r["score"] = total_score
    r["signals"] = signals

    if any(w >= 100 for w, _ in signals):
        r["confidence"] = "CERTAIN_CHEAT"
    elif total_score >= 80:
        r["confidence"] = "HIGH"
    elif total_score >= 45:
        r["confidence"] = "MEDIUM"
    elif total_score >= 20:
        r["confidence"] = "LOW"
    else:
        r["confidence"] = "OK"

    if r["confidence"] != "OK":
        r["issues"] = [d for _, d in signals]

    return r


# ============================================================
#  Аномалии веса
# ============================================================
def compute_weight_anomalies(results):
    sizes = [r["size"] for r in results if r["size"] > 0]
    if not sizes:
        return {}
    med = statistics.median(sizes)
    mean = statistics.mean(sizes)
    std = statistics.pstdev(sizes) if len(sizes) > 1 else 0.0
    for r in results:
        r["size_anomaly_z"] = (r["size"] - mean) / std if std else 0.0
        r["size_anomaly_pct"] = ((r["size"] - med) / med * 100) if med else 0.0
        z = abs(r["size_anomaly_z"])
        if z >= 3.0: r["size_anomaly_label"] = "аномальный"
        elif z >= 2.0: r["size_anomaly_label"] = "сильное отклонение"
        elif z >= 1.0: r["size_anomaly_label"] = "умеренное отклонение"
        else: r["size_anomaly_label"] = "норма"
    return {"median": med, "mean": mean, "stdev": std,
            "min": min(sizes), "max": max(sizes), "count": len(sizes)}


# ============================================================
#  Строгий поиск сигнатур
# ============================================================
_HARD_BOUNDARY_CACHE = {}

def hard_signature_regex(sig):
    if sig in _HARD_BOUNDARY_CACHE:
        return _HARD_BOUNDARY_CACHE[sig]
    esc = re.escape(sig)
    pat = re.compile(rf"(?:^|[^A-Za-z0-9_]){esc}(?:$|[^A-Za-z0-9_])")
    _HARD_BOUNDARY_CACHE[sig] = pat
    return pat


def is_meaningful_string(s):
    if not s or len(s) > 500:
        return False
    printable = sum(1 for c in s if 32 <= ord(c) < 127)
    if printable / len(s) < 0.7:
        return False
    return True


def search_signatures_in_strings(strings):
    client_hits = defaultdict(list)
    soft_by_chunk = defaultdict(dict)

    for stype, sval, addr, rtype in strings:
        if not is_meaningful_string(sval):
            continue

        for client_name, sigs in HARD_CHEAT_SIGNATURES.items():
            for sig in sigs:
                if hard_signature_regex(sig).search(sval):
                    client_hits[client_name].append({
                        "sig": sig, "value": sval[:200],
                        "addr": addr, "type": stype,
                        "region": "Private" if rtype == MEM_PRIVATE else "Mapped",
                    })

        for sig in SOFT_MODULE_HINTS:
            if hard_signature_regex(sig).search(sval):
                chunk_key = addr >> 20
                if sig not in soft_by_chunk[chunk_key]:
                    soft_by_chunk[chunk_key][sig] = (sval[:200], addr, stype, rtype)

    soft_findings = []
    for chunk_key, sigs in soft_by_chunk.items():
        if len(sigs) >= 3:
            for sig, (val, addr, stype, rtype) in sigs.items():
                soft_findings.append({
                    "sig": sig, "value": val, "addr": addr,
                    "type": stype,
                    "region": "Private" if rtype == MEM_PRIVATE else "Mapped",
                    "chunk_group_size": len(sigs),
                })

    return dict(client_hits), soft_findings


# ============================================================
#  Сканер памяти
# ============================================================
def scan_javaw_memory():
    clear()
    print()
    print(p("=" * 70, CYAN))
    print(p("  СКАНИРОВАНИЕ ПАМЯТИ javaw.exe", BOLD + MAGENTA))
    print(p("=" * 70, CYAN))
    print()
    print(p("  Min string length: 4 | Unicode: ON | Private+Mapped", DIM + SKY))
    print()

    if not is_admin():
        log("X НЕТ ПРАВ АДМИНИСТРАТОРА!", color=RED)
        print()
        back_to_menu_hint()
        return None

    pid = find_javaw_pid()
    if not pid:
        log("X javaw.exe не найден. Запусти Minecraft.", color=YELLOW)
        print()
        back_to_menu_hint()
        return None

    log(f"[+] Найден javaw.exe PID={pid}", color=GREEN)
    print()
    print(p("  Сканирование... (несколько минут)", SKY))
    print()

    last_print = [0]
    def progress(total, regs, addr):
        now = time.time()
        if now - last_print[0] < 0.5:
            return
        last_print[0] = now
        sys.stdout.write(p(
            f"\r  Прочитано: {human_size(total)} | регионов: {regs}   ",
            DIM + SKY
        ))
        sys.stdout.flush()

    try:
        strings, total_bytes, region_count = scan_process_strings(
            pid, region_types=(MEM_PRIVATE, MEM_MAPPED),
            min_len=4, max_bytes=2 * 1024 * 1024 * 1024,
            progress_cb=progress,
        )
    except Exception as e:
        print()
        log(f"X Ошибка: {e}", color=RED)
        print()
        back_to_menu_hint()
        return None

    print()
    log(f"[+] Прочитано {human_size(total_bytes)} | регионов: {region_count}", color=GREEN)
    log(f"[+] Извлечено строк: {len(strings)}", color=SKY)
    print()
    print(p("  Анализ строк...", SKY))

    client_hits, soft_findings = search_signatures_in_strings(strings)

    clear()
    print()
    print(p("╔" + "═" * 68 + "╗", CYAN))
    print(p("║", CYAN) + p(" РЕЗУЛЬТАТ СКАНИРОВАНИЯ ПАМЯТИ ".center(68), BOLD + LBLUE) + p("║", CYAN))
    print(p("╚" + "═" * 68 + "╝", CYAN))
    print()

    has_detection = bool(client_hits) or bool(soft_findings)

    if not has_detection:
        print(p("  ╔══════════════════════════════════════════════════════════════╗", GREEN))
        print(p("  ║                                                              ║", GREEN))
        print(p("  ║                    ✓  ПАМЯТЬ ЧИСТА                          ║", GREEN))
        print(p("  ║                                                              ║", GREEN))
        print(p("  ║        читерских клиентов в памяти не обнаружено            ║", GREEN))
        print(p("  ║                                                              ║", GREEN))
        print(p("  ╚══════════════════════════════════════════════════════════════╝", GREEN))
        print()
        print(p(f"  Прочитано памяти: {human_size(total_bytes)}", DIM + SKY))
        print(p(f"  Строк проанализировано: {len(strings)}", DIM + SKY))
        print()
    else:
        print(p("  ╔══════════════════════════════════════════════════════════════╗", RED))
        print(p("  ║                                                              ║", RED))
        print(p("  ║              ☠  ОБНАРУЖЕНЫ СИГНАТУРЫ ЧИТОВ                   ║", BOLD + RED))
        print(p("  ║                                                              ║", RED))
        print(p("  ╚══════════════════════════════════════════════════════════════╝", RED))
        print()

        if client_hits:
            total_hits = sum(len(v) for v in client_hits.values())
            print(p(f"  Обнаружено клиентов: {len(client_hits)}  |  всего совпадений: {total_hits}",
                    BOLD + RED))
            print()
            for client_name, hits in sorted(client_hits.items(),
                                            key=lambda x: -len(x[1])):
                print(p(f"  ● {client_name}", BOLD + RED))
                print(p(f"     совпадений: {len(hits)}", DIM + RED))
                for h in hits[:3]:
                    print(p(f"       • {h['value'][:80]!r}", DIM + RED))
                    print(p(f"         [{h['type']}] @0x{h['addr']:x} | {h['region']}", DIM + RED))
                if len(hits) > 3:
                    print(p(f"       ... и ещё {len(hits)-3} совпадений", DIM + RED))
                print()

        if soft_findings:
            print(p(f"  ⚠ Групповые SOFT-сигнатуры: {len(soft_findings)}", BOLD + YELLOW))
            for f in soft_findings[:15]:
                print(p(f"     • {f['sig']} (группа: {f['chunk_group_size']})", YELLOW))
            if len(soft_findings) > 15:
                print(p(f"     ... и ещё {len(soft_findings)-15}", DIM + YELLOW))
            print()

    result_data = {
        "type": "memory_scan",
        "clean": not has_detection,
        "client_hits": {k: v for k, v in client_hits.items()},
        "soft_findings": soft_findings,
        "stats": {
            "bytes": total_bytes,
            "strings": len(strings),
            "regions": region_count,
            "pid": pid,
        },
    }

    back_to_menu_hint()
    return result_data


# ============================================================
#  Сканер инжектов: ЛЮБЫЕ сторонние DLL
# ============================================================
def scan_injects():
    clear()
    print()
    print(p("=" * 70, CYAN))
    print(p("  СКАН ИНЖЕКТОВ (любые сторонние DLL)", BOLD + MAGENTA))
    print(p("=" * 70, CYAN))
    print()
    print(p("  Показываем ВСЁ, что загружено в javaw.exe и", DIM + SKY))
    print(p("  НЕ является системной/Java/Minecraft библиотекой.", DIM + SKY))
    print()

    if not is_admin():
        log("X НЕТ ПРАВ АДМИНИСТРАТОРА!", color=RED)
        print()
        back_to_menu_hint()
        return None

    pid = find_javaw_pid()
    if not pid:
        log("X javaw.exe не найден. Запусти Minecraft.", color=YELLOW)
        print()
        back_to_menu_hint()
        return None

    log(f"[+] Найден javaw.exe PID={pid}", color=GREEN)
    print()

    try:
        modules = list_process_modules(pid)
    except Exception as e:
        log(f"X Ошибка получения списка модулей: {e}", color=RED)
        print()
        back_to_menu_hint()
        return None

    log(f"[+] Загружено модулей: {len(modules)}", color=SKY)
    print()
    print(p("  Классификация...", SKY))

    trusted = []
    external = []
    suspicious = []

    for mod in modules:
        cls, reason = classify_module(mod)
        mod["reason"] = reason
        if cls == "trusted":
            trusted.append(mod)
        elif cls == "suspicious":
            suspicious.append(mod)
        else:
            external.append(mod)

    clear()
    print()
    print(p("╔" + "═" * 68 + "╗", CYAN))
    print(p("║", CYAN) + p(" РЕЗУЛЬТАТ СКАНА ИНЖЕКТОВ ".center(68), BOLD + LBLUE) + p("║", CYAN))
    print(p("╚" + "═" * 68 + "╝", CYAN))
    print()

    if not external and not suspicious:
        print(p("  ╔══════════════════════════════════════════════════════════════╗", GREEN))
        print(p("  ║                                                              ║", GREEN))
        print(p("  ║                ✓  СТОРОННИХ DLL НЕ НАЙДЕНО                  ║", GREEN))
        print(p("  ║                                                              ║", GREEN))
        print(p("  ║     всё в javaw.exe — системные/Java/Minecraft библиотеки    ║", GREEN))
        print(p("  ║                                                              ║", GREEN))
        print(p("  ╚══════════════════════════════════════════════════════════════╝", GREEN))
        print()
        print(p(f"  Всего модулей: {len(modules)}", DIM + SKY))
        print(p(f"  Доверенных:    {len(trusted)}", DIM + SKY))
        print()
    else:
        # --- Явно подозрительные (чит/инжект маркеры в имени) ---
        if suspicious:
            print(p(f"  ☠ ЯВНО ПОДОЗРИТЕЛЬНЫЕ: {len(suspicious)}", BOLD + RED))
            print()
            for m in suspicious:
                print(p(f"  ● {m['name']}", BOLD + RED))
                print(p(f"     причина: {m['reason']}", DIM + RED))
                print(p(f"     путь:    {m['path']}", DIM + RED))
                print(p(f"     base:    0x{m['base']:x}  |  size: {human_size(m['size'])}", DIM + RED))
                print()

        # --- Сторонние DLL (не системные, но и не чит) ---
        if external:
            print(p(f"  ⚠ СТОРОННИЕ DLL: {len(external)}", BOLD + YELLOW))
            print(p("  Это DLL, загруженные извне системы/Java/Minecraft.", DIM + YELLOW))
            print(p("  Обычно это: оверлеи (Discord, OBS, NVIDIA), хуки,", DIM + YELLOW))
            print(p("  модификации клиента, чит-клиенты, DLL-инжекторы.", DIM + YELLOW))
            print()
            for m in external:
                print(p(f"  ● {m['name']}", BOLD + YELLOW))
                print(p(f"     путь: {m['path']}", DIM + YELLOW))
                print(p(f"     base: 0x{m['base']:x}  |  size: {human_size(m['size'])}", DIM + YELLOW))
                print()

        print(p(f"  Всего модулей: {len(modules)}  |  "
                f"доверенных: {len(trusted)}  |  "
                f"сторонних: {len(external)}  |  "
                f"подозрительных: {len(suspicious)}", BOLD + LBLUE))
        print()

    result_data = {
        "type": "inject_scan",
        "clean": not external and not suspicious,
        "suspicious": suspicious,
        "external": external,
        "trusted_count": len(trusted),
        "total_modules": len(modules),
        "pid": pid,
    }

    back_to_menu_hint()
    return result_data


# ============================================================
#  Метки
# ============================================================
def confidence_color(c):
    return {"CERTAIN_CHEAT": RED, "HIGH": RED, "MEDIUM": YELLOW,
            "LOW": LBLUE, "OK": GREEN}.get(c, WHITE)

def confidence_mark(c):
    return {"CERTAIN_CHEAT": "[X]", "HIGH": "[!]", "MEDIUM": "[*]",
            "LOW": "[.]", "OK": "[+]"}.get(c, "[?]")


# ============================================================
#  Вывод JAR
# ============================================================
def show_final_summary(results):
    clear()
    cheat = [r for r in results if r["confidence"] == "CERTAIN_CHEAT"]
    high = [r for r in results if r["confidence"] == "HIGH"]
    med = [r for r in results if r["confidence"] == "MEDIUM"]
    low = [r for r in results if r["confidence"] == "LOW"]
    ok = [r for r in results if r["confidence"] == "OK"]
    trusted = [r for r in results if r["trusted"]]

    print()
    print(p("+" + "=" * 70 + "+", CYAN))
    print(p("|", CYAN) + p(" РЕЗУЛЬТАТЫ АНАЛИЗА JAR ".center(70), BOLD + LBLUE) + p("|", CYAN))
    print(p("+" + "=" * 70 + "+", CYAN))
    print()
    print(p(f"  Всего модов: {len(results)}", BOLD + LBLUE))
    print()
    print(p(f"  [X]  ТОЧНО ЧИТЫ: {len(cheat)}", BOLD + RED))
    print(p(f"  [!]  Высокая уверенность: {len(high)}", RED))
    print(p(f"  [*]  Средняя уверенность: {len(med)}", YELLOW))
    print(p(f"  [.]  Низкая уверенность: {len(low)}", LBLUE))
    print(p(f"  [+]  Чисто: {len(ok)}", GREEN))
    print(p(f"     (доверенных Modrinth: {len(trusted)})", DIM + GREEN))
    print()

    if cheat:
        print(p("  [X] ОБНАРУЖЕНЫ ЧИТЫ:", BOLD + RED))
        for r in cheat:
            print(p(f"     - {r['name']}", RED))
            if r["hard_cheat_hits"]:
                print(p(f"       сигнатура: {', '.join(r['hard_cheat_hits'])}", RED))
        print()

    if high:
        print(p("  [!] ТРЕБУЮТ ПРОВЕРКИ:", BOLD + RED))
        for r in high:
            print(p(f"     - {r['name']}  (score={r['score']:.0f})", RED))
            for _, d in r["signals"][:3]:
                print(p(f"       -> {d}", DIM + RED))
        print()

    if med:
        print(p("  [*] ПОДОЗРИТЕЛЬНЫЕ:", BOLD + YELLOW))
        for r in med:
            print(p(f"     - {r['name']}  (score={r['score']:.0f})", YELLOW))
        print()

    if low:
        print(p("  [.] СЛАБЫЕ СИГНАЛЫ:", BOLD + LBLUE))
        for r in low:
            print(p(f"     - {r['name']}  (score={r['score']:.0f})", LBLUE))
        print()

    if not cheat and not high and not med:
        print(p("  [+] Ничего серьёзного не найдено", BOLD + GREEN))
        print()


def show_details(results, level):
    clear()
    titles = {
        "CERTAIN_CHEAT": "ОБНАРУЖЕННЫЕ ЧИТЫ",
        "HIGH": "ВЫСОКАЯ УВЕРЕННОСТЬ",
        "MEDIUM": "СРЕДНЯЯ УВЕРЕННОСТЬ",
        "LOW": "СЛАБЫЕ СИГНАЛЫ",
        "OK": "ЧИСТЫЕ МОДЫ",
    }
    col = confidence_color(level)
    print()
    print(p("=" * 70, CYAN))
    print(p(f"  {titles.get(level, level)}", BOLD + col))
    print(p("=" * 70, CYAN))
    print()
    sel = [r for r in results if r["confidence"] == level]
    sel.sort(key=lambda x: x["score"], reverse=True)
    if not sel:
        print(p(f"  Нет модов в этой категории", color=YELLOW))
        back_to_menu_hint()
        return
    for r in sel:
        print(p(f"  {confidence_mark(level)} {r['name']}  (score={r['score']:.0f})", BOLD + col))
        print(p(f"     Размер: {human_size(r['size'])} | классов: {r['class_count']} | "
                f"методов: {r['method_count']}", SKY))
        print(p(f"     обфускация: {r['obf_ratio']*100:.0f}% | "
                f"LineNumbers: {r['line_numbers_ratio']*100:.0f}% | "
                f"пакетов: {r['unique_packages']}", SKY))
        print(p(f"     SHA-1: {r['sha1']}", LBLUE))
        if r["modrinth"]:
            print(p(f"     Modrinth: {r['modrinth']['title']} "
                    f"({r['modrinth']['downloads']} downloads)", GREEN))
        print(p(f"     mod_id: {r['mod_id'] or '-'} | loader: {r['loader'] or '-'}", LBLUE))
        if r["signals"]:
            print(p("     Сигналы:", BOLD + col))
            for w, d in r["signals"]:
                print(p(f"       [{w}] {d}", col))
        print()
    back_to_menu_hint()


# ============================================================
#  Сохранение
# ============================================================
def save_report(results, stats, folder, mem_results):
    script_dir = Path(__file__).resolve().parent
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    txt_path = script_dir / f"mod_report_{ts}.txt"
    json_path = script_dir / f"mod_report_{ts}.json"
    log_path = script_dir / f"mod_scan_log_{ts}.log"

    L = []
    L.append("=" * 72)
    L.append("  MINECRAFT MOD & CHEAT DETECTOR v4.3 — ОТЧЁТ")
    L.append(f"  Дата: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    L.append(f"  Папка: {folder}")
    L.append(f"  Модов: {len(results)}")
    L.append("=" * 72)
    L.append("")

    L.append("─── JAR-АНАЛИЗ ───")
    L.append("")
    for r in sorted(results, key=lambda x: x["score"], reverse=True):
        L.append(f"[{r['confidence']}] {r['name']}  (score={r['score']:.0f})")
        L.append(f"  Размер: {human_size(r['size'])}")
        L.append(f"  SHA-1: {r['sha1']}")
        if r["modrinth"]:
            L.append(f"  Modrinth: {r['modrinth']['title']}")
        L.append(f"  mod_id: {r['mod_id'] or '-'} | loader: {r['loader'] or '-'}")
        if r["signals"]:
            L.append("  Сигналы:")
            for w, d in r["signals"]:
                L.append(f"    [{w}] {d}")
        L.append("")

    if mem_results and mem_results.get("memory"):
        mem = mem_results["memory"]
        L.append("=" * 72)
        L.append("─── СКАНИРОВАНИЕ ПАМЯТИ ───")
        L.append("=" * 72)
        L.append("")
        if mem.get("clean"):
            L.append("  ✓ ПАМЯТЬ ЧИСТА — читов не обнаружено")
        else:
            L.append("  ☠ ОБНАРУЖЕНЫ ЧИТЫ:")
            L.append("")
            for client, hits in mem.get("client_hits", {}).items():
                L.append(f"  ● {client} — {len(hits)} совпадений")
                for h in hits[:5]:
                    L.append(f"      {h['value'][:80]!r}")
                    L.append(f"      [{h['type']}] @0x{h['addr']:x}")
                L.append("")
            for f in mem.get("soft_findings", [])[:10]:
                L.append(f"  ⚠ SOFT: {f['sig']} (группа {f['chunk_group_size']})")
        L.append("")

    if mem_results and mem_results.get("inject"):
        inj = mem_results["inject"]
        L.append("=" * 72)
        L.append("─── СКАН ИНЖЕКТОВ ───")
        L.append("=" * 72)
        L.append("")
        if inj.get("clean"):
            L.append("  ✓ СТОРОННИХ DLL НЕ НАЙДЕНО")
        else:
            if inj.get("suspicious"):
                L.append(f"  ☠ ЯВНО ПОДОЗРИТЕЛЬНЫЕ: {len(inj['suspicious'])}")
                for m in inj["suspicious"]:
                    L.append(f"  ● {m['name']}")
                    L.append(f"      причина: {m['reason']}")
                    L.append(f"      path: {m['path']}")
                    L.append(f"      base: 0x{m['base']:x}")
                L.append("")
            if inj.get("external"):
                L.append(f"  ⚠ СТОРОННИЕ DLL: {len(inj['external'])}")
                for m in inj["external"]:
                    L.append(f"  ● {m['name']}")
                    L.append(f"      path: {m['path']}")
                    L.append(f"      base: 0x{m['base']:x}")
                L.append("")
        L.append(f"  Всего модулей: {inj.get('total_modules', 0)}")
        L.append("")

    txt_path.write_text("\n".join(L), encoding="utf-8")

    payload = {
        "generated_at": datetime.now().isoformat(),
        "scan_folder": str(folder),
        "stats": stats,
        "memory": mem_results.get("memory") if mem_results else None,
        "inject": mem_results.get("inject") if mem_results else None,
        "mods": [{
            "file": r["name"], "size": r["size"], "sha1": r["sha1"],
            "modrinth": r["modrinth"], "trusted": r["trusted"],
            "confidence": r["confidence"], "score": round(r["score"], 1),
            "mod_id": r["mod_id"], "loader": r["loader"],
            "hard_cheat_hits": r["hard_cheat_hits"],
            "soft_cheat_hits": r["soft_cheat_hits"],
            "signals": [{"weight": w, "desc": d} for w, d in r["signals"]],
        } for r in sorted(results, key=lambda x: x["score"], reverse=True)],
    }
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    log_path.write_text("\n".join(LOG_LINES), encoding="utf-8")
    return txt_path, json_path, log_path


# ============================================================
#  Меню
# ============================================================
def interactive_menu(results, stats, folder):
    state = {"memory": None, "inject": None}

    while True:
        clear()
        counts = Counter(r["confidence"] for r in results)
        print()
        print(p("╔" + "═" * 68 + "╗", CYAN))
        print(p("║", CYAN) + p(" ГЛАВНОЕ МЕНЮ ".center(68), BOLD + LBLUE) + p("║", CYAN))
        print(p("╚" + "═" * 68 + "╝", CYAN))
        print()
        print(p(f"  Папка: {folder}", SKY))
        print(p(f"  Всего модов: {len(results)}  |  "
                f"[X] {counts.get('CERTAIN_CHEAT', 0)}  "
                f"[!] {counts.get('HIGH', 0)}  "
                f"[*] {counts.get('MEDIUM', 0)}  "
                f"[.] {counts.get('LOW', 0)}  "
                f"[+] {counts.get('OK', 0)}", LBLUE))

        mem_st = state["memory"]
        inj_st = state["inject"]
        if mem_st:
            if mem_st.get("clean"):
                print(p(f"  Память:  ✓ ЧИСТО", GREEN))
            else:
                n_clients = len(mem_st.get("client_hits", {}))
                print(p(f"  Память:  ☠ {n_clients} клиентов найдено", RED))
        if inj_st:
            if inj_st.get("clean"):
                print(p(f"  Инжекты: ✓ сторонних DLL нет", GREEN))
            else:
                n_sus = len(inj_st.get("suspicious", []))
                n_ext = len(inj_st.get("external", []))
                print(p(f"  Инжекты: ☠ подозр.={n_sus}  сторонних={n_ext}", RED))
        print()

        print(p("  МОДЫ (JAR):", BOLD + LBLUE))
        print(p("  [1] ", RED) + p("[X]  Обнаруженные читы", WHITE))
        print(p("  [2] ", RED) + p("[!]  Высокая уверенность", WHITE))
        print(p("  [3] ", YELLOW) + p("[*]  Средняя уверенность", WHITE))
        print(p("  [4] ", LBLUE) + p("[.]  Слабые сигналы", WHITE))
        print(p("  [5] ", GREEN) + p("[+]  Чистые моды", WHITE))
        print()
        print(p("  ПРОЦЕСС MINECRAFT:", BOLD + LBLUE))
        print(p("  [6] ", MAGENTA) + p("Сканировать память javaw.exe (сигнатуры читов)", WHITE))
        print(p("  [7] ", MAGENTA) + p("Сканировать инжекты (любые сторонние DLL)", WHITE))
        print()
        print(p("  ОТЧЁТ:", BOLD + LBLUE))
        print(p("  [8] ", GREEN) + p("Сохранить полный отчёт", WHITE))
        print(p("  [0] ", RED) + p("Выход", WHITE))
        print()

        try:
            choice = input(p("  > Выбор: ", BOLD + CYAN)).strip()
        except (EOFError, KeyboardInterrupt):
            print(); break

        if choice == "0":
            print(); print(p("  До связи!", BOLD + LBLUE)); print(); break
        elif choice == "1": show_details(results, "CERTAIN_CHEAT")
        elif choice == "2": show_details(results, "HIGH")
        elif choice == "3": show_details(results, "MEDIUM")
        elif choice == "4": show_details(results, "LOW")
        elif choice == "5": show_details(results, "OK")
        elif choice == "6":
            r = scan_javaw_memory()
            if r is not None:
                state["memory"] = r
        elif choice == "7":
            r = scan_injects()
            if r is not None:
                state["inject"] = r
        elif choice == "8":
            txt, js, lg = save_report(results, stats, folder, state)
            clear()
            print()
            print(p("  [+] Отчёты сохранены:", BOLD + GREEN))
            print(p(f"    - {txt}", LBLUE))
            print(p(f"    - {js}", LBLUE))
            print(p(f"    - {lg}", LBLUE))
            print()
            back_to_menu_hint()
        else:
            print(p("  Неверный выбор", RED)); time.sleep(1)


# ============================================================
#  Main
# ============================================================
def main():
    clear()
    print()
    print(p("╔" + "═" * 68 + "╗", CYAN))
    print(p("║", CYAN) + p(" MINECRAFT MOD & CHEAT DETECTOR v4.3 ".center(68), BOLD + LBLUE) + p("║", CYAN))
    print(p("║", CYAN) + p(" JAR · Memory · Any external DLL ".center(68), SKY) + p("║", CYAN))
    print(p("╚" + "═" * 68 + "╝", CYAN))
    print()

    if is_admin():
        print(p("  [+] Права администратора: есть", GREEN))
    else:
        print(p("  [!] Права администратора: НЕТ", YELLOW))
        print(p("      сканирование памяти/инжектов будет недоступно", DIM + YELLOW))
    print()

    default = "."
    try:
        raw = input(p("  Путь к папке с модами", BOLD + LBLUE)
                    + p(f" [{default}]: ", DIM)).strip().strip('"').strip("'")
    except (EOFError, KeyboardInterrupt):
        print(); return

    folder = Path(raw) if raw else Path(default)
    if not folder.exists() or not folder.is_dir():
        print(p(f"\n  X Папка не найдена: {folder}", RED)); return

    jars = sorted(folder.glob("*.jar"))
    if not jars:
        print(p(f"\n  X Нет .jar в {folder}", RED)); return

    print()
    print(p("  Анализ JAR...", BOLD + SKY))
    print(p(f"  Модов: {len(jars)}", LBLUE))
    print()

    results = []
    t0 = time.time()
    for i, jar in enumerate(jars, 1):
        sys.stdout.write(p(f"\r  [{i}/{len(jars)}] {jar.name[:55]:<55}", DIM + SKY))
        sys.stdout.flush()
        results.append(analyze_jar(jar, verbose=False))
    dt = time.time() - t0
    print()
    print(p(f"  [+] Готово за {dt:.1f} сек", BOLD + GREEN))
    time.sleep(0.6)

    stats = compute_weight_anomalies(results)
    show_final_summary(results)
    press_enter()
    interactive_menu(results, stats, folder)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(p("\n\n  Прервано пользователем.", RED))