# -*- coding: utf-8 -*-
"""
Windows 文件/文件夹进程占用检测工具
=====================================
解决删除文件时提示"文件夹正在使用"的问题。

核心技术：
  - Windows Restart Manager API（微软官方接口，无需管理员权限即可检测占用）
  - 备选：枚举进程当前工作目录（CWD）检测
  - 支持结束占用进程、强制删除、重启后删除等操作

作者：自动生成
依赖：Python 3.8+，仅使用标准库（tkinter + ctypes）
"""

import os
import sys
import ctypes
import ctypes.wintypes as wt
import subprocess
import threading
import time
from pathlib import Path
from ctypes import (
    Structure, POINTER, byref, sizeof, c_uint, c_ulong, c_void_p,
    c_wchar_p, c_bool, c_int, WinError, get_last_error,
    c_ushort, c_ubyte, c_long, c_size_t
)

# ============================================================
#  Windows API 常量与结构体定义
# ============================================================

# --- Restart Manager 常量 ---
CCH_RM_MAX_APP_NAME = 255
CCH_RM_MAX_SVC_NAME = 63
RM_INVALID_SESSION = 0xFFFFFFFF
ERROR_MORE_DATA = 234
ERROR_SUCCESS = 0

# RM_APP_TYPE
class RM_APP_TYPE:
    RmUnknownApp = 0
    RmMainWindow = 1
    RmOtherWindow = 2
    RmService = 3
    RmExplorer = 4
    RmConsole = 5
    RmCritical = 1000

APP_TYPE_NAMES = {
    0: "未知应用",
    1: "主窗口程序",
    2: "其他窗口程序",
    3: "系统服务",
    4: "资源管理器",
    5: "控制台程序",
    1000: "关键系统进程",
}

# RM_REBOOT_REASON (bitmask)
class RM_REBOOT_REASON:
    RmRebootReasonNone = 0x0
    RmRebootReasonPermissionDenied = 0x1
    RmRebootReasonSessionMismatch = 0x2
    RmRebootReasonCriticalProcess = 0x4
    RmRebootReasonCriticalService = 0x8
    RmRebootReasonDetectedSelf = 0x10

# RM_SHUTDOWN_TYPE
RM_SHUTDOWN_TYPE = {
    "RmForceShutdown": 0x1,
    "RmShutdownOnlyRegistered": 0x10,
}

# --- 进程权限常量 ---
PROCESS_TERMINATE = 0x0001
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

# --- MoveFileEx 标志 ---
MOVEFILE_DELAY_UNTIL_REBOOT = 0x4
MOVEFILE_REPLACE_EXISTING = 0x1

# ============================================================
#  Restart Manager 结构体
# ============================================================

class FILETIME(Structure):
    _fields_ = [
        ("dwLowDateTime", wt.DWORD),
        ("dwHighDateTime", wt.DWORD),
    ]

class RM_UNIQUE_PROCESS(Structure):
    _fields_ = [
        ("dwProcessId", wt.DWORD),
        ("ProcessStartTime", FILETIME),
    ]

class RM_PROCESS_INFO(Structure):
    _fields_ = [
        ("Process", RM_UNIQUE_PROCESS),
        ("strAppName", ctypes.c_wchar * (CCH_RM_MAX_APP_NAME + 1)),
        ("strServiceShortName", ctypes.c_wchar * (CCH_RM_MAX_SVC_NAME + 1)),
        ("ApplicationType", c_uint),
        ("AppStatus", c_ulong),
        ("TSSessionId", wt.DWORD),
        ("bRestartable", c_bool),
    ]

# ============================================================
#  加载 rstrtmgr.dll 并声明函数原型
# ============================================================

_rstrtmgr = ctypes.WinDLL("rstrtmgr.dll", use_last_error=True)
_kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)

# RmStartSession
_rstrtmgr.RmStartSession.argtypes = [
    POINTER(wt.DWORD), wt.DWORD, ctypes.c_wchar_p
]
_rstrtmgr.RmStartSession.restype = c_int

# RmRegisterResources
_rstrtmgr.RmRegisterResources.argtypes = [
    wt.DWORD, c_uint, POINTER(c_wchar_p),
    c_uint, c_void_p, c_uint, c_void_p
]
_rstrtmgr.RmRegisterResources.restype = c_int

# RmGetList
_rstrtmgr.RmGetList.argtypes = [
    wt.DWORD, POINTER(c_uint), POINTER(c_uint),
    POINTER(RM_PROCESS_INFO), POINTER(c_ulong)
]
_rstrtmgr.RmGetList.restype = c_int

# RmShutdown
_rstrtmgr.RmShutdown.argtypes = [wt.DWORD, c_ulong, c_void_p]
_rstrtmgr.RmShutdown.restype = c_int

# RmEndSession
_rstrtmgr.RmEndSession.argtypes = [wt.DWORD]
_rstrtmgr.RmEndSession.restype = c_int

# --- kernel32 函数 ---
_kernel32.OpenProcess.argtypes = [wt.DWORD, c_bool, wt.DWORD]
_kernel32.OpenProcess.restype = c_void_p

_kernel32.CloseHandle.argtypes = [c_void_p]
_kernel32.CloseHandle.restype = c_bool

_kernel32.TerminateProcess.argtypes = [c_void_p, c_uint]
_kernel32.TerminateProcess.restype = c_bool

_kernel32.QueryFullProcessImageNameW.argtypes = [
    c_void_p, wt.DWORD, ctypes.c_wchar_p, POINTER(wt.DWORD)
]
_kernel32.QueryFullProcessImageNameW.restype = c_bool

_kernel32.MoveFileExW.argtypes = [c_wchar_p, c_wchar_p, wt.DWORD]
_kernel32.MoveFileExW.restype = c_bool

_kernel32.DeleteFileW.argtypes = [c_wchar_p]
_kernel32.DeleteFileW.restype = c_bool

_kernel32.RemoveDirectoryW.argtypes = [c_wchar_p]
_kernel32.RemoveDirectoryW.restype = c_bool

# ============================================================
#  核心检测逻辑
# ============================================================

class LockedProcessInfo:
    """占用进程信息封装"""
    def __init__(self, pid, app_name, svc_name, app_type,
                 app_status, ts_session_id, restartable, exe_path=""):
        self.pid = pid
        self.app_name = app_name
        self.svc_name = svc_name
        self.app_type = app_type
        self.app_status = app_status
        self.ts_session_id = ts_session_id
        self.restartable = restartable
        self.exe_path = exe_path

    @property
    def type_name(self):
        return APP_TYPE_NAMES.get(self.app_type, f"未知({self.app_type})")

    @property
    def status_text(self):
        if self.app_type == RM_APP_TYPE.RmService:
            return "服务运行中"
        if self.app_type == RM_APP_TYPE.RmCritical:
            return "关键进程(不可结束)"
        return "运行中"

    def __repr__(self):
        return f"<LockedProcess PID={self.pid} name={self.app_name}>"


def get_process_exe_path(pid):
    """通过 Windows API 获取进程可执行文件完整路径"""
    if pid <= 0:
        return ""
    h_process = _kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h_process:
        # 尝试更宽的权限
        h_process = _kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
    if not h_process:
        return ""
    try:
        buf_size = wt.DWORD(32768)
        buf = ctypes.create_unicode_buffer(buf_size.value)
        if _kernel32.QueryFullProcessImageNameW(h_process, 0, buf, byref(buf_size)):
            return buf.value
        return ""
    finally:
        _kernel32.CloseHandle(h_process)


def detect_locks_via_restart_manager(path):
    """
    使用 Restart Manager API 检测占用指定文件/文件夹的进程。
    返回 (进程列表, 错误信息)
    """
    path = os.path.abspath(path)
    if not os.path.exists(path):
        return [], f"路径不存在: {path}"

    session_handle = wt.DWORD(0)
    session_key = f"lock_detector_{int(time.time()*1000)}_{os.getpid()}"

    # 1. 启动会话
    ret = _rstrtmgr.RmStartSession(byref(session_handle), 0, session_key)
    if ret != ERROR_SUCCESS:
        return [], f"RmStartSession 失败，错误码: {ret}"

    try:
        # 2. 注册资源（文件/文件夹）
        # 对于文件夹，Restart Manager 也能检测其内部文件的占用
        file_array = (c_wchar_p * 1)(path)
        ret = _rstrtmgr.RmRegisterResources(
            session_handle.value, 1, file_array, 0, None, 0, None
        )
        if ret != ERROR_SUCCESS:
            return [], f"RmRegisterResources 失败，错误码: {ret}"

        # 3. 获取占用进程列表（先查询需要的数量）
        pn_proc_info_needed = c_uint(0)
        pn_proc_info = c_uint(0)
        reboot_reasons = c_ulong(0)

        ret = _rstrtmgr.RmGetList(
            session_handle.value,
            byref(pn_proc_info_needed),
            byref(pn_proc_info),
            None,
            byref(reboot_reasons)
        )

        if ret not in (ERROR_SUCCESS, ERROR_MORE_DATA):
            return [], f"RmGetList 查询数量失败，错误码: {ret}"

        needed = pn_proc_info_needed.value
        if needed == 0:
            return [], None  # 没有占用

        # 分配数组并再次获取
        proc_array = (RM_PROCESS_INFO * needed)()
        pn_proc_info = c_uint(needed)
        reboot_reasons = c_ulong(0)

        ret = _rstrtmgr.RmGetList(
            session_handle.value,
            byref(pn_proc_info_needed),
            byref(pn_proc_info),
            proc_array,
            byref(reboot_reasons)
        )

        if ret != ERROR_SUCCESS and ret != ERROR_MORE_DATA:
            return [], f"RmGetList 获取详情失败，错误码: {ret}"

        # 解析结果
        results = []
        count = pn_proc_info.value
        for i in range(count):
            info = proc_array[i]
            pid = info.Process.dwProcessId
            exe_path = get_process_exe_path(pid)
            proc = LockedProcessInfo(
                pid=pid,
                app_name=info.strAppName,
                svc_name=info.strServiceShortName,
                app_type=info.ApplicationType,
                app_status=info.AppStatus,
                ts_session_id=info.TSSessionId,
                restartable=info.bRestartable,
                exe_path=exe_path,
            )
            results.append(proc)

        return results, None

    finally:
        _rstrtmgr.RmEndSession(session_handle.value)


# ============================================================
#  底层进程 CWD（当前工作目录）枚举
#  通过读取进程 PEB -> ProcessParameters -> CurrentDirectory
#  捕获 Restart Manager 漏掉的"文件夹作为工作目录"场景
# ============================================================

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
ProcessBasicInformation = 0
CURRENT_DIRECTORY_OFFSET = 0x38  # 64位 Windows 中 RTL_USER_PROCESS_PARAMETERS.CurrentDirectory 偏移
TH32CS_SNAPPROCESS = 0x00000002

class UNICODE_STRING(Structure):
    _fields_ = [
        ("Length", c_ushort),
        ("MaximumLength", c_ushort),
        ("Buffer", c_void_p),
    ]

class PROCESS_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("Reserved1", c_void_p),
        ("PebBaseAddress", c_void_p),
        ("Reserved2", c_void_p * 2),
        ("UniqueProcessId", c_void_p),
        ("Reserved3", c_void_p),
    ]

class PEB_PARTIAL(Structure):
    _fields_ = [
        ("InheritedAddressSpace", c_ubyte),
        ("ReadImageFileExecOptions", c_ubyte),
        ("BeingDebugged", c_ubyte),
        ("BitField", c_ubyte),
        ("Mutant", c_void_p),
        ("ImageBaseAddress", c_void_p),
        ("Ldr", c_void_p),
        ("ProcessParameters", c_void_p),
    ]

class PROCESSENTRY32W(Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", POINTER(c_ulong)),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", c_long),
        ("dwFlags", wt.DWORD),
        ("szExeFile", ctypes.c_wchar * 260),
    ]

_ntdll = ctypes.WinDLL("ntdll.dll", use_last_error=True)

_ntdll.NtQueryInformationProcess.argtypes = [
    c_void_p, c_int, c_void_p, c_ulong, POINTER(c_ulong)
]
_ntdll.NtQueryInformationProcess.restype = c_int

_kernel32.ReadProcessMemory.argtypes = [
    c_void_p, c_void_p, c_void_p, c_size_t, POINTER(c_size_t)
]
_kernel32.ReadProcessMemory.restype = c_bool

_kernel32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
_kernel32.CreateToolhelp32Snapshot.restype = c_void_p

_kernel32.Process32First.argtypes = [c_void_p, c_void_p]
_kernel32.Process32First.restype = c_bool

_kernel32.Process32Next.argtypes = [c_void_p, c_void_p]
_kernel32.Process32Next.restype = c_bool


def _enum_all_processes():
    """枚举所有进程，返回 [(pid, exe_name), ...]"""
    processes = []
    snapshot = _kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snapshot or snapshot == c_void_p(-1).value:
        return processes
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = sizeof(PROCESSENTRY32W)
        if _kernel32.Process32First(snapshot, byref(entry)):
            while True:
                processes.append((entry.th32ProcessID, entry.szExeFile))
                if not _kernel32.Process32Next(snapshot, byref(entry)):
                    break
    finally:
        _kernel32.CloseHandle(snapshot)
    return processes


def _read_process_memory(h_process, address, size):
    buf = ctypes.create_string_buffer(size)
    bytes_read = c_size_t(0)
    if _kernel32.ReadProcessMemory(h_process, c_void_p(address), buf, size, byref(bytes_read)):
        return buf.raw[:bytes_read.value]
    return None


def _get_process_cwd(pid):
    """通过 PEB 获取进程的真实当前工作目录"""
    h_process = _kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid
    )
    if not h_process:
        return None
    try:
        pbi = PROCESS_BASIC_INFORMATION()
        return_len = c_ulong(0)
        status = _ntdll.NtQueryInformationProcess(
            h_process, ProcessBasicInformation,
            byref(pbi), sizeof(PROCESS_BASIC_INFORMATION),
            byref(return_len)
        )
        if status != 0 or not pbi.PebBaseAddress:
            return None

        peb_data = _read_process_memory(h_process, pbi.PebBaseAddress, sizeof(PEB_PARTIAL))
        if not peb_data:
            return None
        peb = PEB_PARTIAL.from_buffer_copy(peb_data)
        if not peb.ProcessParameters:
            return None

        cd_data = _read_process_memory(
            h_process, peb.ProcessParameters + CURRENT_DIRECTORY_OFFSET,
            sizeof(UNICODE_STRING)
        )
        if not cd_data:
            return None
        cd = UNICODE_STRING.from_buffer_copy(cd_data)
        if not cd.Buffer or cd.Length == 0:
            return None

        path_data = _read_process_memory(h_process, cd.Buffer, cd.Length)
        if not path_data:
            return None
        try:
            return path_data.decode("utf-16-le", errors="replace").rstrip("\x00")
        except Exception:
            return None
    finally:
        _kernel32.CloseHandle(h_process)


def detect_locks_via_cwd_scan(path):
    """
    备选方案：枚举所有进程的真实当前工作目录(CWD)，
    检测是否有进程的 CWD 位于目标路径下。
    这能捕获 Restart Manager 漏掉的"文件夹作为工作目录"场景。
    """
    path = os.path.abspath(path).lower().rstrip("\\")
    results = []
    try:
        for pid, exe_name in _enum_all_processes():
            if pid in (0, 4):  # System Idle / System
                continue
            try:
                cwd = _get_process_cwd(pid)
                if cwd:
                    cwd_lower = cwd.lower().rstrip("\\")
                    if cwd_lower == path or cwd_lower.startswith(path + "\\"):
                        exe_path = get_process_exe_path(pid)
                        # 优先用可执行文件的文件名作为进程名（避免 Toolhelp32 编码问题）
                        display_name = exe_name
                        if exe_path:
                            try:
                                base = os.path.basename(exe_path)
                                if base:
                                    display_name = base
                            except Exception:
                                pass
                        results.append(LockedProcessInfo(
                            pid=pid,
                            app_name=display_name,
                            svc_name="",
                            app_type=RM_APP_TYPE.RmConsole,
                            app_status=0,
                            ts_session_id=0,
                            restartable=False,
                            exe_path=exe_path,
                        ))
            except Exception:
                continue
    except Exception:
        pass
    return results


def detect_all_locks(path):
    """综合检测：Restart Manager + CWD扫描，去重合并"""
    all_results = {}

    # 主方案
    rm_results, err = detect_locks_via_restart_manager(path)
    for p in rm_results:
        all_results[p.pid] = p

    # 备选方案（补充）
    if os.path.isdir(path):
        cwd_results = detect_locks_via_cwd_scan(path)
        for p in cwd_results:
            if p.pid not in all_results:
                all_results[p.pid] = p

    return list(all_results.values()), err


# ============================================================
#  进程操作
# ============================================================

def terminate_process(pid, force=True):
    """结束指定进程，返回 (是否成功, 消息)"""
    if pid <= 0:
        return False, "无效的 PID"

    # 优先使用 taskkill（支持子进程树和强制模式）
    try:
        cmd = ["taskkill", "/PID", str(pid), "/T"]
        if force:
            cmd.append("/F")
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10,
            encoding="gbk", errors="replace"
        )
        if result.returncode == 0:
            return True, f"进程 {pid} 已结束"
        # taskkill 失败时尝试 API
    except Exception:
        pass

    # 备选：直接调用 TerminateProcess
    h_process = _kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
    if not h_process:
        err = get_last_error()
        return False, f"无法打开进程 {pid}（错误码 {err}），可能需要管理员权限"
    try:
        if _kernel32.TerminateProcess(h_process, 1):
            return True, f"进程 {pid} 已结束"
        else:
            err = get_last_error()
            return False, f"结束进程 {pid} 失败（错误码 {err}）"
    finally:
        _kernel32.CloseHandle(h_process)


def is_process_running(pid):
    """检查进程是否仍在运行"""
    if pid <= 0:
        return False
    try:
        result = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/NH"],
            capture_output=True, text=True, timeout=5,
            encoding="gbk", errors="replace"
        )
        return str(pid) in result.stdout
    except Exception:
        return False


# ============================================================
#  文件删除操作
# ============================================================

def delete_path(path):
    """
    尝试删除文件或文件夹，使用多种方式。
    返回 (是否成功, 消息)
    """
    path = os.path.abspath(path)
    if not os.path.exists(path):
        return True, "路径已不存在（可能已被删除）"

    try:
        if os.path.isfile(path):
            os.remove(path)
            return True, f"文件已删除: {path}"
        else:
            import shutil
            shutil.rmtree(path, ignore_errors=False)
            return True, f"文件夹已删除: {path}"
    except PermissionError:
        # 尝试使用命令行强制删除
        try:
            if os.path.isfile(path):
                result = subprocess.run(
                    ["cmd", "/c", "del", "/f", "/q", path],
                    capture_output=True, text=True, timeout=10,
                    encoding="gbk", errors="replace"
                )
            else:
                result = subprocess.run(
                    ["cmd", "/c", "rmdir", "/s", "/q", path],
                    capture_output=True, text=True, timeout=15,
                    encoding="gbk", errors="replace"
                )
            if not os.path.exists(path):
                return True, f"强制删除成功: {path}"
            return False, f"删除失败，文件仍被占用或权限不足: {path}"
        except Exception as e:
            return False, f"删除异常: {e}"
    except Exception as e:
        return False, f"删除异常: {e}"


def schedule_delete_on_reboot(path):
    """
    注册文件/文件夹在系统重启时自动删除（需要管理员权限）。
    返回 (是否成功, 消息)
    """
    path = os.path.abspath(path)
    if not os.path.exists(path):
        return True, "路径已不存在"

    # 对于文件夹，需要先递归注册所有文件
    paths_to_delete = []
    if os.path.isdir(path):
        for root, dirs, files in os.walk(path, topdown=False):
            for f in files:
                paths_to_delete.append(os.path.join(root, f))
            for d in dirs:
                paths_to_delete.append(os.path.join(root, d))
        paths_to_delete.append(path)
    else:
        paths_to_delete.append(path)

    success_count = 0
    for p in paths_to_delete:
        if _kernel32.MoveFileExW(p, None, MOVEFILE_DELAY_UNTIL_REBOOT):
            success_count += 1

    if success_count == len(paths_to_delete):
        return True, f"已注册 {success_count} 个项目在重启后删除"
    elif success_count > 0:
        return False, f"部分注册成功（{success_count}/{len(paths_to_delete)}），部分可能需要管理员权限"
    else:
        return False, "注册失败，可能需要管理员权限（右键以管理员身份运行）"


# ============================================================
#  GUI 界面
# ============================================================

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext


# ============================================================
#  高 DPI 与图标辅助
# ============================================================

def setup_dpi_awareness():
    """在创建窗口前设置进程 DPI 感知，返回 DPI 缩放比例"""
    scale = 1.0
    try:
        # Windows 8.1+: Per-Monitor DPI Aware
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass
    # 获取系统 DPI 缩放
    try:
        hwnd = ctypes.windll.user32.GetDesktopWindow()
        dpi = ctypes.windll.user32.GetDpiForWindow(hwnd)
        if dpi and dpi > 0:
            scale = dpi / 96.0
    except Exception:
        try:
            hdc = ctypes.windll.user32.GetDC(0)
            dpi = ctypes.windll.gdi32.GetDeviceCaps(hdc, 88)  # LOGPIXELSX
            ctypes.windll.user32.ReleaseDC(0, hdc)
            if dpi and dpi > 0:
                scale = dpi / 96.0
        except Exception:
            pass
    return scale


def get_resource_path(relative_path):
    """获取资源文件路径，兼容开发模式和 PyInstaller 打包模式"""
    if getattr(sys, 'frozen', False):
        # 打包后：资源在 _MEIPASS 临时目录
        base_path = getattr(sys, '_MEIPASS', os.path.dirname(sys.executable))
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)


def load_window_icon(root):
    """
    加载窗口图标，去除 tkinter 默认羽毛图标。
    优先级：打包后从 exe 自身提取 → 开发模式从 ico 文件加载。
    """
    # 打包后：从 exe 自身加载第一个图标资源
    if getattr(sys, 'frozen', False):
        try:
            root.iconbitmap(sys.executable)
            return True
        except Exception:
            pass

    # 开发模式：从 ico 文件加载
    icon_path = get_resource_path('app_icon.ico')
    if os.path.exists(icon_path):
        try:
            root.iconbitmap(icon_path)
            return True
        except Exception:
            pass

    # 最后手段：用 iconphoto 设置图标覆盖羽毛图标（动态导入 PIL，避免打包膨胀）
    try:
        import importlib
        Image = importlib.import_module('PIL.Image')
        ImageTk = importlib.import_module('PIL.ImageTk')
        icon_path = get_resource_path('app_icon.ico')
        if os.path.exists(icon_path):
            img = Image.open(icon_path)
            photo = ImageTk.PhotoImage(img)
            root.iconphoto(True, photo)
            root._icon_ref = photo  # 防止被垃圾回收
            return True
    except Exception:
        pass
    return False


class FileLockDetectorApp:
    def __init__(self, root, dpi_scale=1.0):
        self.root = root
        self.dpi_scale = dpi_scale
        self.root.title("Windows 文件占用检测工具")

        # 根据 DPI 缩放调整窗口初始尺寸
        base_w, base_h = 960, 640
        win_w = int(base_w * dpi_scale)
        win_h = int(base_h * dpi_scale)
        self.root.geometry(f"{win_w}x{win_h}")
        self.root.minsize(int(820 * dpi_scale), int(520 * dpi_scale))

        # 加载自定义图标（去除默认羽毛图标）
        load_window_icon(root)

        self.locked_processes = []
        self._build_ui()
        self._set_style()

    def _set_style(self):
        s = self.dpi_scale
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        # 根据 DPI 缩放字体大小
        title_size = max(10, int(11 * s))
        status_size = max(8, int(9 * s))
        tree_size = max(8, int(9 * s))
        row_height = max(22, int(26 * s))

        font_family = "Microsoft YaHei UI"
        style.configure("Title.TLabel", font=(font_family, title_size, "bold"))
        style.configure("Status.TLabel", font=(font_family, status_size))
        style.configure("Treeview", font=(font_family, tree_size), rowheight=row_height)
        style.configure("Treeview.Heading", font=(font_family, tree_size, "bold"))
        # 通用控件字体
        style.configure("TLabel", font=(font_family, tree_size))
        style.configure("TButton", font=(font_family, tree_size))
        style.configure("TEntry", font=(font_family, tree_size))
        style.configure("TLabelframe", font=(font_family, tree_size))
        style.configure("TLabelframe.Label", font=(font_family, tree_size, "bold"))

    def _build_ui(self):
        # 顶部：路径输入区
        top_frame = ttk.LabelFrame(self.root, text=" 目标路径 ", padding=10)
        top_frame.pack(fill=tk.X, padx=12, pady=(12, 6))

        path_row = ttk.Frame(top_frame)
        path_row.pack(fill=tk.X)

        ttk.Label(path_row, text="文件/文件夹:").pack(side=tk.LEFT)
        self.path_var = tk.StringVar()
        self.path_entry = ttk.Entry(path_row, textvariable=self.path_var, font=("Consolas", 10))
        self.path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=8)
        self.path_entry.bind("<Return>", lambda e: self.start_detect())

        ttk.Button(path_row, text="浏览文件...", command=self._browse_file, width=12).pack(side=tk.LEFT, padx=2)
        ttk.Button(path_row, text="浏览文件夹...", command=self._browse_folder, width=12).pack(side=tk.LEFT, padx=2)
        self.detect_btn = ttk.Button(path_row, text="检测占用", command=self.start_detect, width=12)
        self.detect_btn.pack(side=tk.LEFT, padx=(8, 0))

        # 中部：进程列表
        mid_frame = ttk.LabelFrame(self.root, text=" 占用进程列表 ", padding=6)
        mid_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=6)

        columns = ("pid", "name", "type", "status", "restartable", "exe_path")
        self.tree = ttk.Treeview(mid_frame, columns=columns, show="headings", selectmode="extended")

        self.tree.heading("pid", text="PID")
        self.tree.heading("name", text="进程名称")
        self.tree.heading("type", text="类型")
        self.tree.heading("status", text="状态")
        self.tree.heading("restartable", text="可重启")
        self.tree.heading("exe_path", text="可执行文件路径")

        s = self.dpi_scale
        self.tree.column("pid", width=int(70 * s), anchor=tk.CENTER, stretch=False)
        self.tree.column("name", width=int(160 * s), stretch=False)
        self.tree.column("type", width=int(110 * s), stretch=False)
        self.tree.column("status", width=int(100 * s), stretch=False)
        self.tree.column("restartable", width=int(60 * s), anchor=tk.CENTER, stretch=False)
        self.tree.column("exe_path", width=int(380 * s), stretch=True)

        # 滚动条
        vsb = ttk.Scrollbar(mid_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        # 双击行打开进程所在位置
        self.tree.bind("<Double-1>", self._on_tree_double_click)

        # 底部：操作按钮区
        btn_frame = ttk.Frame(self.root, padding=(12, 4))
        btn_frame.pack(fill=tk.X)

        self.kill_btn = ttk.Button(btn_frame, text="结束选中进程", command=self._kill_selected, state=tk.DISABLED)
        self.kill_btn.pack(side=tk.LEFT, padx=2)

        self.kill_del_btn = ttk.Button(btn_frame, text="结束进程并删除", command=self._kill_and_delete, state=tk.DISABLED)
        self.kill_del_btn.pack(side=tk.LEFT, padx=2)

        self.open_loc_btn = ttk.Button(btn_frame, text="打开进程位置", command=self._open_process_location, state=tk.DISABLED)
        self.open_loc_btn.pack(side=tk.LEFT, padx=2)

        self.force_del_btn = ttk.Button(btn_frame, text="强制删除目标", command=self._force_delete)
        self.force_del_btn.pack(side=tk.LEFT, padx=2)

        self.reboot_del_btn = ttk.Button(btn_frame, text="重启后删除", command=self._reboot_delete)
        self.reboot_del_btn.pack(side=tk.LEFT, padx=2)

        ttk.Button(btn_frame, text="清空列表", command=self._clear_results).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="退出", command=self.root.quit).pack(side=tk.RIGHT, padx=2)

        # 状态栏
        self.status_var = tk.StringVar(value="就绪。请输入或选择要检测的文件/文件夹路径。")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, anchor=tk.W,
                                padding=(12, 6), style="Status.TLabel", relief=tk.SUNKEN)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)

        # 日志区
        log_frame = ttk.LabelFrame(self.root, text=" 操作日志 ", padding=4)
        log_frame.pack(fill=tk.X, padx=12, pady=(0, 6))
        self.log_text = scrolledtext.ScrolledText(
            log_frame, height=5, font=("Consolas", 9), wrap=tk.WORD,
            bg="#1e1e1e", fg="#d4d4d4", insertbackground="white"
        )
        self.log_text.pack(fill=tk.X)
        self.log_text.configure(state=tk.DISABLED)

    # ---------- 路径浏览 ----------
    def _browse_file(self):
        path = filedialog.askopenfilename(title="选择要检测的文件")
        if path:
            self.path_var.set(path)

    def _browse_folder(self):
        path = filedialog.askdirectory(title="选择要检测的文件夹")
        if path:
            self.path_var.set(path)

    # ---------- 日志 ----------
    def _log(self, msg, level="INFO"):
        timestamp = time.strftime("%H:%M:%S")
        color_map = {"INFO": "#d4d4d4", "SUCCESS": "#4ec9b0", "WARN": "#dcdcaa", "ERROR": "#f48771"}
        tag = f"log_{level}"
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"[{timestamp}] ", "log_time")
        self.log_text.insert(tk.END, f"{msg}\n", tag)
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)
        # 配置颜色
        self.log_text.tag_configure("log_time", foreground="#808080")
        for lv, clr in color_map.items():
            self.log_text.tag_configure(f"log_{lv}", foreground=clr)

    def _set_status(self, msg):
        self.status_var.set(msg)

    # ---------- 检测 ----------
    def start_detect(self):
        path = self.path_var.get().strip().strip('"').strip("'")
        if not path:
            messagebox.showwarning("提示", "请先输入或选择要检测的路径。")
            return
        if not os.path.exists(path):
            messagebox.showerror("错误", f"路径不存在:\n{path}")
            return

        self._clear_results()
        self.detect_btn.configure(state=tk.DISABLED, text="检测中...")
        self._set_status(f"正在检测: {path}")
        self._log(f"开始检测路径: {path}")

        # 后台线程执行检测，避免界面卡顿
        t = threading.Thread(target=self._do_detect, args=(path,), daemon=True)
        t.start()

    def _do_detect(self, path):
        try:
            results, err = detect_all_locks(path)
            # 回到主线程更新 UI
            self.root.after(0, lambda: self._on_detect_done(results, err, path))
        except Exception as e:
            self.root.after(0, lambda: self._on_detect_done([], str(e), path))

    def _on_detect_done(self, results, err, path):
        self.detect_btn.configure(state=tk.NORMAL, text="检测占用")
        self.locked_processes = results

        if err and not results:
            self._set_status(f"检测出错: {err}")
            self._log(f"检测出错: {err}", "ERROR")
            messagebox.showerror("检测失败", err)
            return

        # 填充列表
        for p in results:
            self.tree.insert("", tk.END, iid=str(p.pid), values=(
                p.pid,
                p.app_name or "(未知名称)",
                p.type_name,
                p.status_text,
                "是" if p.restartable else "否",
                p.exe_path or "(无法获取路径)",
            ))

        if results:
            self._set_status(f"检测完成：发现 {len(results)} 个进程正在占用该路径。")
            self._log(f"检测完成，发现 {len(results)} 个占用进程", "SUCCESS")
            self._update_buttons_state()
        else:
            self._set_status("检测完成：未发现占用进程。该路径当前可以正常删除。")
            self._log("未发现占用进程，路径可正常删除", "SUCCESS")
            if messagebox.askyesno("未发现占用", "未检测到占用该路径的进程。\n\n是否现在尝试删除该文件/文件夹？"):
                self._force_delete()

    def _update_buttons_state(self):
        has_selection = bool(self.tree.selection())
        state = tk.NORMAL if has_selection else tk.DISABLED
        self.kill_btn.configure(state=state)
        self.kill_del_btn.configure(state=state)
        self.open_loc_btn.configure(state=state)

    def _clear_results(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.locked_processes = []
        self._update_buttons_state()

    # ---------- 进程操作 ----------
    def _get_selected_pids(self):
        return [int(iid) for iid in self.tree.selection()]

    def _get_process_by_pid(self, pid):
        for p in self.locked_processes:
            if p.pid == pid:
                return p
        return None

    def _kill_selected(self):
        pids = self._get_selected_pids()
        if not pids:
            return
        if not messagebox.askyesno("确认结束进程",
                                     f"确定要结束以下 {len(pids)} 个进程吗？\n\n"
                                     + "\n".join(f"  PID {pid}: {self._get_process_by_pid(pid).app_name}" for pid in pids)
                                     + "\n\n未保存的数据可能会丢失。"):
            return

        for pid in pids:
            proc = self._get_process_by_pid(pid)
            if proc and proc.app_type == RM_APP_TYPE.RmCritical:
                self._log(f"跳过关键系统进程 PID={pid} ({proc.app_name})", "WARN")
                continue
            ok, msg = terminate_process(pid, force=True)
            level = "SUCCESS" if ok else "ERROR"
            self._log(f"结束进程 PID={pid}: {msg}", level)

        # 刷新检测
        self.root.after(500, self.start_detect)

    def _kill_and_delete(self):
        pids = self._get_selected_pids()
        path = self.path_var.get().strip().strip('"').strip("'")
        if not pids or not path:
            return

        if not messagebox.askyesno("确认操作",
                                     f"将结束 {len(pids)} 个占用进程，然后删除:\n{path}\n\n此操作不可恢复，确定继续吗？"):
            return

        # 结束所有选中进程
        for pid in pids:
            proc = self._get_process_by_pid(pid)
            if proc and proc.app_type == RM_APP_TYPE.RmCritical:
                self._log(f"跳过关键系统进程 PID={pid}", "WARN")
                continue
            ok, msg = terminate_process(pid, force=True)
            self._log(f"结束进程 PID={pid}: {msg}", "SUCCESS" if ok else "ERROR")

        # 等待进程退出
        time.sleep(1)

        # 删除
        ok, msg = delete_path(path)
        self._log(f"删除结果: {msg}", "SUCCESS" if ok else "ERROR")
        if ok:
            messagebox.showinfo("成功", msg)
            self._clear_results()
            self._set_status("文件/文件夹已成功删除。")
        else:
            if messagebox.askyesno("删除失败", msg + "\n\n是否尝试注册为重启后删除？"):
                self._reboot_delete()

    def _on_tree_double_click(self, event):
        self._open_process_location()

    def _open_process_location(self):
        pids = self._get_selected_pids()
        if not pids:
            return
        pid = pids[0]
        proc = self._get_process_by_pid(pid)
        if not proc or not proc.exe_path:
            messagebox.showinfo("提示", "无法获取该进程的可执行文件路径。")
            return
        try:
            subprocess.Popen(f'explorer /select,"{proc.exe_path}"')
            self._log(f"已在资源管理器中定位: {proc.exe_path}")
        except Exception as e:
            self._log(f"打开资源管理器失败: {e}", "ERROR")

    # ---------- 删除操作 ----------
    def _force_delete(self):
        path = self.path_var.get().strip().strip('"').strip("'")
        if not path or not os.path.exists(path):
            messagebox.showwarning("提示", "路径不存在或未输入。")
            return

        if not messagebox.askyesno("确认强制删除",
                                     f"将强制删除以下路径:\n{path}\n\n"
                                     "如果文件仍被占用，删除可能失败。\n确定继续吗？"):
            return

        ok, msg = delete_path(path)
        self._log(f"强制删除: {msg}", "SUCCESS" if ok else "ERROR")
        if ok:
            messagebox.showinfo("成功", msg)
            self._clear_results()
            self._set_status("删除成功。")
        else:
            if messagebox.askyesno("删除失败", msg + "\n\n是否先检测占用进程？"):
                self.start_detect()
            elif messagebox.askyesno("删除失败", "是否尝试注册为重启后自动删除？"):
                self._reboot_delete()

    def _reboot_delete(self):
        path = self.path_var.get().strip().strip('"').strip("'")
        if not path or not os.path.exists(path):
            messagebox.showwarning("提示", "路径不存在或未输入。")
            return

        if not messagebox.askyesno("确认重启后删除",
                                     f"将注册以下路径在系统重启时自动删除:\n{path}\n\n"
                                     "此操作需要管理员权限。确定继续吗？"):
            return

        ok, msg = schedule_delete_on_reboot(path)
        self._log(f"重启后删除: {msg}", "SUCCESS" if ok else "ERROR")
        if ok:
            messagebox.showinfo("成功", msg + "\n\n系统重启后该文件/文件夹将被自动删除。")
        else:
            messagebox.showwarning("部分成功/失败",
                                    msg + "\n\n建议右键以管理员身份运行本程序后重试。")


# ============================================================
#  命令行模式
# ============================================================

def run_cli(path, kill=False, delete=False):
    """命令行模式执行检测"""
    print(f"\n{'='*60}")
    print(f"  Windows 文件占用检测 - 命令行模式")
    print(f"  目标路径: {path}")
    print(f"{'='*60}\n")

    if not os.path.exists(path):
        print(f"[错误] 路径不存在: {path}")
        return 1

    results, err = detect_all_locks(path)

    if err:
        print(f"[警告] {err}\n")

    if not results:
        print("[结果] 未发现占用进程，该路径当前可以正常删除。")
        if delete:
            ok, msg = delete_path(path)
            print(f"[删除] {msg}")
        return 0

    print(f"[结果] 发现 {len(results)} 个进程正在占用该路径:\n")
    print(f"{'PID':>8}  {'进程名称':<25} {'类型':<14} {'可执行路径'}")
    print("-" * 90)
    for p in results:
        name = (p.app_name or "(未知)")[:24]
        print(f"{p.pid:>8}  {name:<25} {p.type_name:<14} {p.exe_path or '(无法获取)'}")

    if kill:
        print("\n[操作] 正在结束所有占用进程...")
        for p in results:
            if p.app_type == RM_APP_TYPE.RmCritical:
                print(f"  跳过关键进程 PID={p.pid} ({p.app_name})")
                continue
            ok, msg = terminate_process(p.pid, force=True)
            print(f"  PID={p.pid}: {msg}")
        time.sleep(1)

    if delete:
        print("\n[操作] 正在删除目标路径...")
        ok, msg = delete_path(path)
        print(f"  {msg}")

    return 0


def print_usage():
    print("""
Windows 文件占用检测工具 - 命令行用法

  python file_lock_detector.py [选项] <路径>

选项:
  (无参数)        启动图形界面
  <路径>          检测指定文件/文件夹的占用进程
  -k, --kill      检测后自动结束所有占用进程
  -d, --delete    检测后删除目标文件/文件夹（会先结束占用进程）
  -h, --help      显示此帮助信息

示例:
  python file_lock_detector.py                          # 启动 GUI
  python file_lock_detector.py "E:\\test\\locked.txt"  # 仅检测
  python file_lock_detector.py -k "E:\\test\\folder"   # 检测并结束进程
  python file_lock_detector.py -d "E:\\test\\folder"   # 检测并删除
""")


# ============================================================
#  入口
# ============================================================

def main():
    args = sys.argv[1:]

    # 无参数 → 启动 GUI
    if not args:
        dpi_scale = setup_dpi_awareness()
        root = tk.Tk()
        app = FileLockDetectorApp(root, dpi_scale=dpi_scale)
        root.mainloop()
        return

    # 帮助
    if args[0] in ("-h", "--help", "/?"):
        print_usage()
        return

    # 解析选项
    kill = False
    delete = False
    path = None

    for arg in args:
        if arg in ("-k", "--kill"):
            kill = True
        elif arg in ("-d", "--delete"):
            delete = True
            kill = True  # 删除需要先结束占用
        elif not arg.startswith("-"):
            path = arg.strip('"').strip("'")

    if not path:
        print("[错误] 未指定路径。使用 -h 查看帮助。")
        sys.exit(1)

    sys.exit(run_cli(path, kill=kill, delete=delete))


if __name__ == "__main__":
    main()
