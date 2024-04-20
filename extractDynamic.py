#!/usr/bin/python3
import json

Cuckoo_report = "report.json"
with open(Cuckoo_report, 'r') as file:
    Cuckoo_report = json.load(file)

apis = []
#class_ = ""

try:
        api_calls = Cuckoo_report['behavior']['apistats']
except:
        api_calls = []

for key in api_calls:
        apis += list(api_calls[key].keys())

apis_dict = {"InternetOpen":0 ,
            "GetProcAddress":0,
            "CreateToolhelp32Snapshot":0,
            "HTTPOpenRequest":0,
            "IoctlSocket":0,
            "OpenProcess":0,
            "CreateThread":0,
            "SetWindowsHookExA":0,
            "InternetReadFile":0,
            "FindResource":0,
            "CountClipboardFormats":0,
            "WriteProcessMemory":0,
            "Free":0,
            "GetEIP":0,
            "GetAsyncKeyState":0,
            "DispatchMessage":0,
            "SizeOfResource":0,
            "GetFileSize":0,
            "GetTempPathA":0,
            "NtUnmapViewOfSection":0,
            "WSAIoctl":0,
            "ReadFile":0,
            "GetTickCount":0,
            "FOpen":0,
            "Malloc":0,
            "InternetConnect":0,
            "SScanf":0,
            "GetKeyState":0,
            "GetModuleHandle":0,
            "ReadProcessMemory":0,
            "LockResource":0,
            "RegSetValueEx":0,
            "ShellExecute":0,
            "IsDebuggerPresent":0,
            "WSASocket":0,
            "VirtualProtect":0,
            "Bind":0,
            "WinExec":0,
            "GetForegroundWindow":0,
            "CreateProcessA":0,
            "LoadLibraryA":0,
            "Socket":0,
            "LoadResource":0,
            "CreateFileA":0,
            "VirtualAllocEx":0,
            "HTTPSendRequest":0,
            "BroadcastSystemMessage":0,
            "FindWindowA":0,
            "Process32First":0,
            "CreateRemoteThread":0,
            "GetWindowThreadProcessId":0,
            "URLDownloadToFile":0,
            "SetWindowsHookEx":0,
            "GetMessage":0,
            "VirtualAlloc":0,
            "MoveFileA":0,
            "FindResourceA":0,
            "GetWindowsDirectoryA":0,
            "PeekMessageA":0,
            "FindClose":0,
            "MapVirtualKeyA":0,
            "SetEnvironmentVariableA":0,
            "GetKeyboardState":0,
            "MCISendStringA":0,
            "GetFileType":0,
            "RasEnumConnectionsA":0,
            "FlushFileBuffers":0,
            "GetVersionExA":0,
            "WSAAsyncSelect":0,
            "GetCurrentThreadId":0,
            "LookupPrivilegeValueA":0,
            "GetCurrentProcess":0,
            "SetStdHandle":0,
            "WSACleanup":0,
            "WSAStartup":0,
            "CreateMutexA":0,
            "GetForegroundWindow":0,
            "SetKeyboardState":0,
            "OleInitialize":0,
            "SetUnhandledExceptionFilter":0,
            "UnhookWindowsHookEx":0,
            "GetModuleHandleA":0,
            "GetSystemDirectoryA":0,
            "RegOpenKey":0,
            "GetFileAttributesA":0,
            "AdjustTokenPrivileges":0,
            "FreeLibrary":0,
            "GetStartupInfoA":0,
            "RasGetConnectStatusA":0,
            "OpenProcessToken":0,
            "PostMessageA":0,
            "GetExitCodeProcess":0,
            "SetFileTime":0,
            "DispatchMessageA":0,
            "RegDeleteValueA":0,
            "FreeEnvironmentStringsA":0,
            "CallNextHookEx":0,
            "GetUserNameA":0,
            "HeapCreate":0,
            "GlobalMemoryStatus":0,
            "SetFileAttributesA":0,
            "URLDownloadToFileA":0,
            "RaiseException":0,
            "WSAGetLastError":0,
            "RegCreateKeyExA":0,
            "keybd_event":0,
            "ExitWindowsEx":0,
            "GetCommandLineA":0,
            "RegCreateKeyA":0,
            "FreeEnvironmentStringsW":0,
            "UnhandledExceptionFilter":0,
            "GetExitCodeThread":0,
            "PeekNamedPipe":0
}

for i in apis:
    if i in apis_dict:
        apis_dict[i] = 1

model_list = []
for k,v in apis_dict.items():
    model_list.append(v)
