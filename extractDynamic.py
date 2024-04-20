#!/usr/bin/python3
import json

Cuckoo_report = "/home/kali/malwares/report.json"
with open(Cuckoo_report, 'r') as file:
    Cuckoo_report = json.load(file)

apis = []
class_ = "UnKnown"

try:
    api_calls = Cuckoo_report['behavior']['apistats']
except:
    api_calls = []

for key in api_calls:
    apis += list(api_calls[key].keys())

apis = [class_] + apis


apis_calls = ['InternetOpen', 'GetProcAddress', 'CreateToolhelp32Snapshot', 'HttpOpenRequest', 'ioctlsocket', 'OpenProcess', 'CreateThread', 'SetWindowsHookExA', 'InternetReadFile', 'FindResource', 'CountClipboardFormats', 'WriteProcessMemory', 'free', 'GetEIP', 'GetAsyncKeyState', 'DispatchMessage', 'SizeOfResource', 'GetFileSize', 'GetTempPathA', 'NtUnmapViewOfSection', 'WSAIoctl', 'ReadFile', 'GetTickCount', 'Fopen', 'malloc', 'InternetConnect', 'Sscanf', 'GetKeyState', 'GetModuleHandle', 'ReadProcessMemory', 'LockResource', 'RegSetValueEx', 'ShellExecute', 'IsDebuggerPresent', 'WSASocket', 'VirtualProtect', 'bind', 'WinExec', 'GetForeGroundWindow', 'CreateProcessA', 'LoadLibraryA', 'socket', 'LoadResource', 'CreateFileA', 'VirtualAllocEx', 'HTTPSendRequest', 'BroadcastSystemMessage', 'FindWindowsA', 'Process32First', 'CreateRemoteThread', 'GetWindowsThreadProcessId', 'URLDownloadToFile', 'SetWindowsHookEx', 'GetMessage', 'VirtualAlloc', 'MoveFileA', 'FindResourceA', 'GetWindowsDirectoryA', 'PeekMessageA', 'FindClose', 'MapVirtualKeyA', 'SetEnvironmentVariableA', 'GetKeyboardState', 'mciSendStringA', 'GetFileType', 'RasEnumConnectionsA', 'FlushFileBuffers', 'GetVersionExA', 'ioctlsocket', 'WSAAsyncSelect', 'GetCurrentThreadId', 'LookupPrivilegeValueA', 'GetCurrentProcess', 'SetStdHandle', 'WSACleanup', 'WSAStartup', 'CreateMutexA', 'GetForegroundWindow', 'SetKeyboardState', 'OleInitialize', 'SetUnhandledExceptionFilter', 'UnhookWindowsHookEx', 'GetModuleHandleA', 'GetSystemDirectoryA', 'RegOpenKey', 'GetFileAttributesA', 'AdjustTokenPrivileges', 'FreeLibrary', 'GetStartupInfoA', 'RasGetConnectStatusA', 'OpenProcessToken', 'PostMessageA', 'GetTickCount', 'GetExitCodeProcess', 'SetFileTime', 'DispatchMessageA', 'RegDeleteValueA', 'FreeEnvironmentStringsA', 'CallNextHookEx', 'GetUserNameA', 'HeapCreate', 'GlobalMemoryStatus', 'SetFileAttributesA', 'URLDownloadToFileA', 'RaiseException', 'WSAGetLastError', 'RegCreateKeyExA', 'keybd_event', 'ExitWindowsEx', 'GetCommandLineA', 'RegCreateKeyA', 'FreeEnvironmentStringsW', 'UnhandledExceptionFilter', 'GetExitCodeThread', 'PeekNamedPipe']


model_features = []
for i in range(len(apis_calls)):
    if apis_calls[i] in apis:
        model_features.append(1)
    else:
        model_features.append(0)

import pickle
import os
import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.ensemble import RandomForestClassifier

if __name__ == '__main__':

    # Load the trained PCA model
    with open(os.path.join('pca_model.pkl'), 'rb') as f:
        pca = pickle.load(f)

    # Load the trained RandomForestClassifier model
    with open(os.path.join('best_rf_model_pca_dynamic.pkl'), 'rb') as f:
        clf = pickle.load(f)

    # Load the features mapping
    with open(os.path.join('pca_features_mapping.pkl'),'rb') as f:
        features_mapping = pickle.load(f)

    # Convert to a pandas Series if it's a list
    #model_features = pd.Series(model_list)

    # Transform the extracted features using PCA
    #pe_features_transformed = pca.transform([model_features[features_mapping.values()].values])[0]


    # Transform the model_list using PCA
    model_list_transformed = pca.transform([model_features])[0]

    # Predict using the transformed features
    prediction = clf.predict([model_list_transformed])[0]
    print(f"The predicted class is: {prediction}")
    # Predict if the PE file is malicious or not based on the transformed features
    res = clf.predict([model_list_transformed])[0]

    print(f'The file is {res}')
