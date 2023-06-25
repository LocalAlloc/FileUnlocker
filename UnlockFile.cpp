#include <windows.h>
#include <RestartManager.h>
#include <stdio.h>
#include <string>
#include <commdlg.h>
#include <sstream>
#pragma comment(lib, "RstrtMgr.lib")

int __cdecl wmain(int argc, WCHAR** argv)
{
    OPENFILENAMEA ofn;
    CHAR szFile[MAX_PATH] = { 0 };
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFilter = "All Files (*.*)\0*.*\0";
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_ALLOWMULTISELECT | OFN_PATHMUSTEXIST;

    if (GetOpenFileNameA(&ofn) == TRUE)
    {
        DWORD dwSession;
        WCHAR szSessionKey[CCH_RM_SESSION_KEY + 1] = { 0 };
        DWORD dwError = RmStartSession(&dwSession, 0, szSessionKey);

        std::wstringstream startSessionMsg;
        startSessionMsg << L"RmStartSession returned " << dwError;
        MessageBox(NULL, startSessionMsg.str().c_str(), L"Session Start", MB_OK | MB_ICONINFORMATION | MB_TOPMOST);

        if (dwError == ERROR_SUCCESS) {
            std::wstring wstrFilePath;
            if (strlen(ofn.lpstrFile) > 0) {
                int len = MultiByteToWideChar(CP_ACP, 0, ofn.lpstrFile, -1, NULL, 0);
                wchar_t* wFilePath = new wchar_t[len];
                MultiByteToWideChar(CP_ACP, 0, ofn.lpstrFile, -1, wFilePath, len);
                wstrFilePath = wFilePath;
                delete[] wFilePath;
            }

            const wchar_t* pszFilePath = wstrFilePath.c_str();

            dwError = RmRegisterResources(dwSession, 1, &pszFilePath, 0, NULL, 0, NULL);

            std::wstringstream registerResourcesMsg;
            registerResourcesMsg << L"RmRegisterResources(" << wstrFilePath << L") returned " << dwError;
            MessageBox(NULL, registerResourcesMsg.str().c_str(), L"Register Resources", MB_OK | MB_ICONINFORMATION | MB_TOPMOST);

            if (dwError == ERROR_SUCCESS) {
                DWORD dwReason;
                UINT i;
                UINT nProcInfoNeeded;
                UINT nProcInfo = 10;
                RM_PROCESS_INFO rgpi[10];
                dwError = RmGetList(dwSession, &nProcInfoNeeded, &nProcInfo, rgpi, &dwReason);

                std::wstring getListMsg = L"RmGetList returned " + std::to_wstring(dwError);
                MessageBox(NULL, getListMsg.c_str(), L"Get List", MB_OK | MB_ICONINFORMATION | MB_TOPMOST);

                if (dwError == ERROR_SUCCESS) {
                    CHAR buff[256];
                    std::wstring infoMsg = L"RmGetList returned " + std::to_wstring(nProcInfo) + L" infos (" + std::to_wstring(nProcInfoNeeded) + L" needed)";
                    MessageBox(NULL, infoMsg.c_str(), L"Info", MB_OK | MB_ICONINFORMATION | MB_TOPMOST);

                    for (i = 0; i < nProcInfo; i++) {
                        std::wstring appTypeMsg = L"ApplicationType: " + std::to_wstring(rgpi[i].ApplicationType);
                        MessageBox(NULL, appTypeMsg.c_str(), L"Application Type", MB_OK | MB_ICONINFORMATION | MB_TOPMOST);

                        std::wstring appNameMsg = L"AppName: " + std::wstring(rgpi[i].strAppName);
                        MessageBox(NULL, appNameMsg.c_str(), L"App Name", MB_OK | MB_ICONINFORMATION | MB_TOPMOST);

                        std::wstring procIdMsg = L"ProcessId: " + std::to_wstring(rgpi[i].Process.dwProcessId);
                        MessageBox(NULL, procIdMsg.c_str(), L"Process ID", MB_OK | MB_ICONINFORMATION | MB_TOPMOST);

                        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, FALSE, rgpi[i].Process.dwProcessId);
                        if (hProcess) {
                            FILETIME ftCreate, ftExit, ftKernel, ftUser;
                            if (GetProcessTimes(hProcess, &ftCreate, &ftExit, &ftKernel, &ftUser) &&
                                CompareFileTime(&rgpi[i].Process.ProcessStartTime, &ftCreate) == 0) {
                                WCHAR sz[MAX_PATH];
                                DWORD cch = MAX_PATH;
                                if (QueryFullProcessImageNameW(hProcess, 0, sz, &cch) && cch <= MAX_PATH) {
                                    std::wstring pathMsg = L"Process Path: " + std::wstring(sz);
                                    MessageBox(NULL, pathMsg.c_str(), L"Process Path", MB_OK | MB_ICONINFORMATION | MB_TOPMOST);
                                }
                            }
                        }
                        TerminateProcess(hProcess, 0);
                        CloseHandle(hProcess);
                    }
                }
            }
            RmEndSession(dwSession);
        }
    }
    return 0;
}
