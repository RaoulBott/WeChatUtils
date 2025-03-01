#include <windows.h>
#include <iostream>
#include <vector>
#include <Psapi.h>
#include <cstring>
#include <tlhelp32.h>
#include <tchar.h>

// Internal helper function: iterates through all system processes to find the target.
// If WeChat.exe is found and has loaded WeChatWin.dll, returns immediately;
// otherwise, saves the candidate for Weixin.exe and continues searching.
static bool FindWeChatCandidate(HANDLE& hProcess, HMODULE& hModule)
{
    HANDLE hWeixinProcCandidate = NULL;
    HMODULE hWeixinModuleCandidate = NULL;

    HANDLE hSnapProc = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapProc == INVALID_HANDLE_VALUE)
        return false;

    PROCESSENTRY32 pe = { 0 };
    pe.dwSize = sizeof(pe);
    bool bFound = false;

    if (Process32First(hSnapProc, &pe))
    {
        do
        {
            bool isWeChat = (_tcsicmp(pe.szExeFile, _T("WeChat.exe")) == 0);
            bool isWeixin = (_tcsicmp(pe.szExeFile, _T("Weixin.exe")) == 0);
            if (!isWeChat && !isWeixin)
                continue;

            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
            if (hProc)
            {
                // Enumerate the modules loaded by the process
                HANDLE hSnapMod = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe.th32ProcessID);
                if (hSnapMod != INVALID_HANDLE_VALUE)
                {
                    MODULEENTRY32 me = { 0 };
                    me.dwSize = sizeof(me);
                    bool moduleFound = false;
                    if (Module32First(hSnapMod, &me))
                    {
                        do
                        {
                            if (isWeChat && _tcsicmp(me.szModule, _T("WeChatWin.dll")) == 0)
                            {
                                moduleFound = true;
                                break;
                            }
                            else if (isWeixin && _tcsicmp(me.szModule, _T("Weixin.dll")) == 0)
                            {
                                moduleFound = true;
                                break;
                            }
                        } while (Module32Next(hSnapMod, &me));
                    }
                    CloseHandle(hSnapMod);

                    if (moduleFound)
                    {
                        if (isWeChat)
                        {
                            // Found the highest priority WeChat.exe
                            if (hWeixinProcCandidate) // If there is a previous Weixin candidate, release it
                                CloseHandle(hWeixinProcCandidate);
                            hProcess = hProc;
                            hModule = me.hModule;
                            bFound = true;
                            break;
                        }
                        else if (isWeixin)
                        {
                            // Save Weixin candidate (lower priority)
                            if (!hWeixinProcCandidate)
                            {
                                hWeixinProcCandidate = hProc;
                                hWeixinModuleCandidate = me.hModule;
                            }
                            else
                            {
                                CloseHandle(hProc);
                            }
                        }
                    }
                    else
                    {
                        CloseHandle(hProc);
                    }
                }
                else
                {
                    CloseHandle(hProc);
                }
            }
        } while (Process32Next(hSnapProc, &pe));
    }
    CloseHandle(hSnapProc);

    // If WeChat.exe was not found but a candidate for Weixin.exe was found, return it
    if (!bFound && hWeixinProcCandidate)
    {
        hProcess = hWeixinProcCandidate;
        hModule = hWeixinModuleCandidate;
        bFound = true;
    }

    return bFound;
}

// Returns both process and module information
bool GetWeChatProcessInfo(HANDLE& hProcess, HMODULE& hModule)
{
    return FindWeChatCandidate(hProcess, hModule);
}

// Returns only the process handle
bool GetWeChatProcess(HANDLE& hProcess)
{
    HMODULE dummy;
    return FindWeChatCandidate(hProcess, dummy);
}

// Returns only the module handle
bool GetWeChatModule(HMODULE& hModule)
{
    HANDLE dummy = nullptr;
    bool is_success;
    is_success = FindWeChatCandidate(dummy, hModule);
    if (dummy)
    {
        CloseHandle(dummy);
    }
    return is_success;
}

// Get the process handle based on process name
// Parameters:
//   processName: The target process name (e.g., L"notepad.exe")
//   hProcess: Reference to return the found process handle
// Returns: true if the handle is successfully obtained; otherwise, false
bool GetProcessHandle(const std::wstring& processName, HANDLE& hProcess)
{
    hProcess = nullptr;
    // Create a system snapshot to get all process information
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return false;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    // Iterate through the process list to find a matching process name
    if (Process32FirstW(hSnapshot, &pe))
    {
        do
        {
            if (processName == pe.szExeFile)
            {
                // Target process found; open with required access rights
                hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);
                CloseHandle(hSnapshot);
                return (hProcess != nullptr);
            }
        } while (Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return false;
}

// Search for addresses in the process memory that contain the target string
// Parameters:
//   hProcess: Handle of the target process
//   targetString: The string to search for (null-terminated C-style string)
//   foundPtrs: Returns a list of addresses where the string is found
// Returns: true if at least one match is found; otherwise, false
bool searchStringAndPointers(HANDLE hProcess, const char* targetString, std::vector<ULONG_PTR>& foundPtrs) {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    // Start scanning from the minimum accessible system address
    BYTE* addr = reinterpret_cast<BYTE*>(sysInfo.lpMinimumApplicationAddress);
    BYTE* maxAddr = reinterpret_cast<BYTE*>(sysInfo.lpMaximumApplicationAddress);
    size_t targetStringLen = strlen(targetString);

    MEMORY_BASIC_INFORMATION mbi;
    while (addr < maxAddr) {
        // Exit loop if VirtualQueryEx fails
        if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == 0)
            break;

        // Check if the memory region is committed and has PAGE_READWRITE or PAGE_READONLY protection
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY))
        {
            std::vector<BYTE> buffer(mbi.RegionSize);
            SIZE_T bytesRead = 0;
            // Attempt to read the entire memory region
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead)) {
                // Iterate through the data and search for the target string
                for (size_t i = 0; i <= bytesRead - targetStringLen; ++i) {
                    try {
                        if (memcmp(buffer.data() + i, targetString, targetStringLen) == 0) {
                            // Save the found address (base address of region + offset)
                            foundPtrs.push_back(reinterpret_cast<ULONG_PTR>(mbi.BaseAddress) + i);
                        }
                    }
                    catch (...) {
                        // Ignore exceptions and continue scanning the next byte
                        continue;
                    }
                }
            }
        }
        // Move to the next memory region
        addr = reinterpret_cast<BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
    }

    return !foundPtrs.empty();
}

// Search for addresses in the process memory that match the specified value
// Parameters:
//   hProcess: Handle of the target process
//   Value: The value to search for (assumed to be the same size as ULONG_PTR)
//   foundPtrs: Returns a list of addresses where the value is found
// Returns: true if at least one match is found; otherwise, false
bool SearchProcessValue(HANDLE hProcess, ULONG_PTR Value, std::vector<ULONG_PTR>& foundPtrs)
{
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    // Start scanning from the minimum accessible system address
    LPBYTE addr = (LPBYTE)sysInfo.lpMinimumApplicationAddress;

    while (addr < (LPBYTE)sysInfo.lpMaximumApplicationAddress)
    {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) != sizeof(mbi))
            break;

        // Check if the region is committed with readable properties, excluding PAGE_GUARD regions
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) &&
            !(mbi.Protect & PAGE_GUARD))
        {
            SIZE_T regionSize = mbi.RegionSize;
            BYTE* buffer = new BYTE[regionSize];
            SIZE_T bytesRead = 0;
            // Attempt to read the entire memory region
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer, regionSize, &bytesRead))
            {
                // Search within the memory for data matching the Value
                for (SIZE_T i = 0; i <= bytesRead - sizeof(ULONG_PTR); i++)
                {
                    // Read data as ULONG_PTR size
                    ULONG_PTR currentVal = *(ULONG_PTR*)(buffer + i);
                    if (currentVal == Value)
                    {
                        // Save the found address (base address of the region + offset)
                        foundPtrs.push_back((ULONG_PTR)mbi.BaseAddress + i);
                    }
                }
            }
            delete[] buffer;
        }

        // Move to the next memory region
        addr += mbi.RegionSize;
    }

    return !foundPtrs.empty();
}

// Read a string from the remote process with try-catch protection
// Parameter stringStructAddr: Pointer to the string structure
// (The structure stores the actual string pointer at offset 0x00 and the string length at offset 0x10)
std::string ReadRemoteString(HANDLE hProcess, void* stringStructAddr) {
    try {
        SIZE_T bytesRead = 0;
        char* remoteStrPtr = nullptr;
        // Read the string data pointer (located at offset 0x00 in the structure)
        if (!ReadProcessMemory(hProcess, stringStructAddr, &remoteStrPtr, sizeof(remoteStrPtr), &bytesRead))
            return "";

        size_t strLen = 0;
        // Read the string length (located at offset 0x10 in the structure)
        if (!ReadProcessMemory(hProcess, static_cast<BYTE*>(stringStructAddr) + 0x10, &strLen, sizeof(strLen), &bytesRead))
            return "";

        // Allocate a buffer, with one extra byte for the terminating '\0'
        std::vector<char> buffer(strLen + 1, 0);
        if (!ReadProcessMemory(hProcess, remoteStrPtr, buffer.data(), strLen, &bytesRead))
            return "";

        return std::string(buffer.data(), strLen);
    }
    catch (...) {
        // Catch all exceptions and return an empty string
        return "";
    }
}

typedef struct _wechat_extdevnewpwd {
    std::string key;
    std::string wxid;
    std::string extdevnewpwd;
    std::string avatar_url;
}wechat_extdevnewpwd, * pwechat_extdevnewpwd;

// Read all program strings from the extdev string structure address with try-catch protection
// Compatible with two memory structures:
// Memory structure 1: Structure 1 address = extdevStrStruct - 0x58
// Memory structure 2: Structure 1 address = extdevStrStruct - 0x48
// Other structures are fixed:
//   Structure 2: extdevStrStruct - 0x20
//   Structure 3: extdevStrStruct
//   Structure 4: extdevStrStruct + 0x40
void ReadAllProgramStringsFromExtdev(HANDLE hProcess, void* extdevStrStruct, wechat_extdevnewpwd &outStruct) {
    try {
        // Try two offsets to determine the address of structure 1
        void* candidate1 = static_cast<BYTE*>(extdevStrStruct) - 0x58;
        std::string s1 = ReadRemoteString(hProcess, candidate1);
        if (s1.empty()) {
            // If using -0x58 yields an empty string, try using -0x48
            candidate1 = static_cast<BYTE*>(extdevStrStruct) - 0x48;
            s1 = ReadRemoteString(hProcess, candidate1);
        }
        void* struct1 = candidate1;
        void* struct2 = static_cast<BYTE*>(extdevStrStruct) - 0x20;
        void* struct3 = extdevStrStruct;
        void* struct4 = static_cast<BYTE*>(extdevStrStruct) + 0x40;

        std::string s2 = ReadRemoteString(hProcess, struct2);
        std::string s3 = ReadRemoteString(hProcess, struct3);
        std::string s4 = ReadRemoteString(hProcess, struct4);

        //std::cout << "Structure1 string at " << struct1 << ": " << s1 << std::endl;
        //std::cout << "Structure2 string at " << struct2 << ": " << s2 << std::endl;
        //std::cout << "Structure3 string at " << struct3 << ": " << s3 << std::endl;
        //std::cout << "Structure4 string at " << struct4 << ": " << s4 << std::endl;

        outStruct.key = s1;
        outStruct.wxid = s2;
        outStruct.extdevnewpwd = s3;
        outStruct.avatar_url = s4;
    }
    catch (...) {
        std::cout << "Exception occurred in ReadAllProgramStringsFromExtdev" << std::endl;
    }
}

int ShowWeChatInfo() {
    HANDLE hProcess;

    const char* targetString = "extdevnewpwd_";  // Example target string
    std::vector<ULONG_PTR> foundPtrs;

    if (!GetWeChatProcess(hProcess))
    {
        return 1;
    }

    if (searchStringAndPointers(hProcess, targetString, foundPtrs)) {
        // std::cout << "Found target string(s)" << std::endl;

        for (auto ptr : foundPtrs) {
            // std::cout << "str Pointer: " << std::hex << std::uppercase << ptr << std::endl;

            std::vector<ULONG_PTR> foundPtrs2;
            if (SearchProcessValue(hProcess, (ULONG_PTR)ptr, foundPtrs2))
            {
                for (auto ptr2 : foundPtrs2) {
                    // std::cout << "found Pointer 2: " << std::hex << std::uppercase << ptr2 << std::endl;
                    void* extdevStruct = reinterpret_cast<void*>(ptr2);
                    wechat_extdevnewpwd outStruct;
                    ReadAllProgramStringsFromExtdev(hProcess, extdevStruct, outStruct);
                    if (!outStruct.avatar_url.empty())
                    {
                        std::cout << "key ==> " << outStruct.key << std::endl << std::endl;
                        std::cout << "wxid ==> " << outStruct.wxid << std::endl << std::endl;
                        std::cout << "extdevnewpwd ==> " << outStruct.extdevnewpwd << std::endl << std::endl;
                        std::cout << "avatar_url ==> " << outStruct.avatar_url << std::endl << std::endl;
                    }
                }
            }
        }
    }
    CloseHandle(hProcess);
    return 0;
}

// Demo main function
int main() {
    return ShowWeChatInfo();
}
