#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <thread>
#include <intrin.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <cstdint>
#include <array>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")

#include <type_traits>
#include <nmmintrin.h>
#include <algorithm>

typedef NTSTATUS(NTAPI* NtCreateSection_t)(PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS(NTAPI* NtMapViewOfSection_t)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
typedef NTSTATUS(NTAPI* NtUnmapViewOfSection_t)(HANDLE, PVOID);


namespace OBFS
{
    template<class _Ty>
    using clean_type = typename std::remove_const_t<std::remove_reference_t<_Ty>>;

    template <int _size, char _key1, char _key2, typename T>
    class skCrypter
    {
    public:
        __forceinline constexpr skCrypter(T* data)
        {
            crypt(data);
        }

        __forceinline T* decrypt()
        {
            crypt(_storage);
            return _storage;
        }

        __forceinline operator T* ()
        {
            decrypt();
            return _storage;
        }

    private:
        __forceinline constexpr void crypt(T* data)
        {
            for (int i = 0; i < _size; i++)
                _storage[i] = data[i] ^ (_key1 + i % (1 + _key2));
        }

        T _storage[_size]{};
    };
}

#define XS(str) KEyy2(str, __TIME__[4], __TIME__[7]).decrypt()
#define KEyy2(str, key1, key2) []() { \
    constexpr static auto crypted = OBFS::skCrypter<sizeof(str) / sizeof(str[0]), key1, key2, \
        OBFS::clean_type<decltype(str[0])>>((OBFS::clean_type<decltype(str[0])>*)str); \
    return crypted; \
}()

inline void ShowDetectionPopup(const char* message) {
    LI_FN(MessageBoxA)(nullptr, message, XS("Detection Alert"), MB_ICONWARNING | MB_OK);
}

static bool CustomStrStr(const char* str, const char* search) {
    if (!str || !search) return false;
    for (; *str; ++str) {
        const char* s = str;
        const char* n = search;
        while (*s && *n && *s == *n) {
            ++s;
            ++n;
        }
        if (!*n) return true;
    }
    return false;
}

static bool CustomStrStr(const wchar_t* str, const char* search) {
    if (!str || !search) return false;
    for (; *str; ++str) {
        const wchar_t* s = str;
        const char* n = search;
        while (*s && *n && (char)*s == *n) {
            ++s;
            ++n;
        }
        if (!*n) return true;
    }
    return false;
}

static BOOL CALLBACK EnumWndProc(HWND hwnd, LPARAM lParam)
{
    char cur_window[1024];
    LI_FN(GetWindowTextA)(hwnd, cur_window, 1023);

    if (CustomStrStr(cur_window, XS("WinDbg")) ||
        CustomStrStr(cur_window, XS("x64_dbg")) ||
        CustomStrStr(cur_window, XS("OllyICE")) ||
        CustomStrStr(cur_window, XS("OllyDBG")) ||
        CustomStrStr(cur_window, XS("Immunity")) ||
        CustomStrStr(cur_window, XS("Cheat Engine")))
    {
        *((BOOL*)lParam) = TRUE;
    }
    return TRUE;
}
namespace AntiDebug {
    typedef struct _PEB {
        BYTE Reserved1[2];
        BYTE BeingDebugged;
        BYTE Reserved2[1];
        PVOID Reserved3[2];
        PPEB_LDR_DATA Ldr;
        PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
#ifdef _WIN64
        BYTE Reserved4[104];
        PVOID Reserved5[5];
        union {
            ULONG NtGlobalFlag;
            // The user's snippet uses Reserved2[1] for ModuleList which is PEB-dependent
        };
        PVOID Reserved5_2[46];
#else
        BYTE Reserved4[84];
        ULONG NtGlobalFlag;
        BYTE Reserved4_2[16];
        PVOID Reserved5[52];
#endif
        PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
        BYTE Reserved6[128];
        PVOID Reserved7[1];
        ULONG SessionId;
    } PEB, * PPEB;

    typedef struct _PROCESS_BASIC_INFORMATION {
        PVOID Reserved1;
        PPEB PebBaseAddress;
        PVOID Reserved2[2];
        ULONG_PTR UniqueProcessId;
        PVOID Reserved3;
    } PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

    typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    typedef NTSTATUS(NTAPI* pNtSetInformationThread)(HANDLE, THREADINFOCLASS, PVOID, ULONG);

    inline bool IsDebuggerPresentAdvanced() {
        PPEB pPeb = nullptr;
#ifdef _WIN64
        pPeb = (PPEB)__readgsqword(0x60);
#else
        pPeb = (PPEB)__readfsdword(0x30);
#endif
        return (pPeb->BeingDebugged || (pPeb->NtGlobalFlag & 0x70));
    }

    inline bool CheckHardwareBreakpoints() {
        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (LI_FN(GetThreadContext)(GetCurrentThread(), &ctx))
            return (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0);
        return false;
    }

    inline bool CheckSoftwareBreakpoints() {
        DWORD oldProtect;
        void* addr = (void*)IsDebuggerPresentAdvanced;
        if (LI_FN(VirtualProtect)(addr, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            bool isBreakpoint = (*(BYTE*)addr == 0xCC);
            LI_FN(VirtualProtect)(addr, 1, oldProtect, &oldProtect);
            return isBreakpoint;
        }
        return false;
    }

    inline bool CheckTimingAttack() {
        ULONGLONG start = __rdtsc();
        LI_FN(Sleep)(1000);
        ULONGLONG end = __rdtsc();
        return (end - start) < 1000000000ULL;
    }

    inline bool CheckRemoteDebugger() {
        DWORD_PTR debugPort = 0;
        NTSTATUS status = LI_FN(NtQueryInformationProcess).nt()(GetCurrentProcess(), ProcessDebugPort, &debugPort, sizeof(debugPort), NULL);
        return NT_SUCCESS(status) && debugPort != 0;
    }

    inline bool CheckWindow() {
        BOOL ret = FALSE;
        LI_FN(EnumWindows)((WNDENUMPROC)EnumWndProc, (LPARAM)&ret);

        if (LI_FN(FindWindowA).get<HWND(WINAPI*)(LPCSTR, LPCSTR)>()(XS("OLLYDBG"), nullptr) != nullptr ||
            LI_FN(FindWindowA).get<HWND(WINAPI*)(LPCSTR, LPCSTR)>()(XS("WinDbgFrameClass"), nullptr) != nullptr ||
            LI_FN(FindWindowA).get<HWND(WINAPI*)(LPCSTR, LPCSTR)>()(XS("QWidget"), nullptr) != nullptr ||
            LI_FN(FindWindowA).get<HWND(WINAPI*)(LPCSTR, LPCSTR)>()(XS("Qt5153QTQWindowIcon"), nullptr) != nullptr || // IDA in quick start
            LI_FN(FindWindowA).get<HWND(WINAPI*)(LPCSTR, LPCSTR)>()(XS("Qt5153QTQWindowPopupDropShadowSaveBits"), nullptr) != nullptr || // ida 
            LI_FN(FindWindowA).get<HWND(WINAPI*)(LPCSTR, LPCSTR)>()(XS("Qt5QWindowIcon"), nullptr) != nullptr || // X64DBG ( some old version of x64dbg have this idk why butttttt )
            LI_FN(FindWindowA).get<HWND(WINAPI*)(LPCSTR, LPCSTR)>()(XS("Qt5QWindowPopupDropShadowSaveBits"), nullptr) != nullptr) // x64dbg ( new )
        {
            return true;
        }

        char fore_window[1024];
        LI_FN(GetWindowTextA)(LI_FN(GetForegroundWindow)(), fore_window, 1023);
        if (CustomStrStr(fore_window, XS("WinDbg")) ||
            CustomStrStr(fore_window, XS("x64_dbg")) ||
            CustomStrStr(fore_window, XS("OllyICE")) ||
            CustomStrStr(fore_window, XS("OllyDBG")) ||
            CustomStrStr(fore_window, XS("Immunity")))
        {
            return true;
        }

        return ret != FALSE;
    }

    inline bool CheckProcesses() {
        const char* processes[] = {
            XS("x64dbg.exe"), XS("x32dbg.exe"), XS("windbg.exe"), XS("ollydbg.exe"),
            XS("immunitydebugger.exe"), XS("cheatengine-x86_64.exe"), XS("cheatengine-i386.exe"),
            XS("wireshark.exe"), XS("procmon.exe"), XS("idag.exe"), XS("idag64.exe")
        };

        HANDLE hSnapshot = LI_FN(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;

        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe); 

        if (LI_FN(Process32First)(hSnapshot, &pe)) {
            do {
                for (auto const& proc : processes) {
                    if (CustomStrStr(pe.szExeFile, proc)) {
                        LI_FN(CloseHandle)(hSnapshot);
                        return true;
                    }
                }
            } while (LI_FN(Process32Next)(hSnapshot, &pe));
        }

        LI_FN(CloseHandle)(hSnapshot);
        return false;
    }

    inline bool CheckIntegrity() {
        auto ntdll = LI_FN(GetModuleHandleA)(XS("ntdll.dll"));
        if (!ntdll) return false;

        auto nt_query = (BYTE*)LI_FN(GetProcAddress)(ntdll, XS("NtQueryInformationProcess"));
        if (!nt_query) return false;

        // 0xCC = INT3, 0xE9 = JMP
        if (*nt_query == 0xCC || *nt_query == 0xE9) {
            return true;
        }

        return false;
    }

    inline bool detect_hypervisor() {
        int cpuInfo[4] = { 0 };
        __cpuid(cpuInfo, 1);
        return (cpuInfo[2] & (1 << 31)) != 0;
    }

    inline bool detect_low_ram() {
        MEMORYSTATUSEX memInfo;
        memInfo.dwLength = sizeof(MEMORYSTATUSEX);
        if (GlobalMemoryStatusEx(&memInfo)) {
            DWORDLONG totalRAM = memInfo.ullTotalPhys / (1024 * 1024 * 1024);
            return totalRAM < 4;
        }
        return false;
    }

    inline bool detect_few_cores() {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        return sysInfo.dwNumberOfProcessors < 4;
    }

    inline bool detect_low_disk_space() {
        ULARGE_INTEGER freeBytesAvailable, totalBytes, totalFreeBytes;
        if (GetDiskFreeSpaceExA(XS("C:\\"), &freeBytesAvailable, &totalBytes, &totalFreeBytes)) {
            ULONGLONG totalGB = totalBytes.QuadPart / (1024 * 1024 * 1024);
            return totalGB < 100;
        }
        return false;
    }

    inline bool detect_vm() {
        bool vm = false;

        const char* vm_vendors[] = {
            XS("VMware"),
            XS("VBox"),
            XS("VIRTUAL"),
            XS("QEMU"),
            XS("Xen"),
            XS("Parallels")
        };

        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, XS("SYSTEM\\CurrentControlSet\\Services"), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            char keyName[256];
            DWORD index = 0;
            DWORD nameSize = sizeof(keyName);

            while (RegEnumKeyExA(hKey, index, keyName, &nameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                for (const auto& vendor : vm_vendors) {
                    if (CustomStrStr(keyName, vendor)) {
                        vm = true;
                        break;
                    }
                }
                nameSize = sizeof(keyName);
                index++;
            }
            RegCloseKey(hKey);
        }

        return vm;
    }
    inline void SecurityExit() {
        ShowDetectionPopup(XS("Critical security violation detected! Terminating process..."));

   
        HMODULE hMod = LI_FN(GetModuleHandleA).get<HMODULE(WINAPI*)(LPCSTR)>()(nullptr);
        auto base = (char*)hMod;
        if (base) {
            DWORD old;
            if (LI_FN(VirtualProtect)(base, 0x1000, PAGE_READWRITE, &old)) {
                LI_FN(memset)(base, 0, 0x1000);
            }
        }


        LI_FN(TerminateProcess)(LI_FN(GetCurrentProcess)(), 0xDEAD);

 
        LI_FN(exit)(0);
    }

    struct _integrity_check {
        struct section {
            void* address = nullptr;
            std::uint32_t size = 0;
            std::uint32_t checksum = 0;

            bool operator==(const section& other) const {
                return checksum == other.checksum;
            }
        } _cached;

        std::uint32_t crc32(void* data, std::size_t size) {
            std::uint32_t result = 0;
            auto p = reinterpret_cast<std::uint8_t*>(data);
            for (std::size_t i = 0; i < size; ++i)
                result = _mm_crc32_u8(result, p[i]);
            return result;
        }

        section get_text_section(std::uintptr_t module) {
            section text_section = {};
            auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
            if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return text_section;
            auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(module + dos->e_lfanew);
            auto section_hdr = IMAGE_FIRST_SECTION(nt);

            for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, section_hdr++) {
                if (LI_FN(strncmp)((char*)section_hdr->Name, (char*)XS(".text"), 5) == 0) {
                    text_section.address = reinterpret_cast<void*>(module + section_hdr->VirtualAddress);
                    text_section.size = section_hdr->Misc.VirtualSize;
                    text_section.checksum = crc32(text_section.address, text_section.size);
                    break;
                }
            }
            return text_section;
        }

        _integrity_check() {
            _cached = get_text_section(reinterpret_cast<std::uintptr_t>(LI_FN(GetModuleHandleA)(nullptr)));
        }

        bool check() {
            auto current = get_text_section(reinterpret_cast<std::uintptr_t>(LI_FN(GetModuleHandleA)(nullptr)));
            return current.checksum == _cached.checksum;
        }
    };

    inline _integrity_check& get_integrity() {
        static _integrity_check instance;
        return instance;
    }

    inline bool CheckIntegrityAdvanced() {
        return get_integrity().check();
    }

    inline void BetterAntiDump() {
#if defined(_M_X64)
        const auto peb = (PPEB)__readgsqword(0x60);
#elif defined(_M_IX86)
        const auto peb = (PPEB)__readfsdword(0x30);
#endif
        if (peb && peb->Ldr) {
      
            const auto in_load_order_module_list = (PLIST_ENTRY)peb->Ldr->Reserved2[1];
            if (in_load_order_module_list) {
                const auto table_entry = CONTAINING_RECORD(in_load_order_module_list, LDR_DATA_TABLE_ENTRY, Reserved1[0]);
                const auto p_size_of_image = (PULONG)&table_entry->Reserved3[1];
                *p_size_of_image = (ULONG)((INT_PTR)table_entry->DllBase + 0x100000);
            }
        }

      
        HMODULE hMod = LI_FN(GetModuleHandleA).get<HMODULE(WINAPI*)(LPCSTR)>()(nullptr);
        auto base = (char*)hMod;
        if (base) {
            DWORD old;
            if (LI_FN(VirtualProtect)(base, 0x1000, PAGE_READWRITE, &old)) {
                LI_FN(memset)(base, 0, 0x1000);
                LI_FN(VirtualProtect)(base, 0x1000, old, &old);
            }
        }
    }

    inline void RemapImage() {
        HMODULE hMod = LI_FN(GetModuleHandleA).get<HMODULE(WINAPI*)(LPCSTR)>()(nullptr);
        auto base = (char*)hMod;
        if (!base) return;
        auto dos = (PIMAGE_DOS_HEADER)base;
        auto nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
        auto size = nt->OptionalHeader.SizeOfImage;

        HANDLE section_handle = NULL;
        LARGE_INTEGER section_size = { 0 };
        section_size.QuadPart = size;

        auto ntdll = LI_FN(GetModuleHandleA)(XS("ntdll.dll"));
        if (!ntdll) return;

        auto nt_create_sec = reinterpret_cast<NtCreateSection_t>(
            LI_FN(GetProcAddress)(ntdll, XS("NtCreateSection"))
            );

        auto nt_map_sec = reinterpret_cast<NtMapViewOfSection_t>(
            LI_FN(GetProcAddress)(ntdll, XS("NtMapViewOfSection"))
            );

        auto nt_unmap_sec = reinterpret_cast<NtUnmapViewOfSection_t>(
            LI_FN(GetProcAddress)(ntdll, XS("NtUnmapViewOfSection"))
            );



        if (!nt_create_sec || !nt_map_sec || !nt_unmap_sec) return;

        NTSTATUS status = nt_create_sec(&section_handle, SECTION_ALL_ACCESS, NULL, &section_size, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
        if (!NT_SUCCESS(status)) return;

        PVOID local_view = NULL;
        SIZE_T view_size = 0;
        LARGE_INTEGER offset = { 0 };
        status = nt_map_sec(section_handle, LI_FN(GetCurrentProcess)(), &local_view, 0, size, &offset, &view_size, 2, 0, PAGE_READWRITE);
        if (!NT_SUCCESS(status)) {
            LI_FN(CloseHandle)(section_handle);
            return;
        }

        LI_FN(memcpy)(local_view, base, size);
        status = nt_unmap_sec(LI_FN(GetCurrentProcess)(), base);
        
        PVOID remap_base = base;
        status = nt_map_sec(section_handle, LI_FN(GetCurrentProcess)(), &remap_base, 0, 0, &offset, &view_size, 2, 0, PAGE_EXECUTE_READWRITE);

        LI_FN(CloseHandle)(section_handle);
    }

    inline bool IsRunningInVM() {
        bool detected = false;
        if (detect_hypervisor() || detect_vm()) {
            detected = true;
        }

        if (detect_low_ram()) {
            detected = true;
        }

        if (detect_few_cores()) {
            detected = true;
        }

        if (detect_low_disk_space()) {
            detected = true;
        }
        return detected;
    }


    inline bool IsBeingDebugged() {
        return IsDebuggerPresentAdvanced() || CheckRemoteDebugger() || CheckHardwareBreakpoints() ||
            CheckSoftwareBreakpoints() || LI_FN(IsDebuggerPresent)() || CheckTimingAttack() ||
            CheckWindow()  || CheckProcesses() || !CheckIntegrityAdvanced();
    }

    inline void AntiDump() {
        LI_FN(SetErrorMode)(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
        BetterAntiDump();

        HANDLE hToken;
        if (LI_FN(OpenProcessToken)(LI_FN(GetCurrentProcess)(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
            TOKEN_PRIVILEGES tp;
            LI_FN(LookupPrivilegeValueA)(nullptr, XS("SeDebugPrivilege"), &tp.Privileges[0].Luid);
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            LI_FN(AdjustTokenPrivileges)(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
            LI_FN(CloseHandle)(hToken);
        }
    }



    inline DWORD WINAPI HiddenThread(LPVOID lpParam) {
        LI_FN(NtSetInformationThread).nt()(LI_FN(GetCurrentThread)(), (THREADINFOCLASS)17, nullptr, 0);

        while (true) {
            if (IsBeingDebugged() || IsRunningInVM()) {
                SecurityExit();
            }
            LI_FN(Sleep)(1000);
        }
        return 0;
    }

    inline void StartHiddenThread() {
        DWORD threadId;
        HANDLE hThread = LI_FN(CreateThread)(nullptr, 0, (LPTHREAD_START_ROUTINE)HiddenThread, nullptr, 0, &threadId);
        if (hThread) LI_FN(CloseHandle)(hThread);
    }
}
