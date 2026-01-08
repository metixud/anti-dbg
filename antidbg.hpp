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
#include "lazy_importer.hpp"

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")

#include <cstdlib>
#include <cmath>
#include <type_traits>

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
        ULONG NtGlobalFlag;
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
                    if (strstr(keyName, vendor)) {
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
    inline bool IsRunningInVM() {
        bool detected = false;
        if (detect_hypervisor() || detect_vm()) {
            ShowDetectionPopup(XS("Virtual Machine detected!"));
            detected = true;
        }

        if (detect_low_ram()) {
            ShowDetectionPopup(XS("Suspicious low RAM configuration detected!"));
            detected = true;
        }

        if (detect_few_cores()) {
            ShowDetectionPopup(XS("Suspicious low CPU core count detected!"));
            detected = true;
        }

        if (detect_low_disk_space()) {
            ShowDetectionPopup(XS("Suspicious low disk space detected!"));
            detected = true;
        }
        return detected;
    }

    inline bool CheckSuspendedThreads() {
        HANDLE hSnapshot = LI_FN(CreateToolhelp32Snapshot)(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;

        THREADENTRY32 te;
        te.dwSize = sizeof(te);
        if (!LI_FN(Thread32First)(hSnapshot, &te)) {
            LI_FN(CloseHandle)(hSnapshot);
            return false;
        }

        do {
            if (te.th32OwnerProcessID == LI_FN(GetCurrentProcessId)()) {
                HANDLE hThread = LI_FN(OpenThread)(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                if (hThread) {
                    DWORD suspendCount = LI_FN(SuspendThread)(hThread);
                    LI_FN(ResumeThread)(hThread);
                    if (suspendCount > 0) {
                        LI_FN(CloseHandle)(hThread);
                        LI_FN(CloseHandle)(hSnapshot);
                        return true;
                    }
                    LI_FN(CloseHandle)(hThread);
                }
            }
        } while (LI_FN(Thread32Next)(hSnapshot, &te));
        LI_FN(CloseHandle)(hSnapshot);
        return false;
    }

    inline bool IsBeingDebugged() {
        return IsDebuggerPresentAdvanced() || CheckRemoteDebugger() || CheckHardwareBreakpoints() ||
            CheckSoftwareBreakpoints() || CheckTimingAttack() || CheckSuspendedThreads();
    }

    inline void AntiDump() {
        LI_FN(SetErrorMode)(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
        HANDLE hToken;
        if (LI_FN(OpenProcessToken)(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
            TOKEN_PRIVILEGES tp;
            LI_FN(LookupPrivilegeValueA)(nullptr, XS("SeDebugPrivilege"), &tp.Privileges[0].Luid);
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            LI_FN(AdjustTokenPrivileges)(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
            LI_FN(CloseHandle)(hToken);
        }
    }



    inline DWORD WINAPI HiddenThread(LPVOID lpParam) {
        LI_FN(NtSetInformationThread).nt()(GetCurrentThread(), (THREADINFOCLASS)17, nullptr, 0);

        while (true) {
            if (IsBeingDebugged()) {
                ShowDetectionPopup(XS("Debugger detected!"));
                LI_FN(TerminateProcess)(GetCurrentProcess(), 0xDEAD);
            }
            if (IsRunningInVM()) {
                ShowDetectionPopup(XS("VM detected!"));
                LI_FN(TerminateProcess)(GetCurrentProcess(), 0xDEAD);
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
