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

// This protection is under Custom License – Non-Commercial Source Distribution
// Copyright (c) 2025 metix
// Discord Username: ntwritefile

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

namespace AntiDebug {
    typedef struct _PEB {
        BYTE Reserved1[2];
        BYTE BeingDebugged;
        BYTE Reserved2[1];
        PVOID Reserved3[2];
        PPEB_LDR_DATA Ldr;
        PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
        BYTE Reserved4[104];
        PVOID Reserved5[52];
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

    inline bool DetectVMSignatures(const void* buffer, size_t size) {
        if (!buffer || size == 0) return false;
        std::string_view memoryView(static_cast<const char*>(buffer), size);

        const std::vector<std::string_view> signatures = {
            XS("QEMU"), XS("Oracle"), XS("innotek"), XS("VirtualBox"), XS("Virtual Platform"),
            XS("VMware"), XS("Parallels"), XS("777777"), XS("VBox"), XS("Xen"), XS("Hyper-V")
        };

        for (const auto& sig : signatures) {
            if (memoryView.find(sig) != std::string_view::npos) {
                return true;
            }
        }
        return false;
    }

    inline bool CheckVMViaCPUID() {
        int cpuInfo[4] = { 0 };
        __cpuid(cpuInfo, 1);
        return (cpuInfo[2] >> 31) & 1;
    }

    inline bool CheckVMViaDiskSize() {
        DWORD sectorsPerCluster = 0, bytesPerSector = 0;
        DWORD freeClusters = 0, totalClusters = 0;
        if (LI_FN(GetDiskFreeSpaceA)(XS("C:\\"), &sectorsPerCluster, &bytesPerSector, &freeClusters, &totalClusters)) {
            ULONGLONG totalBytes = (ULONGLONG)totalClusters * sectorsPerCluster * bytesPerSector;
            return (totalBytes < 60ULL * 1024 * 1024 * 1024);
        }
        return false;
    }

    inline bool IsRunningInVM() {
        MEMORY_BASIC_INFORMATION mbi;
        LI_FN(VirtualQuery)((LPCVOID)DetectVMSignatures, &mbi, sizeof(mbi));
        if (DetectVMSignatures(mbi.AllocationBase, mbi.RegionSize)) {
            return true;
        }
        if (CheckVMViaCPUID()) {
            return true;
        }
        if (CheckVMViaDiskSize()) {
            return true;
        }
        return false;
    }

    inline bool IsDebuggerPresentAdvanced() {
        if (LI_FN(IsDebuggerPresent)()) {
            return true;
        }

        PPEB pPeb = nullptr;
#ifdef _WIN64
        pPeb = (PPEB)__readgsqword(0x60);
#else
        pPeb = (PPEB)__readfsdword(0x30);
#endif
        if (pPeb && pPeb->BeingDebugged) {
            return true;
        }

        PROCESS_BASIC_INFORMATION pbi;
        if (LI_FN(NtQueryInformationProcess).nt()(GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), nullptr) >= 0) {
            if (pbi.PebBaseAddress->BeingDebugged) {
                return true;
            }
        }

        BOOL isDebugged = FALSE;
        if (LI_FN(CheckRemoteDebuggerPresent)(GetCurrentProcess(), &isDebugged) && isDebugged) {
            return true;
        }

        DWORD start = LI_FN(GetTickCount)();
        LI_FN(Sleep)(500);
        DWORD end = LI_FN(GetTickCount)();
        if ((end - start) < 400) {
            return true;
        }

        __try {
            __debugbreak();
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return true;
        }

        return false;
    }

    inline bool CheckRemoteDebugger() {
        HANDLE hSnapshot = LI_FN(CreateToolhelp32Snapshot)(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return false;
        }

        THREADENTRY32 te;
        te.dwSize = sizeof(te);
        if (LI_FN(Thread32First)(hSnapshot, &te)) {
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
        }
        LI_FN(CloseHandle)(hSnapshot);
        return false;
    }

    inline bool IsBeingDebugged() {
        return IsDebuggerPresentAdvanced() || CheckRemoteDebugger();
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

    inline void ShowDetectionPopup(const char* message) {
        LI_FN(MessageBoxA)(nullptr, message, XS("Detection Alert"), MB_ICONWARNING | MB_OK);
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
        if (hThread) {
            LI_FN(CloseHandle)(hThread);
        }
    }
}
