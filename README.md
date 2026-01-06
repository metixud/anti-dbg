# **AntiDbg - Advanced Anti-Debug & Anti-VM Protection**
[![C++](https://img.shields.io/badge/C++-17/20-blue)](https://en.cppreference.com/)
[![x64](https://img.shields.io/badge/x64-green)](https://docs.microsoft.com/en-us/cpp/build/x64-software-conventions?view=msvc-170)
[![No Selling](https://img.shields.io/badge/Selling-Not%20Allowed-red)](LICENSE)
[![Public Domain](https://img.shields.io/badge/License-Unlicense-blue)](https://unlicense.org/)

*A lightweight, obfuscated, and evasive anti-debug/anti-VM library for Windows applications.*

---

## **⚠️ Legal Warning**
This repository is **for educational and research purposes only**.
- **Do NOT use** this to bypass anti-cheat systems (EAC, BattlEye, VAC, etc.).
- **Do NOT use** this for malicious purposes (malware, cheats, etc.).
- **Use at your own risk** – some techniques may trigger antivirus false positives.

---

## **🔍 Features**

| **Category**          | **Techniques Used**                                                                 |
|-----------------------|------------------------------------------------------------------------------------|
| **Anti-Debug**        | PEB (`BeingDebugged`, `NtGlobalFlag`), Hardware Breakpoints (`Dr0-Dr3`), Software Breakpoints (`0xCC`), Timing Attacks (RDTSC), Thread Suspension Check, `NtQueryInformationProcess` |
| **Anti-VM**           | CPUID Hypervisor Bit, VMware/VirtualBox Signatures, Registry Checks, Disk Size Analysis |
| **Anti-Tamper**       | Thread Hiding (`NtSetInformationThread`), Memory Protection (`VirtualProtect`) |
| **Obfuscation**       | String Encryption (XOR + Dynamic Keys), Lazy Importer (`LI_FN`), Runtime Decryption |
| **Stealth**           | Hidden Threads, Direct Syscalls (via `ntdll`), No Hardcoded API Calls |

---

## **📦 How to Use ?**
```
#include "antidbg.hpp"

int main() {
	AntiDebug::StartHiddenThread();
	// ur code
}
```
