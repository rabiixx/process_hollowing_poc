#include <iostream>
#include <Windows.h>
#include <winternl.h>


typedef NTSTATUS(NTAPI* PH_NtQueryInformationProcess)(
    IN HANDLE               ProcessHandle,
    IN PROCESS_INFORMATION_CLASS ProcessInformationClass,
    OUT PVOID               ProcessInformation,
    IN ULONG                ProcessInformationLength,
    OUT PULONG              ReturnLength
    );

int main()
{

    LPSTARTUPINFOA si = new STARTUPINFOA();
    LPPROCESS_INFORMATION pi = new PROCESS_INFORMATION();
    PROCESS_BASIC_INFORMATION* pbi = new PROCESS_BASIC_INFORMATION();

    if (CreateProcessA(
        NULL,
        (LPSTR)TEXT("C:\\Windows\\System32\\notepad.exe"),
        NULL,
        NULL,
        TRUE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW,
        NULL,
        NULL,
        si,
        pi) == FALSE)
    {
        std::cout << "[x] Failed to execute notepad.exe\n";
        return FALSE;
    }

    // Get module handler
    HMODULE hModule = LoadLibrary(TEXT("ntdll.dll"));

    if (hModule == NULL)
    {
        std::cout << "[x] Failed to obtain module handler\n";
        return FALSE;
    }

    // Get ntdll function VA (Virtual Address)
    PH_NtQueryInformationProcess phNtQueryInformationProcess = (PH_NtQueryInformationProcess)GetProcAddress(hModule, "NtQueryInformationProcess");

    if (phNtQueryInformationProcess == NULL) {
        printf("Error: could not find the function NtOpenFile in library ntdll.dll.");
        exit(-1);
    }

    printf("NtQueryInformationProcess is located at 0x % 08x in ntdll.dll.n", (unsigned int)phNtQueryInformationProcess);

    PULONG ReturnLength = 0;

    NtQueryInformationProcess(
        pi->hProcess,
        ProcessBasicInformation,                    // Retrieves a pointer to a PEB structure
        pbi,
        sizeof(PROCESS_BASIC_INFORMATION),
        ReturnLength);

}
