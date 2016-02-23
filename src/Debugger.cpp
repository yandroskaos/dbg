#include "../inc/dbg.h"
#include "Disassembler.h"
#include "Tools.h"

#include <algorithm>
#include <string>
#include <vector>
#include <map>
using namespace std;

#include <psapi.h>
#pragma comment(lib, "psapi.lib")

struct PROCESS
{
	DWORD   pid;
	HANDLE  handle;
	DWORD   platform;
	wstring name;
	LPVOID  peb;
};

DWORD   __stdcall ProcessPID     (PROCESS* _process) { return _process->pid; }
HANDLE  __stdcall ProcessHandle  (PROCESS* _process) { return _process->handle; }
DWORD   __stdcall ProcessPlatform(PROCESS* _process) { return _process->platform; }
LPCWSTR __stdcall ProcessName    (PROCESS* _process) { return _process->name.c_str(); }
LPVOID  __stdcall ProcessPEB     (PROCESS* _process) { return _process->peb; }

struct THREAD
{
	PROCESS* process;
	DWORD    tid;
	HANDLE   handle;
	LPVOID   teb;
};
PROCESS* __stdcall ThreadProcess(THREAD* _thread) { return _thread->process; }
DWORD    __stdcall ThreadTID    (THREAD* _thread) { return _thread->tid; }
HANDLE   __stdcall ThreadHandle (THREAD* _thread) { return _thread->handle; }
LPVOID   __stdcall ThreadTEB    (THREAD* _thread) { return _thread->teb; }

struct MODULE
{
	PROCESS*         process;
	LPVOID           base;
	HMODULE          handle;
	DWORD            size;
	DWORD            platform;
	wstring          name;
	vector<FUNCTION> exports;
};
PROCESS*    __stdcall ModuleProcess        (MODULE* _module) { return _module->process; }
LPVOID      __stdcall ModuleBase           (MODULE* _module) { return _module->base; }
HMODULE     __stdcall ModuleHandle         (MODULE* _module) { return _module->handle; }
DWORD       __stdcall ModuleSize           (MODULE* _module) { return _module->size; }
DWORD       __stdcall ModulePlatform       (MODULE* _module) { return _module->platform; }
LPCWSTR     __stdcall ModuleName           (MODULE* _module) { return _module->name.c_str(); }
FUNCTION*   __stdcall ModuleExportsFunction(MODULE* _module, UINT _index) { return _module->exports.empty() || _index >= _module->exports.size() ? 0 : &_module->exports[_index]; }
DWORD      __stdcall  ModuleExportsSize    (MODULE* _module) { return _module->exports.size(); }

struct FUNCTION
{
	MODULE* module;
	LPVOID  address;
	string  name;
};
MODULE* __stdcall FunctionModule (FUNCTION* _function) { return _function->module; }
LPVOID  __stdcall FunctionAddress(FUNCTION* _function) { return _function->address; }
LPCSTR  __stdcall FunctionName   (FUNCTION* _function) { return _function->name.c_str(); }

struct BREAKPOINT
{
	LPVOID address;
	BYTE   original;
	BOOL   oneShot;
	LPVOID singleStepAddress;
};

#define DR_ALL (DR0 | DR1 | DR2 | DR3)

struct DEBUGGER
{
	map<DWORD, PROCESS*>                  processes;
	map<DWORD, map<DWORD, THREAD*> >      threads;
	map<DWORD, map<LPVOID, MODULE*> >     modules;
	map<DWORD, map<LPVOID, BREAKPOINT> >  breakpoints; 

	HANDLE debugThread;
	HANDLE shutdownEvent;
	HANDLE successfulAttachEvent;

	BOOL  killOnExit;
	DWORD originalPid;

	INSPECTOR* inspector;
};

/////////////////////////////////////////////////////////////////////////////
//PRIVATE INTERFACE
/////////////////////////////////////////////////////////////////////////////
static DWORD   DbgSspProcessPlatform(HANDLE _process);
static LPVOID  DbgSspProcessPEB     (HANDLE _process);
static LPVOID  DbgSspThreadTEB      (HANDLE _process, HANDLE _thread);
static BOOL    DbgSspModuleFillData (HANDLE _process, MODULE* _module);
static wstring DbgSspFileName       (HANDLE _file);

static PROCESS* DbgSspOnCreateProcess(DEBUGGER* _dbg, DEBUG_EVENT* _event);
static VOID     DbgSspOnExitProcess  (DEBUGGER* _dbg, DEBUG_EVENT* _event);
static THREAD*  DbgSspOnCreateThread (DEBUGGER* _dbg, DEBUG_EVENT* _event, BOOL _mainThread);
static VOID     DbgSspOnExitThread   (DEBUGGER* _dbg, DEBUG_EVENT* _event);
static MODULE*  DbgSspOnLoadDll      (DEBUGGER* _dbg, DEBUG_EVENT* _event);
static VOID     DbgSspOnUnloadDll    (DEBUGGER* _dbg, DEBUG_EVENT* _event);

static BREAKPOINT* DbgBppGetSoftwareBreakpoint(DEBUGGER* _dbg, DWORD _pid, LPVOID _address);
static LPVOID      DbgBppGetHardwareBreakpoint(DEBUGGER* _dbg, CONTEXT* _context);
static BOOL        DbgBppOnInt01(DEBUGGER* _dbg, DWORD _pid, DWORD _tid, LPVOID _address);
static BOOL        DbgBppOnInt03(DEBUGGER* _dbg, DWORD _pid, DWORD _tid, LPVOID _address);

static VOID    DbgpClear       (DEBUGGER* _dbg);
static BOOL    DbgpDebugChilds (HANDLE _process, DWORD _enable);
static DWORD   DbgpPlatform    ();

#ifndef STATUS_WX86_SINGLE_STEP
#define STATUS_WX86_SINGLE_STEP 0x4000001E
#endif

#ifndef STATUS_WX86_BREAKPOINT
#define STATUS_WX86_BREAKPOINT 0x4000001F
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL 0xC0000001
#endif

static DWORD WINAPI DebugThread(LPVOID _parameter)
{
	DEBUGGER* dbg = (DEBUGGER*)_parameter;
	BOOL      selfTerminated = FALSE;

	if(!DebugActiveProcess(dbg->originalPid))
		return GetLastError();

	DebugSetProcessKillOnExit(FALSE);

	while(WaitForSingleObject(dbg->shutdownEvent, 0) == WAIT_TIMEOUT)
	{
		DEBUG_EVENT debugEvent = {0};
		DWORD status = DBG_CONTINUE;

		if(WaitForDebugEvent(&debugEvent, 1 * 1000))
		{
			switch(debugEvent.dwDebugEventCode)
			{
			case CREATE_PROCESS_DEBUG_EVENT:
				{
					PROCESS* p = DbgSspOnCreateProcess(dbg, &debugEvent);
					UINT wantToDebug = debugEvent.dwProcessId == dbg->originalPid ? DBG_DEBUG_PROCESS : DBG_DONT_DEBUG;
					if(dbg->inspector->OnCreateProcess)
						wantToDebug = dbg->inspector->OnCreateProcess(dbg->inspector->context, debugEvent.dwProcessId, p);
					
					if(wantToDebug == DBG_DONT_DEBUG)
					{
						DebugActiveProcessStop(debugEvent.dwProcessId);
						DbgSspOnExitProcess(dbg, &debugEvent);
						if(dbg->originalPid == debugEvent.dwProcessId)
							return STATUS_UNSUCCESSFUL;
					}
					else
					{
						if(wantToDebug == DBG_DEBUG_TREE)
							DbgpDebugChilds(debugEvent.u.CreateProcessInfo.hProcess, 1);

						THREAD* t = DbgSspOnCreateThread(dbg, &debugEvent, TRUE);
						if(dbg->inspector->OnCreateThread)
							dbg->inspector->OnCreateThread(dbg->inspector->context, debugEvent.dwProcessId, t);

						if(dbg->originalPid == debugEvent.dwProcessId)
							SetEvent(dbg->successfulAttachEvent);
					}
					break;
				}
			case EXIT_PROCESS_DEBUG_EVENT:
				{
					if(dbg->inspector->OnExitProcess)
						dbg->inspector->OnExitProcess(dbg->inspector->context, debugEvent.dwProcessId, debugEvent.u.ExitProcess.dwExitCode);
					DbgSspOnExitProcess(dbg, &debugEvent);

					if(dbg->originalPid == debugEvent.dwProcessId)
					{
						selfTerminated = TRUE;
						SetEvent(dbg->shutdownEvent);
					}
					break;
				}
			case CREATE_THREAD_DEBUG_EVENT:
				{
					THREAD* t = DbgSspOnCreateThread(dbg, &debugEvent, FALSE);
					if(dbg->inspector->OnCreateThread)
						dbg->inspector->OnCreateThread(dbg->inspector->context, debugEvent.dwProcessId, t);
					break;
				}
			case EXIT_THREAD_DEBUG_EVENT:
				{
					if(dbg->inspector->OnExitThread)
						dbg->inspector->OnExitThread(dbg->inspector->context, debugEvent.dwProcessId, debugEvent.dwThreadId);
					DbgSspOnExitThread(dbg, &debugEvent);
					break;
				}
			case LOAD_DLL_DEBUG_EVENT:
				{
					MODULE* m = DbgSspOnLoadDll(dbg, &debugEvent);
					if(dbg->inspector->OnLoadDll)
						dbg->inspector->OnLoadDll(dbg->inspector->context, debugEvent.dwProcessId, m);
					break;
				}
			case UNLOAD_DLL_DEBUG_EVENT:
				{
					if(dbg->inspector->OnUnloadDll)
						dbg->inspector->OnUnloadDll(dbg->inspector->context, debugEvent.dwProcessId, debugEvent.u.UnloadDll.lpBaseOfDll);
					DbgSspOnUnloadDll(dbg, &debugEvent);
					break;
				}
			case EXCEPTION_DEBUG_EVENT:
				{
					BOOL handled = FALSE;

					//INT 1
					if( (debugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP)
						||
						(debugEvent.u.Exception.ExceptionRecord.ExceptionCode == STATUS_WX86_SINGLE_STEP))
					{
						if(DbgBppOnInt01(dbg, debugEvent.dwProcessId, debugEvent.dwThreadId, debugEvent.u.Exception.ExceptionRecord.ExceptionAddress))
						{
							handled = TRUE;
							if(dbg->inspector->OnHardwareBreakpoint)
								dbg->inspector->OnHardwareBreakpoint(dbg->inspector->context, debugEvent.dwProcessId, debugEvent.dwThreadId, debugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
						}
					}

					//INT 3
					if( (debugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT)
						||
						(debugEvent.u.Exception.ExceptionRecord.ExceptionCode == STATUS_WX86_BREAKPOINT))
					{
						if(DbgBppOnInt03(dbg, debugEvent.dwProcessId, debugEvent.dwThreadId, debugEvent.u.Exception.ExceptionRecord.ExceptionAddress))
						{
							handled = TRUE;
							if(dbg->inspector->OnSoftwareBreakpoint)
								dbg->inspector->OnSoftwareBreakpoint(dbg->inspector->context, debugEvent.dwProcessId, debugEvent.dwThreadId, debugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
						}
					}

					//Other
					if(!handled)
					{
						status  = DBG_EXCEPTION_NOT_HANDLED;
						if(dbg->inspector->OnException)
							dbg->inspector->OnException(dbg->inspector->context, debugEvent.dwProcessId, debugEvent.dwThreadId, debugEvent.u.Exception.dwFirstChance, &debugEvent.u.Exception.ExceptionRecord);
					}

					break;
				}
			case OUTPUT_DEBUG_STRING_EVENT:
				{
					if(dbg->inspector->OnDebugString)
					{
						//Read from process
						DWORD size = debugEvent.u.DebugString.nDebugStringLength * (debugEvent.u.DebugString.fUnicode ? 2 : 1);
						BYTE* debugString = new BYTE[size]();
						if(!ReadProcessMemory(dbg->processes[debugEvent.dwProcessId]->handle, debugEvent.u.DebugString.lpDebugStringData, debugString, size, 0))
						{
							delete [] debugString;
							break;
						}

						//Convert if not Unicode
						if(!debugEvent.u.DebugString.fUnicode)
						{
							WCHAR* newDebugString = new WCHAR[size]();
							MultiByteToWideChar(CP_UTF8, MB_PRECOMPOSED, (LPCSTR)debugString, -1, newDebugString, size);
							delete [] debugString;
							debugString = (BYTE*)newDebugString;
						}

						//Notify
						dbg->inspector->OnDebugString(dbg->inspector->context, debugEvent.dwProcessId, (WCHAR*)debugString);

						//Done
						delete [] debugString;
					}
					break;
				}
			case RIP_EVENT:
				{
					dbg->inspector->OnRIP(dbg->inspector->context, debugEvent.dwProcessId, debugEvent.u.RipInfo.dwError);
					break;
				}
			}

			ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, status);
		}
	}

	if(!selfTerminated)
	{
		DebugSetProcessKillOnExit(dbg->killOnExit);
	}
	else
	{
		//EnterCriticalSection(&dbg->serializer);

		CloseHandle(dbg->debugThread);
		dbg->debugThread = 0;

		CloseHandle(dbg->successfulAttachEvent);
		dbg->successfulAttachEvent = 0;

		CloseHandle(dbg->shutdownEvent);
		dbg->shutdownEvent = 0;

		dbg->originalPid = 0;
		dbg->inspector   = 0;
		dbg->killOnExit  = FALSE;
		DbgpClear(dbg);

		//LeaveCriticalSection(&dbg->serializer);
	}

	return ERROR_SUCCESS;
}


static vector<PROCESS*> DbgSspEnumerateProcesses(DEBUGGER* _dbg);
static vector<THREAD*>  DbgSspEnumerateThreads  (DEBUGGER* _dbg, DWORD _pid);
static vector<MODULE*>  DbgSspEnumerateModules  (DEBUGGER* _dbg, DWORD _pid);

static VOID DbgpClear(DEBUGGER* _dbg)
{
	//Breakpoints
	for(map<DWORD, map<LPVOID, BREAKPOINT> >::iterator bps = _dbg->breakpoints.begin(); bps != _dbg->breakpoints.end(); bps++)
	{
		PROCESS* process = _dbg->processes[bps->first];

		//Delete software breakpoints
		for(map<LPVOID, BREAKPOINT>::iterator bp = bps->second.begin(); bp != bps->second.end(); bp++)
		{
			WriteProcessMemory(process->handle, bp->second.address, &bp->second.original, 1, 0);
		}
		bps->second.clear();

		//Delete hardware breakpoints
		vector<THREAD*> threads = DbgSspEnumerateThreads(_dbg, process->pid);
		for(unsigned int t = 0; t < threads.size(); t++)
		{
			CONTEXT context = {0};
			context.ContextFlags = CONTEXT_ALL;
			if(!GetThreadContext(threads[t]->handle, &context))
				continue;

			context.Dr0 = context.Dr1 = context.Dr2 = context.Dr3 = 0;
			context.Dr7 &= 0x0000FF00;

			SetThreadContext(threads[t]->handle, &context);
		}
	}
	_dbg->breakpoints.clear();

	//Threads
	for(map<DWORD, map<DWORD, THREAD*> >::iterator ts = _dbg->threads.begin(); ts != _dbg->threads.end(); ts++)
	{
		for(map<DWORD, THREAD*>::iterator t = ts->second.begin(); t != ts->second.end(); t++)
		{
			delete [] t->second->teb;
			delete t->second;
		}
		ts->second.clear();
	}
	_dbg->threads.clear();

	//Modules
	for(map<DWORD, map<LPVOID, MODULE*> >::iterator ms = _dbg->modules.begin(); ms != _dbg->modules.end(); ms++)
	{
		for(map<LPVOID, MODULE*>::iterator m = ms->second.begin(); m != ms->second.end(); m++)
		{
			delete m->second;
		}
		ms->second.clear();
	}
	_dbg->modules.clear();

	//Processes
	for(map<DWORD, PROCESS*>::iterator p = _dbg->processes.begin(); p != _dbg->processes.end(); p++)
	{
		delete [] p->second->peb;
		delete p->second;
	}
	_dbg->processes.clear();
}

static BOOL DbgpDebugChilds(HANDLE _process, DWORD _enable)
{
	typedef NTSTATUS (NTAPI * LPFN_NTSETINFORMATIONPROCESS)(IN HANDLE _process, IN DWORD _informationClass, IN PVOID _information, IN ULONG _informationSize);

	static LPFN_NTSETINFORMATIONPROCESS fnNtSetInformationProcess = 0;
	if (!fnNtSetInformationProcess)
		fnNtSetInformationProcess = (LPFN_NTSETINFORMATIONPROCESS) GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationProcess");

	if (!fnNtSetInformationProcess)
		return 0;

	NTSTATUS status = fnNtSetInformationProcess(_process, 0x1F, &_enable, sizeof(DWORD));

	return status == 0;
}

static DWORD DbgpPlatform()
{
#ifdef _WIN64
	return 64;
#else
	return 32;
#endif
}

DEBUGGER* __stdcall DbgNew()
{
	DEBUGGER* dbg = new DEBUGGER();

	dbg->debugThread = 0;
	dbg->shutdownEvent = 0;
	dbg->successfulAttachEvent = 0;

	dbg->killOnExit = FALSE;
	dbg->originalPid = 0;

	dbg->inspector = 0;

	return dbg;
}

VOID __stdcall DbgDelete(DEBUGGER* _dbg)
{
	if(_dbg->debugThread)
		DbgDetach(_dbg, FALSE);

	DbgpClear(_dbg);

	delete _dbg;
}

DWORD __stdcall DbgAttach(DEBUGGER* _dbg, DWORD _pid, INSPECTOR* _inspector)
{
	if(_dbg->debugThread)
		DbgDetach(_dbg, FALSE);

	if(!_pid || !_inspector)
		return STATUS_UNSUCCESSFUL;

	DbgpClear(_dbg);
	_dbg->killOnExit = FALSE;

	_dbg->shutdownEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if(!_dbg->shutdownEvent)
		return GetLastError();

	_dbg->successfulAttachEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if(!_dbg->successfulAttachEvent)
	{
		DWORD lastError = GetLastError();
		CloseHandle(_dbg->shutdownEvent);
		_dbg->shutdownEvent = 0;
		return lastError;
	}

	_dbg->originalPid = _pid;
	_dbg->inspector = _inspector;

	_dbg->debugThread = CreateThread(0, 0, DebugThread, (LPVOID)_dbg, 0, 0);
	if(!_dbg->debugThread)
	{
		DWORD lastError = GetLastError();

		_dbg->originalPid = 0;
		_dbg->inspector = 0;

		CloseHandle(_dbg->successfulAttachEvent);
		_dbg->successfulAttachEvent = 0;

		CloseHandle(_dbg->shutdownEvent);
		_dbg->shutdownEvent = 0;

		return lastError;
	}

	HANDLE waitFor[2] = {_dbg->successfulAttachEvent, _dbg->debugThread};
	DWORD result = WaitForMultipleObjects(2, waitFor, FALSE, INFINITE);
	if(result != WAIT_OBJECT_0)
	{
		DWORD lastError = 0;
		if(!GetExitCodeThread(_dbg->debugThread, &lastError))
			lastError = GetLastError();

		CloseHandle(_dbg->debugThread);
		_dbg->debugThread = 0;

		_dbg->originalPid = 0;
		_dbg->inspector = 0;

		CloseHandle(_dbg->successfulAttachEvent);
		_dbg->successfulAttachEvent = 0;

		CloseHandle(_dbg->shutdownEvent);
		_dbg->shutdownEvent = 0;

		return lastError;
	}

	return ERROR_SUCCESS;
}

VOID __stdcall DbgDetach(DEBUGGER* _dbg, BOOL _killOnExit)
{
	if(!_dbg->debugThread)
		return;

	_dbg->killOnExit = _killOnExit;

	if(_dbg->inspector->OnExitProcess)
		_dbg->inspector->OnExitProcess(_dbg->inspector->context, _dbg->originalPid, _killOnExit ? 0xBAADDEAD : 0xC0000FEE);

	SetEvent(_dbg->shutdownEvent);
	if(WaitForSingleObject(_dbg->debugThread, 5 * 1000) != WAIT_OBJECT_0)
		TerminateThread(_dbg->debugThread, 0);

	CloseHandle(_dbg->debugThread);
	_dbg->debugThread = 0;

	CloseHandle(_dbg->successfulAttachEvent);
	_dbg->successfulAttachEvent = 0;

	CloseHandle(_dbg->shutdownEvent);
	_dbg->shutdownEvent = 0;

	_dbg->originalPid = 0;
	_dbg->inspector = 0;

	_dbg->killOnExit  = FALSE;
	DbgpClear(_dbg);
}

DWORD __stdcall DbgOriginalPid(DEBUGGER* _dbg)
{
	return _dbg->originalPid;
}

/////////////////////////////////////////////////////////////////////////////
//SESSION MANAGEMENT
/////////////////////////////////////////////////////////////////////////////
//PRIVATE
static DWORD DbgSspProcessPlatform(HANDLE _process)
{
	typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
	static LPFN_ISWOW64PROCESS fnIsWow64Process = 0;
		
	if(!fnIsWow64Process)
		fnIsWow64Process = (LPFN_ISWOW64PROCESS) GetProcAddress(GetModuleHandleW(L"kernel32"), "IsWow64Process");

	BOOL isWow64 = FALSE;
	if(fnIsWow64Process)
		fnIsWow64Process(_process, &isWow64);

	return isWow64 ? 32 : OSPlatform();
}

static LPVOID DbgSspProcessPEB(HANDLE _process)
{
	#define PEB_SIZE (8  * sizeof(LPVOID))
	UINT _sizeToRead = PEB_SIZE;

	typedef struct _PROCESS_BASIC_INFORMATION
	{
		PVOID		Reserved1;
		PVOID		PebBaseAddress;
		PVOID		Reserved2[2];
		ULONG_PTR	UniqueProcessId;
		PVOID		Reserved3;
	} PROCESS_BASIC_INFORMATION;

	typedef NTSTATUS (NTAPI * LPFN_NTQUERYINFORMATIONPROCESS)(IN HANDLE _process, IN DWORD _informationClass, OUT PVOID _information, IN ULONG _informationSize, OUT OPTIONAL PULONG _returnSize);

	static LPFN_NTQUERYINFORMATIONPROCESS fnNtQueryInformationProcess = 0;
	if (!fnNtQueryInformationProcess)
		fnNtQueryInformationProcess = (LPFN_NTQUERYINFORMATIONPROCESS) GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");

	if (!fnNtQueryInformationProcess)
		return 0;

	PROCESS_BASIC_INFORMATION pbi;
	ULONG size = 0;
	ZeroMemory(&pbi, sizeof(pbi));
	NTSTATUS status = fnNtQueryInformationProcess(_process, 0, &pbi, sizeof(pbi), &size);

	if(status != 0 || size != sizeof(pbi))
		return 0;

	LPVOID peb = new BYTE[_sizeToRead]();
	if(!peb)
		return 0;

	if(!ReadProcessMemory(_process, pbi.PebBaseAddress, peb, _sizeToRead, 0))
	{
		delete [] peb;
		return 0;
	}

	return peb;
}

static LPVOID DbgSspThreadTEB(HANDLE _process, HANDLE _thread)
{
	#define TEB_SIZE (16 * sizeof(LPVOID))
	UINT _sizeToRead = TEB_SIZE;
	typedef struct _THREAD_BASIC_INFORMATION
	{
		NTSTATUS	ExitStatus;
		PVOID		TebBaseAddress;
		ULONG_PTR	ClientId;
		KAFFINITY	AffinityMask;
		ULONG_PTR	Priority;
		ULONG_PTR	BasePriority;
	} THREAD_BASIC_INFORMATION;

	typedef NTSTATUS (NTAPI * LPFN_NTQUERYINFORMATIONTHREAD)(IN HANDLE _thread, IN DWORD _informationClass, OUT PVOID _information, IN ULONG _informationSize, OUT OPTIONAL PULONG _returnSize);

	static LPFN_NTQUERYINFORMATIONTHREAD fnNtQueryInformationThread = 0;
	if (!fnNtQueryInformationThread)
		fnNtQueryInformationThread = (LPFN_NTQUERYINFORMATIONTHREAD) GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread");

	if (!fnNtQueryInformationThread)
		return 0;

	THREAD_BASIC_INFORMATION tbi;
	ULONG size = 0;
	ZeroMemory(&tbi, sizeof(tbi));
	NTSTATUS status = fnNtQueryInformationThread(_thread, 0, &tbi, sizeof(tbi), &size);

	if(status != 0 || size != sizeof(tbi))
		return 0;

	LPVOID teb = new BYTE[_sizeToRead]();
	if(!teb)
		return 0;

	if(!ReadProcessMemory(_process, tbi.TebBaseAddress, teb, _sizeToRead, 0))
	{
		delete [] teb;
		return 0;
	}

	return teb;
}

static BOOL DbgSspModuleFillData(HANDLE _process, MODULE* _module)
{
	//_module->base MUST BE FILLED
	if(!_module->base)
		return FALSE;

	BYTE page[4096];

	//Read initial page containing module headers
	if(!ReadProcessMemory(_process, _module->base, page, 4096, 0))
		return FALSE;

	//Exports section relevant data
	DWORD exports_rva  = 0;
	DWORD exports_size = 0;

	//Headers to locate exports
	IMAGE_DOS_HEADER*	dos_header		= (IMAGE_DOS_HEADER*)       page;
	IMAGE_NT_HEADERS32*	nt_headers		= (IMAGE_NT_HEADERS32*)     (page + dos_header->e_lfanew);

	_module->size = nt_headers->OptionalHeader.SizeOfImage;
	_module->platform = nt_headers->OptionalHeader.Magic == 0x010B ? 32 : (nt_headers->OptionalHeader.Magic == 0x020B ? 64: 0);

	//Exports section relevant data
	DWORD eat_rva  = 0;
	DWORD eat_size = 0;

	if(_module->platform == 32)
	{
		IMAGE_OPTIONAL_HEADER32* optional_header = &nt_headers->OptionalHeader;
		if(!optional_header->NumberOfRvaAndSizes)
			return FALSE;

		eat_rva  = optional_header->DataDirectory[0].VirtualAddress;
		eat_size = optional_header->DataDirectory[0].Size;
	}
	else
	{
		IMAGE_OPTIONAL_HEADER64* optional_header = (IMAGE_OPTIONAL_HEADER64*) &nt_headers->OptionalHeader;
		if(!optional_header->NumberOfRvaAndSizes)
			return FALSE;

		eat_rva  = optional_header->DataDirectory[0].VirtualAddress;
		eat_size = optional_header->DataDirectory[0].Size;
	}

	//Module does not export anything
	if(!eat_rva || !eat_size)
		return FALSE;

	//Read and parse exports data from module
	BYTE* eat = new (std::nothrow) BYTE[eat_size];
	if(!ReadProcessMemory(_process, (LPVOID)((BYTE*)_module->base + eat_rva), eat, eat_size, 0))
	{
		delete[] eat;
		return FALSE;
	}

	//Translation from process address space to our allocated buffer
	#define RVA2OFFSET(X)	((X) - eat_rva)
	#define ACCESS_RVA(X)	((BYTE*)(eat + RVA2OFFSET(X)))
	#define CHECK(X)		((ACCESS_RVA(X) < eat + eat_size) ? TRUE : FALSE)

	//Walk every function name
	IMAGE_EXPORT_DIRECTORY* eat_directory = (IMAGE_EXPORT_DIRECTORY*)eat;
	for(UINT i = 0; i < eat_directory->NumberOfNames; i++)
	{
		DWORD name_entry_rva = eat_directory->AddressOfNames + (i << 2);
		if(!CHECK(name_entry_rva)) continue;

		DWORD name_rva = *(DWORD*) ACCESS_RVA(name_entry_rva);
		if(!CHECK(name_rva)) continue;
		CHAR* name = (CHAR*) ACCESS_RVA(name_rva);

		DWORD ordinal_entry_rva = eat_directory->AddressOfNameOrdinals + (i << 1);
		if(!CHECK(ordinal_entry_rva)) continue;
		WORD ordinal = *(WORD*) ACCESS_RVA(ordinal_entry_rva);

		DWORD address_entry_rva = eat_directory->AddressOfFunctions + (ordinal << 2);
		if(!CHECK(address_entry_rva)) continue;
		DWORD address_rva = *(DWORD*) ACCESS_RVA(address_entry_rva);
		if(address_rva > _module->size) continue;
		LPVOID address = (BYTE*) _module->base + address_rva;

		//Save function
		FUNCTION function;
		function.module  = _module;
		function.address = address;
		//function.ordinal = ordinal;
		function.name    = name;

		_module->exports.push_back(function);
	}

	//Clean resources
	delete[] eat;

	//Everything went well
	return TRUE;
}

static wstring DbgSspFileName(HANDLE _file) 
{
#define FILENAME_SIZE 512
	WCHAR fileName[FILENAME_SIZE] = {0};

	if(OSGroup() >= OS_WINDOWS_VISTA)
	{
		typedef DWORD (WINAPI * LPFN_GETFINALPATHNAMEBYHANDLE)(IN HANDLE hFile, OUT LPTSTR lpszFilePath, IN DWORD cchFilePath, IN DWORD dwFlags);
		static LPFN_GETFINALPATHNAMEBYHANDLE fnGetFinalPathNameByHandle = 0;
		if(!fnGetFinalPathNameByHandle)
			fnGetFinalPathNameByHandle = (LPFN_GETFINALPATHNAMEBYHANDLE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetFinalPathNameByHandle");

		if(fnGetFinalPathNameByHandle)
		{
			DWORD result = fnGetFinalPathNameByHandle(_file, fileName, FILENAME_SIZE, VOLUME_NAME_DOS);
			if(result && result < FILENAME_SIZE)
				return fileName;
		}
	}

	/*
	//Get the file size.
	DWORD fileSizeHi = 0;
	DWORD fileSizeLo = GetFileSize(_file, &dfileSizeHi); 
	if(dwFileSizeLo == 0 && dwFileSizeHi == 0)
		return FALSE;
	*/

	HANDLE fileMap = CreateFileMapping(_file, NULL, PAGE_READONLY, 0, 1, NULL);
	if(!fileMap)
		return FALSE;

	LPVOID view = MapViewOfFile(fileMap, FILE_MAP_READ, 0, 0, 1);
	if(!view) 
	{
		CloseHandle(fileMap);
		return FALSE;
	}

	if(!GetMappedFileNameW(GetCurrentProcess(), view, fileName, FILENAME_SIZE))
	{
		UnmapViewOfFile(view);
		CloseHandle(fileMap);
		return FALSE;
	}

	UnmapViewOfFile(view);
	CloseHandle(fileMap);

	// Translate path with device name to drive letters.
	WCHAR drives[512] = {0};
	if(!GetLogicalDriveStrings(512 - 1, drives))
		return FALSE;

	WCHAR systemName[MAX_PATH];
	WCHAR drive[3] = L" :";
	WCHAR* p = drives;

	do 
	{
		//Copy the drive letter to the template string
		*drive = *p;

		// Look up each device name
		if(QueryDosDevice(drive, systemName, MAX_PATH))
		{
			size_t length = wcslen(systemName);
			if((length < MAX_PATH) && (!_wcsnicmp(fileName, systemName, length)))
			{
				return wstring(drive) +  wstring(fileName + length);
			}
		}

		// Go to the next NULL character.
		while (*p++);
	}
	while(*p); //end of string

	return L"";
}

static PROCESS* DbgSspOnCreateProcess(DEBUGGER* _dbg, DEBUG_EVENT* _event)
{
	PROCESS* process  = new PROCESS;
	process->pid      = _event->dwProcessId;
	process->handle   = _event->u.CreateProcessInfo.hProcess;
	process->platform = DbgSspProcessPlatform(_event->u.CreateProcessInfo.hProcess);
	process->name     = DbgSspFileName(_event->u.CreateProcessInfo.hFile);
	process->peb      = DbgSspProcessPEB(_event->u.CreateProcessInfo.hProcess);

	if(_event->u.CreateProcessInfo.hFile)
		CloseHandle(_event->u.CreateProcessInfo.hFile);

	_dbg->processes.insert(pair<DWORD, PROCESS*>(_event->dwProcessId, process));
	_dbg->threads.insert(pair<DWORD, map<DWORD, THREAD*> >(_event->dwProcessId, map<DWORD, THREAD*>()));
	_dbg->modules.insert(pair<DWORD, map<LPVOID, MODULE*> >(_event->dwProcessId, map<LPVOID, MODULE*>()));

	return process;
}

static VOID DbgSspOnExitProcess(DEBUGGER* _dbg, DEBUG_EVENT* _event)
{
	map<DWORD, map<DWORD, THREAD*> >::iterator ts = _dbg->threads.find(_event->dwProcessId);
	for(map<DWORD, THREAD*>::iterator t = ts->second.begin(); t != ts->second.end(); t++)
	{
		delete [] t->second->teb;
		delete t->second;
	}
	_dbg->threads.erase(ts);

	map<DWORD, map<LPVOID, MODULE*> >::iterator ms = _dbg->modules.find(_event->dwProcessId);
	for(map<LPVOID, MODULE*>::iterator m = ms->second.begin(); m != ms->second.end(); m++)
	{
		delete m->second;
	}
	_dbg->modules.erase(ms);


	map<DWORD, PROCESS*>::iterator p = _dbg->processes.find(_event->dwProcessId);
	delete [] p->second->peb;
	delete p->second;
	_dbg->processes.erase(p);
}

static THREAD* DbgSspOnCreateThread(DEBUGGER* _dbg, DEBUG_EVENT* _event, BOOL _mainThread)
{
	PROCESS* process = DbgSsGetProcess(_dbg, _event->dwProcessId);

	THREAD* thread  = new THREAD;
	thread->process = process;
	thread->tid     = _event->dwThreadId;
	thread->handle  = _mainThread ? _event->u.CreateProcessInfo.hThread : _event->u.CreateThread.hThread;
	thread->teb     = DbgSspThreadTEB(process->handle, thread->handle);

	map<DWORD, map<DWORD, THREAD*> >::iterator i = _dbg->threads.find(_event->dwProcessId);
	i->second.insert(pair<DWORD, THREAD*>(_event->dwThreadId, thread));

	return thread;
}

static VOID DbgSspOnExitThread(DEBUGGER* _dbg, DEBUG_EVENT* _event)
{
	map<DWORD, map<DWORD, THREAD*> >::iterator i = _dbg->threads.find(_event->dwProcessId);

	map<DWORD, THREAD*>::iterator j = i->second.find(_event->dwThreadId);

	delete [] j->second->teb;
	delete j->second;
	i->second.erase(j);
}

static MODULE* DbgSspOnLoadDll(DEBUGGER* _dbg, DEBUG_EVENT* _event)
{
	PROCESS* process = DbgSsGetProcess(_dbg, _event->dwProcessId);

	MODULE* module  = new MODULE;
	module->process = process;
	module->base    = _event->u.LoadDll.lpBaseOfDll;
	module->handle  = (HMODULE)_event->u.LoadDll.lpBaseOfDll;
	module->name    = DbgSspFileName(_event->u.LoadDll.hFile);
	DbgSspModuleFillData(process->handle, module);

	if(_event->u.LoadDll.hFile)
		CloseHandle(_event->u.LoadDll.hFile);

	map<DWORD, map<LPVOID, MODULE*> >::iterator i = _dbg->modules.find(_event->dwProcessId);
	i->second.insert(pair<LPVOID, MODULE*>(_event->u.LoadDll.lpBaseOfDll, module));

	return module;
}

static VOID DbgSspOnUnloadDll(DEBUGGER* _dbg, DEBUG_EVENT* _event)
{
	map<DWORD, map<LPVOID, MODULE*> >::iterator i = _dbg->modules.find(_event->dwProcessId);

	map<LPVOID, MODULE*>::iterator j = i->second.find(_event->u.UnloadDll.lpBaseOfDll);

	delete j->second;
	i->second.erase(j);
}

static vector<PROCESS*> DbgSspEnumerateProcesses(DEBUGGER* _dbg)
{
	vector<PROCESS*> result;
	for (map<DWORD, PROCESS*>::iterator i = _dbg->processes.begin(); i != _dbg->processes.end(); i++)
		result.push_back(i->second);

	return result;
}

static vector<THREAD*> DbgSspEnumerateThreads(DEBUGGER* _dbg, DWORD _pid)
{
	vector<THREAD*> result;

	map<DWORD, map<DWORD, THREAD*> >::iterator i = _dbg->threads.find(_pid);
	if (i == _dbg->threads.end()) return result;

	for (map<DWORD, THREAD*>::iterator j = i->second.begin(); j != i->second.end(); j++)
		result.push_back(j->second);

	return result;
}

static vector<MODULE*> DbgSspEnumerateModules(DEBUGGER* _dbg, DWORD _pid)
{
	vector<MODULE*> result;

	map<DWORD, map<LPVOID, MODULE*> >::iterator i = _dbg->modules.find(_pid);
	if (i == _dbg->modules.end()) return result;

	for (map<LPVOID, MODULE*>::iterator j = i->second.begin(); j != i->second.end(); j++)
		result.push_back(j->second);

	return result;
}

//PUBLIC
PROCESS* __stdcall DbgSsGetProcess(DEBUGGER* _dbg, DWORD _pid)
{
	map<DWORD, PROCESS*>::iterator i = _dbg->processes.find(_pid);
	return i != _dbg->processes.end() ? i->second : 0;
}

THREAD* __stdcall DbgSsGetThread(DEBUGGER* _dbg, DWORD _pid, DWORD _tid)
{
	map<DWORD, map<DWORD, THREAD*> >::iterator i = _dbg->threads.find(_pid);
	if(i == _dbg->threads.end()) return 0;
	
	map<DWORD, THREAD*>::iterator j = i->second.find(_tid);
	return j != i->second.end() ? j->second : 0;
}

MODULE* __stdcall DbgSsGetModule(DEBUGGER* _dbg, DWORD _pid, LPVOID _base)
{
	map<DWORD, map<LPVOID, MODULE*> >::iterator i = _dbg->modules.find(_pid);
	if(i == _dbg->modules.end()) return 0;

	map<LPVOID, MODULE*>::iterator j = i->second.find(_base);
	return j != i->second.end() ? j->second : 0;
}

DWORD __stdcall DbgSsProcessesNumber(DEBUGGER* _dbg)
{
	DWORD result = 0;
	for (map<DWORD, PROCESS*>::iterator i = _dbg->processes.begin(); i != _dbg->processes.end(); i++)
		result++;

	return result;
}

PROCESS* __stdcall DbgSsAccessProcess(DEBUGGER* _dbg, UINT _index)
{
	for (map<DWORD, PROCESS*>::iterator i = _dbg->processes.begin(); i != _dbg->processes.end(); i++)
	{
		if (!_index)
			return i->second;
		_index--;
	}

	return 0;
}

DWORD __stdcall DbgSsThreadsNumber(DEBUGGER* _dbg, DWORD _pid)
{
	DWORD result = 0;

	map<DWORD, map<DWORD, THREAD*> >::iterator i = _dbg->threads.find(_pid);
	if (i == _dbg->threads.end()) return result;

	for (map<DWORD, THREAD*>::iterator j = i->second.begin(); j != i->second.end(); j++)
		result++;

	return result;
}

THREAD* __stdcall DbgSsAccessThread(DEBUGGER* _dbg, DWORD _pid, UINT _index)
{
	map<DWORD, map<DWORD, THREAD*> >::iterator i = _dbg->threads.find(_pid);
	if (i == _dbg->threads.end()) return 0;

	for (map<DWORD, THREAD*>::iterator j = i->second.begin(); j != i->second.end(); j++)
	{
		if (!_index)
			return j->second;
		_index--;
	}

	return 0;

}

DWORD __stdcall DbgSsModulesNumber(DEBUGGER* _dbg, DWORD _pid)
{
	DWORD result = 0;

	map<DWORD, map<LPVOID, MODULE*> >::iterator i = _dbg->modules.find(_pid);
	if (i == _dbg->modules.end()) return result;

	for (map<LPVOID, MODULE*>::iterator j = i->second.begin(); j != i->second.end(); j++)
		result++;

	return result;
}

MODULE* __stdcall DbgSsAccessModule(DEBUGGER* _dbg, DWORD _pid, UINT _index)
{
	map<DWORD, map<LPVOID, MODULE*> >::iterator i = _dbg->modules.find(_pid);
	if (i == _dbg->modules.end()) return 0;

	for (map<LPVOID, MODULE*>::iterator j = i->second.begin(); j != i->second.end(); j++)
	{
		if (!_index)
			return j->second;
		_index--;
	}

	return 0;
}

/////////////////////////////////////////////////////////////////////////////
//BREAKPOINTS MANAGEMENT
/////////////////////////////////////////////////////////////////////////////
//PRIVATE
static BREAKPOINT* DbgBppGetSoftwareBreakpoint(DEBUGGER* _dbg, DWORD _pid, LPVOID _address)
{
	map<DWORD, map<LPVOID, BREAKPOINT> >::iterator i = _dbg->breakpoints.find(_pid);
	if(i == _dbg->breakpoints.end())
		return 0;

	map<LPVOID, BREAKPOINT>::iterator j = i->second.find(_address);
	if(j == i->second.end())
		return 0;

	return &j->second;
}

static LPVOID DbgBppGetHardwareBreakpoint(CONTEXT* _context)
{
	ULONG_PTR who = _context->Dr6 & 0x0000000F;

	if(who == DR0)
		return (LPVOID)_context->Dr0;

	if(who == DR1)
		return (LPVOID)_context->Dr1;

	if(who == DR2)
		return (LPVOID)_context->Dr2;

	if(who == DR3)
		return (LPVOID)_context->Dr3;

	return 0;
}

static BOOL DbgBppOnInt01(DEBUGGER* _dbg, DWORD _pid, DWORD _tid, LPVOID _address)
{
	THREAD* thread = _dbg->threads[_pid][_tid];

	CONTEXT context = {0};
	context.ContextFlags = CONTEXT_ALL;
	if(!GetThreadContext(thread->handle, &context))
		return FALSE;

	if(DbgBppGetHardwareBreakpoint(&context) == _address)
	{
		context.EFlags |= 0x00010000;
		return SetThreadContext(thread->handle, &context);
	}

	BREAKPOINT* bp = DbgBppGetSoftwareBreakpoint(_dbg, _pid, _address);
	if(bp)
	{
		context.EFlags &= 0xFFFFFEFF;

		if(!SetThreadContext(thread->handle, &context))
			return FALSE;

		static const BYTE exceptionOpcodeByte = 0xCC;
		if(!WriteProcessMemory(thread->process->handle, bp->address, &exceptionOpcodeByte, 1, 0))
			return FALSE;
	}

	return FALSE;
}

static BOOL DbgBppOnInt03(DEBUGGER* _dbg, DWORD _pid, DWORD _tid, LPVOID _address)
{
	//Find breakpoint
	BREAKPOINT* bp = DbgBppGetSoftwareBreakpoint(_dbg, _pid, _address);
	if(!bp)
		return FALSE;

	THREAD* thread = _dbg->threads[_pid][_tid];

	CONTEXT context = {0};
	context.ContextFlags = CONTEXT_ALL;
	if(!GetThreadContext(thread->handle, &context))
		return FALSE;

	if(!bp->oneShot)
		context.EFlags |= 0x00000100;

#ifdef _WIN64
	context.Rip -= 1;
#else
	context.Eip -= 1;
#endif

	if(!SetThreadContext(thread->handle, &context))
		return FALSE;

	if(!WriteProcessMemory(thread->process->handle, bp->address, &bp->original, 1, 0))
		return FALSE;

	if(bp->oneShot)
	{
		map<DWORD, map<LPVOID, BREAKPOINT> >::iterator i = _dbg->breakpoints.find(_pid);
		map<LPVOID, BREAKPOINT>::iterator j = i->second.find(_address);
		i->second.erase(j);
	}

	return TRUE;
}

//PUBLIC
BOOL __stdcall DbgBpNewSoftware(DEBUGGER* _dbg, DWORD _pid, LPVOID _address, BOOL _oneShot)
{
	PROCESS* process = DbgSsGetProcess(_dbg, _pid);
	if(!process)
		return FALSE;

	//Prepare breakpoint
	BREAKPOINT bp;
	bp.address = _address;
	bp.oneShot = _oneShot;

	if(_oneShot)
	{
		//If one shot, when hit, will be deleted
		if(!ReadProcessMemory(process->handle, bp.address, &bp.original, 1, 0))
			return FALSE;

		bp.singleStepAddress = 0;
	}
	else
	{
		//If persistent, when hit, need to put a single step exception matching the address of the next disassembled instruction to reput the breakpoint
		BYTE buffer[16] = {0};
		if(!ReadProcessMemory(process->handle, bp.address, buffer, 16, 0))
			return FALSE;

		MODULE* module = DbgModuleForAddress(_dbg, _pid, bp.address);
		bp.original = buffer[0];
		bp.singleStepAddress = (BYTE*)bp.address + DasmInstSize(buffer, 16, module ? module->platform : process->platform);
	}
	
	//Set physical breakpoint
	static const BYTE exceptionOpcodeByte = 0xCC;
	if(!WriteProcessMemory(process->handle, bp.address, &exceptionOpcodeByte, 1, 0))
		return FALSE;

	//Update internal data
	map<DWORD, map<LPVOID, BREAKPOINT> >::iterator i = _dbg->breakpoints.find(_pid);
	if(i == _dbg->breakpoints.end())
	{
		pair<map<DWORD, map<LPVOID, BREAKPOINT> >::iterator, bool> r = _dbg->breakpoints.insert(pair<DWORD, map<LPVOID, BREAKPOINT> >(_pid, map<LPVOID, BREAKPOINT>()));
		i = r.first;
	}
	i->second.insert(pair<LPVOID, BREAKPOINT>(bp.address, bp));

	if(!_oneShot)
		i->second.insert(pair<LPVOID, BREAKPOINT>(bp.singleStepAddress, bp));

	//Ok
	return TRUE;
}

BOOL __stdcall DbgBpDelSoftware(DEBUGGER* _dbg, DWORD _pid, LPVOID _address)
{
	//Find breakpoint
	BREAKPOINT* bp = DbgBppGetSoftwareBreakpoint(_dbg, _pid, _address);
	if(!bp)
		return TRUE;

	//Physical restore
	PROCESS* process = DbgSsGetProcess(_dbg, _pid);
	if(!WriteProcessMemory(process->handle, bp->address, &bp->original, 1, 0))
		return FALSE;

	//Update internal data
	BREAKPOINT bpp = *bp;
	map<DWORD, map<LPVOID, BREAKPOINT> >::iterator i = _dbg->breakpoints.find(_pid);
	map<LPVOID, BREAKPOINT>::iterator j = i->second.find(_address);
	i->second.erase(j);
	if(!bpp.oneShot)
	{
		j = i->second.find(bpp.singleStepAddress);
		i->second.erase(j);
	}
	
	return TRUE;
}

BOOL __stdcall DbgBpNewHardware(DEBUGGER* _dbg, DWORD _pid, DWORD _tid, DWORD _debugRegister, LPVOID _address)
{
	if(_debugRegister > DR3)
		return FALSE;

	THREAD* thread = DbgSsGetThread(_dbg, _pid, _tid);
	if(!thread)
		return FALSE;

	CONTEXT context = {0};
	context.ContextFlags = CONTEXT_ALL;
	if(!GetThreadContext(thread->handle, &context))
		return FALSE;

	ULONG_PTR andMask = 0;
	ULONG_PTR orMask = 0;
	switch(_debugRegister)
	{
		case DR0: context.Dr0 = (ULONG_PTR)_address; andMask = 0xFFF0FFFC; orMask = 0x00000001; break;
		case DR1: context.Dr1 = (ULONG_PTR)_address; andMask = 0xFF0FFFF3; orMask = 0x00000004; break;
		case DR2: context.Dr2 = (ULONG_PTR)_address; andMask = 0xF0FFFFCF; orMask = 0x00000010; break;
		case DR3: context.Dr3 = (ULONG_PTR)_address; andMask = 0x0FFFFF3F; orMask = 0x00000040; break;
	}

	context.Dr7 &= andMask;
	context.Dr7 |= orMask; 

	return SetThreadContext(thread->handle, &context);
}

BOOL __stdcall DbgBpDelHardware(DEBUGGER* _dbg, DWORD _pid, DWORD _tid, DWORD _debugRegisterMask)
{
	if(!(_debugRegisterMask &= DR_ALL))
		return FALSE;

	THREAD* thread = DbgSsGetThread(_dbg, _pid, _tid);
	if(!thread)
		return FALSE;

	CONTEXT context = {0};
	context.ContextFlags = CONTEXT_ALL;
	if(!GetThreadContext(thread->handle, &context))
		return FALSE;

	if(_debugRegisterMask & DR0)
	{
		context.Dr0 = 0;
		context.Dr7 &= 0xFFF0FFFC;
	}
	if(_debugRegisterMask & DR1)
	{
		context.Dr1 = 0;
		context.Dr7 &= 0xFF0FFFF3;
	}
	if(_debugRegisterMask & DR2)
	{
		context.Dr2 = 0;
		context.Dr7 &= 0xF0FFFFCF;
	}
	if(_debugRegisterMask & DR3)
	{
		context.Dr3 = 0;
		context.Dr7 &= 0x0FFFFF3F;
	}

	return SetThreadContext(thread->handle, &context);
}


/////////////////////////////////////////////////////////////////////////////
//MISCELLANEOUS MANAGEMENT
/////////////////////////////////////////////////////////////////////////////
LPVOID __stdcall DbgFindApi(DEBUGGER* _dbg, DWORD _pid, LPCWSTR _library, LPCSTR _function)
{
	map<DWORD, map<LPVOID, MODULE*> >::iterator i = _dbg->modules.find(_pid);
	if(i == _dbg->modules.end()) return 0;

	for(map<LPVOID, MODULE*>::iterator j = i->second.begin(); j != i->second.end(); j++)
	{
		MODULE* module = j->second;
		if(!_wcsicmp(FILENAME(module->name).c_str(), _library))
		{
			for(UINT j = 0; j < module->exports.size(); j++)
			{
				if(!_stricmp(module->exports[j].name.c_str(), _function))
				{
					return module->exports[j].address;
				}
			}
		}
	}

	return 0;
}

MODULE* __stdcall DbgModuleForAddress(DEBUGGER* _dbg, DWORD _pid, LPVOID _address)
{
	map<DWORD, map<LPVOID, MODULE*> >::iterator i = _dbg->modules.find(_pid);
	if(i == _dbg->modules.end()) return 0;

	ULONG_PTR address = (ULONG_PTR)_address;

	for(map<LPVOID, MODULE*>::iterator j = i->second.begin(); j != i->second.end(); j++)
	{
		MODULE* module = j->second;
		ULONG_PTR base = (ULONG_PTR)module->base;
		DWORD     size = module->size;

		if(base <= address && address < base + size)
		{
			return module;
		}
	}

	return 0;
}

ULONG_PTR __stdcall DbgStackRead(DEBUGGER* _dbg, DWORD _pid, DWORD _tid, INT _displacementInWordsFromStackPointer)
{
	THREAD* thread = DbgSsGetThread(_dbg, _pid, _tid);
	if(!thread)
		return 0;

	CONTEXT context = {0};
	context.ContextFlags = CONTEXT_ALL;
	if(!GetThreadContext(thread->handle, &context))
		return 0;

	ULONG_PTR sp = 0;
#ifdef _WIN64
	sp = context.Rsp;
#else
	sp = context.Esp;
#endif
	UINT size = thread->process->platform / 8;
	ULONG_PTR data = 0;
	ReadProcessMemory(thread->process->handle, (LPVOID)(sp + _displacementInWordsFromStackPointer * size), &data, size, 0);
	return data;
}

ULONG_PTR __stdcall DbgStackReadParameter(DEBUGGER* _dbg, DWORD _pid, DWORD _tid, UINT _parameter)
{
#ifdef _WIN64
	THREAD* thread = DbgSsGetThread(_dbg, _pid, _tid);
	if(!thread)
		return 0;

	if(thread->process->platform == 64 && _parameter <= 3)
	{
		CONTEXT context = {0};
		context.ContextFlags = CONTEXT_ALL;
		if(!GetThreadContext(thread->handle, &context))
			return 0;

		switch(_parameter)
		{
		case 0: return context.Rcx;
		case 1: return context.Rdx;
		case 2: return context.R8;
		case 3: return context.R9;
		}
	}
#endif
	return DbgStackRead(_dbg, _pid, _tid, _parameter + 1);
}

ULONG_PTR __stdcall DbgStackReturnAddress(DEBUGGER* _dbg, DWORD _pid, DWORD _tid)
{
	return DbgStackRead(_dbg, _pid, _tid, 0);
}
