#include "../inc/dbg.h"
#include "Tools.h"

#include <map>
using namespace std;

#include <psapi.h>
#pragma comment(lib, "psapi.lib")

struct ON_CREATE_PROCESS_INFO
{
	LPCWSTR applicationName;
	LPCWSTR commandLine;
	BOOL    needToResume;
	LPVOID  processInfoAddress;
};

struct PROCESS_MONITOR
{
	DEBUGGER*           dbg;
	INSPECTOR           inspector;
	LPFN_PMONNEWPROCESS onNewProcessCallback;

	LPVOID    createProcessInternal;
	map<DWORD, ON_CREATE_PROCESS_INFO> createProcessInfo;

	PROCESS_MONITOR();
};

static VOID __stdcall PmpOnCreateThread(LPVOID _context, DWORD _pid, THREAD* _thread)
{
	PROCESS_MONITOR* pm = (PROCESS_MONITOR*)_context;
	if(pm->createProcessInternal)
		DbgBpNewHardware(pm->dbg, _pid, ThreadTID(_thread), DR3, pm->createProcessInternal);
}

static VOID __stdcall PmpOnLoadDll(LPVOID _context, DWORD _pid, MODULE* _module)
{
	PROCESS_MONITOR* pm = (PROCESS_MONITOR*)_context;
	
	if(!_wcsicmp(FILENAME(wstring(ModuleName(_module))).c_str(), L"kernel32.dll"))
	{
		for(UINT i = 0; i < ModuleExportsSize(_module); i++)
		{
			FUNCTION* f = ModuleExportsFunction(_module, i);

			if(!_stricmp(FunctionName(f), "CreateProcessInternalW"))
			{
				pm->createProcessInternal = FunctionAddress(f);
			}
		}

		if(pm->createProcessInternal)
		{
			for(UINT j = 0; j < DbgSsThreadsNumber(pm->dbg, _pid); j++)
			{
				THREAD* t = DbgSsAccessThread(pm->dbg, _pid, j);
				DbgBpNewHardware(pm->dbg, _pid, ThreadTID(t), DR3, pm->createProcessInternal);
			}
		}
	}
}

static VOID __stdcall PmpOnHardwareBreakpoint(LPVOID _context, DWORD _pid, DWORD _tid, LPVOID _address)
{
	PROCESS_MONITOR* pm = (PROCESS_MONITOR*)_context;

	THREAD* thread = DbgSsGetThread(pm->dbg, _pid, _tid);

	CONTEXT context = {0};
	context.ContextFlags = CONTEXT_ALL;
	if(!GetThreadContext(ThreadHandle(thread), &context))
		return;

	if(_address == pm->createProcessInternal)
	{
		LPVOID returnAddress = (LPVOID)DbgStackReturnAddress(pm->dbg, _pid, _tid);
		DbgBpNewHardware(pm->dbg, _pid, _tid, DR3, returnAddress);

		//Get parameters
		WCHAR* appName = 0;
		LPVOID p1 = (LPVOID)DbgStackReadParameter(pm->dbg, _pid, _tid, 1);
		if(p1)
		{
			appName = new WCHAR[MAX_PATH]();
			ReadProcessMemory(ProcessHandle(ThreadProcess(thread)), p1, appName, MAX_PATH - 1, 0);
		}
		WCHAR* commandLine = 0;
		LPVOID p2 = (LPVOID)DbgStackReadParameter(pm->dbg, _pid, _tid, 2);
		if(p2)
		{
			commandLine = new WCHAR[1024]();
			ReadProcessMemory(ProcessHandle(ThreadProcess(thread)), p2, commandLine, 1024 - 1, 0);
		}

		ULONG_PTR flags = DbgStackReadParameter(pm->dbg, _pid, _tid, 6);

		ON_CREATE_PROCESS_INFO info = {0};
		info.applicationName    = appName;
		info.commandLine        = commandLine;
		info.needToResume       = !(flags & CREATE_SUSPENDED);
		info.processInfoAddress = (LPVOID)DbgStackReadParameter(pm->dbg, _pid, _tid, 10);
		pm->createProcessInfo.insert(pair<DWORD, ON_CREATE_PROCESS_INFO>(_tid, info));

		if(info.needToResume)
		{
			flags |= CREATE_SUSPENDED;
#ifdef _WIN64
			WriteProcessMemory(ProcessHandle(ThreadProcess(thread)), (LPVOID)(context.Rsp + 7*(ProcessPlatform(ThreadProcess(thread))/8)), &flags, ProcessPlatform(ThreadProcess(thread))/8, 0);
#else
			WriteProcessMemory(ProcessHandle(ThreadProcess(thread)), (LPVOID)(context.Esp + 7*(ProcessPlatform(ThreadProcess(thread))/8)), &flags, ProcessPlatform(ThreadProcess(thread))/8, 0);
#endif
		}
	}
	else
	{
		DbgBpNewHardware(pm->dbg, _pid, _tid, DR3, pm->createProcessInternal);

		//Get output data
		ON_CREATE_PROCESS_INFO info = pm->createProcessInfo[_tid];
		BYTE processInfo[24] = {0};
		if(info.processInfoAddress)
			ReadProcessMemory(ProcessHandle(ThreadProcess(thread)), info.processInfoAddress, &processInfo, sizeof(processInfo), 0);

		DWORD newPid = 0;
		DWORD newTid = 0;
		if(ProcessPlatform(ThreadProcess(thread)) == 32)
		{
			newPid = *(DWORD*)(processInfo + 8);
			newTid = *(DWORD*)(processInfo + 12);
		}
		else
		{
			newPid = *(DWORD*)(processInfo + 16);
			newTid = *(DWORD*)(processInfo + 20);
		}

		//Here NOTIFY
		pm->onNewProcessCallback(_pid, newPid, info.applicationName ? info.applicationName : L"", info.commandLine ? info.commandLine : L"");

		//Resume
		if(info.needToResume)
		{
			HANDLE mainAppThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, newTid);
			ResumeThread(mainAppThread);
			CloseHandle(mainAppThread);
		}

		//Clean
		delete[] info.applicationName;
		delete[] info.commandLine;
		pm->createProcessInfo.erase(pm->createProcessInfo.find(_tid));
	}
}

PROCESS_MONITOR::PROCESS_MONITOR()
{
	dbg = 0;
	createProcessInternal = 0;
	onNewProcessCallback = 0;


	inspector.context = this;
	inspector.OnCreateProcess      = 0;
	inspector.OnExitProcess        = 0;
	inspector.OnCreateThread       = PmpOnCreateThread;
	inspector.OnExitThread         = 0;
	inspector.OnLoadDll            = PmpOnLoadDll;
	inspector.OnUnloadDll          = 0;
	inspector.OnHardwareBreakpoint = PmpOnHardwareBreakpoint;
	inspector.OnSoftwareBreakpoint = 0;
	inspector.OnException          = 0;
	inspector.OnDebugString        = 0;
	inspector.OnRIP                = 0;
}

static PROCESS_MONITOR gProcessMonitor; 

static DWORD PmpExplorerPID()
{
#define NUMBER_OF_PROCESSES 256

	DWORD  lastError = ERROR_SUCCESS;
	DWORD* pids = 0;
	DWORD  number = NUMBER_OF_PROCESSES;

	for(;;)
	{
		pids = new (std::nothrow) DWORD[number];
		if(!pids)
		{
			//Memory error
			lastError = ERROR_NOT_ENOUGH_MEMORY;
			pids = 0;
			number = 0;
			break;
		}

		DWORD bytesNeeded = 0;
		if(::EnumProcesses(pids, number * sizeof(DWORD), &bytesNeeded))
		{
			//Did we have enough space?
			DWORD used = bytesNeeded / sizeof(DWORD);
			if(used < number)
			{
				//We're OK, remember the value
				number = used;
				break;
			}
			else
			{
				//Reserve more memory in the next iteration
				delete[] pids;
				pids = 0;
				number += NUMBER_OF_PROCESSES;
			}
		}
		else
		{
			//Error
			lastError = ::GetLastError();
			delete[] pids;
			pids = 0;
			number = 0;
			break;
		}
	}

	//Actualize error
	if(lastError != ERROR_SUCCESS)
	{
		::SetLastError(lastError);
		return 0;
	}

	DWORD pid = 0;
	for(DWORD i = 0; i < number; i++)
	{
		HANDLE process = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pids[i]);
		if(!process)
			continue;

		DWORD pathSize = MAX_PATH;
		WCHAR* imageFullPath = 0;

		while(pathSize <= 5 * MAX_PATH)
		{
			imageFullPath = new WCHAR[pathSize];

			if(::GetProcessImageFileNameW(process, imageFullPath, pathSize))
				break;

			DWORD lastError = ::GetLastError();

			delete[] imageFullPath;
			imageFullPath = 0;
			pathSize += MAX_PATH;

			if(lastError != ERROR_INSUFFICIENT_BUFFER)
				break;
		}

		::CloseHandle(process);

		if(!imageFullPath)
			continue;

		wstring name = FILENAME(wstring(imageFullPath));

		delete [] imageFullPath;

		if(_wcsicmp(L"explorer.exe", name.c_str()))
			continue;

		pid = pids[i];
		break;
	}

	delete [] pids;
	return pid;
}

BOOL __stdcall PmStart(LPFN_PMONNEWPROCESS _onNewProcessCallback)
{
	if(!_onNewProcessCallback)
		return FALSE;

	DWORD pid = PmpExplorerPID();
	if(!pid)
		return FALSE;

	//printf("\nEXPLORER.EXE PID = %d\n", pid);

	gProcessMonitor.dbg = DbgNew();
	if(!gProcessMonitor.dbg)
		return FALSE;

	if(DbgAttach(gProcessMonitor.dbg, pid, &gProcessMonitor.inspector) != ERROR_SUCCESS)
	{
		DbgDelete(gProcessMonitor.dbg);
		gProcessMonitor.dbg = 0;
		return FALSE;
	}

	gProcessMonitor.onNewProcessCallback = _onNewProcessCallback;

	return TRUE;
}

BOOL __stdcall PmStop()
{
	if(!gProcessMonitor.dbg)
		return TRUE;

	DbgDetach(gProcessMonitor.dbg, FALSE);
	DbgDelete(gProcessMonitor.dbg);
	gProcessMonitor.dbg = 0;

	gProcessMonitor.createProcessInternal = 0;

	gProcessMonitor.createProcessInfo.clear();

	gProcessMonitor.onNewProcessCallback = 0;

	return TRUE;
}
