#include <windows.h>

BOOL APIENTRY DllMain(HANDLE _module, DWORD _reason, LPVOID _reserved)
{
	BOOL dynamicallyLoaded = _reserved == 0 && (_reason == DLL_PROCESS_ATTACH || _reason == DLL_PROCESS_DETACH);

	if (_reason == DLL_PROCESS_ATTACH)
	{
		//Initialization
	}
	else if (_reason == DLL_PROCESS_DETACH)
	{
		//Shutdown
	}
	else if (_reason == DLL_THREAD_ATTACH)
	{
	}
	else if (_reason == DLL_THREAD_DETACH)
	{
	}

	return TRUE;
}

/*
/////////////////////////////////////////////////////////////////////////
//ANTI EXPLOIT
/////////////////////////////////////////////////////////////////////////
struct ANTI_EXPLOIT
{
	DEBUGGER* dbg;
	INSPECTOR inspector;

	ANTI_EXPLOIT();
	~ANTI_EXPLOIT();
};

UINT AeOnCreateProcess(LPVOID _context, DWORD _pid, PROCESS* _process)
{
	ANTI_EXPLOIT* ae = (ANTI_EXPLOIT*)_context;
	if (DbgOriginalPid(ae->dbg) == _pid)
	{
		wprintf(L"[%d] PROCESS ROOT: [%d]%s\n", DbgOriginalPid(ae->dbg), _pid, FILENAME(_process->name).c_str());
		return DBG_DEBUG_TREE;
	}

	if (AeGrpIsApplicationProtected(FILENAME(_process->name).c_str()))
	{
		wprintf(L"[%d] PROTECTING PROCESS: [%d]%s\n", DbgOriginalPid(ae->dbg), _pid, FILENAME(_process->name).c_str());
		return DBG_DEBUG_TREE;
	}

	return DBG_DONT_DEBUG;
}

VOID AeOnExitProcess(LPVOID _context, DWORD _pid, DWORD _exitCode)
{
	ANTI_EXPLOIT* ae = (ANTI_EXPLOIT*)_context;
	wprintf(L"[%d] PROCESS EXITING: [%d]\n", DbgOriginalPid(ae->dbg), _pid);
}

VOID AeOnCreateThread(LPVOID _context, DWORD _pid, THREAD* _thread){}
VOID AeOnExitThread(LPVOID _context, DWORD _pid, DWORD _tid){}
VOID AeOnLoadDll(LPVOID _context, DWORD _pid, MODULE* _module){}
VOID AeOnUnloadDll(LPVOID _context, DWORD _pid, LPVOID _module){}
VOID AeOnHardwareBreakpoint(LPVOID _context, DWORD _pid, DWORD _tid, LPVOID _address){}
VOID AeOnSoftwareBreakpoint(LPVOID _context, DWORD _pid, DWORD _tid, LPVOID _address){}
VOID AeOnException(LPVOID _context, DWORD _pid, DWORD _tid, BOOL _firstChance, EXCEPTION_RECORD* _exception){}
VOID AeOnDebugString(LPVOID _context, DWORD _pid, const wstring& _debugString){}
VOID AeOnRIP(LPVOID _context, DWORD _pid, DWORD _error){}

ANTI_EXPLOIT::ANTI_EXPLOIT()
{
	dbg = DbgNew();

	inspector.context = this;
	inspector.OnCreateProcess = AeOnCreateProcess;
	inspector.OnExitProcess = AeOnExitProcess;
	inspector.OnCreateThread = AeOnCreateThread;
	inspector.OnExitThread = AeOnExitThread;
	inspector.OnLoadDll = AeOnLoadDll;
	inspector.OnUnloadDll = AeOnUnloadDll;
	inspector.OnHardwareBreakpoint = AeOnHardwareBreakpoint;
	inspector.OnSoftwareBreakpoint = AeOnSoftwareBreakpoint;
	inspector.OnException = AeOnException;
	inspector.OnDebugString = AeOnDebugString;
	inspector.OnRIP = AeOnRIP;
}
ANTI_EXPLOIT::~ANTI_EXPLOIT()
{
	DbgDelete(dbg);
}

/////////////////////////////////////////////////////////////////////////
//AEPOC
/////////////////////////////////////////////////////////////////////////
struct AEPOC
{
	BOOL multiInstance;
	map<DWORD, ANTI_EXPLOIT*> aes;

	AEPOC();
};

AEPOC gAepoc;

AEPOC::AEPOC()
{
}

VOID AepocNewAntiexploit(DWORD _parentPid, DWORD _pid, LPCWSTR _applicationName, LPCWSTR _commandLine)
{
	if (!AeGrpIsApplicationProtected(FILENAME(wstring(_applicationName)).c_str()))
		return;

	ANTI_EXPLOIT* ae = new ANTI_EXPLOIT();
	if (DbgAttach(ae->dbg, _pid, &ae->inspector) == ERROR_SUCCESS)
	{
		gAepoc.aes.insert(pair<DWORD, ANTI_EXPLOIT*>(_pid, ae));
	}
}


/////////////////////////////////////////////////////////////////////////
//PUBLIC INTERFACE
/////////////////////////////////////////////////////////////////////////
BOOL AeStart(BOOL _multiInstance)
{
	gAepoc.multiInstance = _multiInstance;

	if (_multiInstance)
	{
		//Use Process Monitor
		return PmStart();
	}
	else
	{
		DWORD pid = PmExplorerPID();
		if (!pid)
			return FALSE;

		printf("\nEXPLORER.EXE PID = %d\n", pid);

		ANTI_EXPLOIT* ae = new ANTI_EXPLOIT();
		if (DbgAttach(ae->dbg, pid, &ae->inspector) == ERROR_SUCCESS)
		{
			gAepoc.aes.insert(pair<DWORD, ANTI_EXPLOIT*>(pid, ae));
			return TRUE;
		}
	}

	return FALSE;
}

BOOL AeStop()
{

	for (map<DWORD, ANTI_EXPLOIT*>::iterator i = gAepoc.aes.begin(); i != gAepoc.aes.end(); i++)
		DbgDetach(i->second->dbg, FALSE);

	if (gAepoc.multiInstance)
	{
		return PmStop();
	}

	return TRUE;
}
*/