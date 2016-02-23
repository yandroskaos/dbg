#ifndef __DBG_H__
#define __DBG_H__

#include <windows.h>

/////////////////
//CONFIGURATION//
/////////////////
#define VER_MAJOR	0
#define VER_MINOR	9
#define VER_TYPE	1
#define VER_BUILD	1

//////
//OS//
//////
#define OS_WINDOWS_SERVER_10			0x8000
#define OS_WINDOWS_10					0x4000
#define OS_WINDOWS_SERVER_2012_R2		0x2000
#define OS_WINDOWS_81					0x1000
#define OS_WINDOWS_SERVER_2012			0x0800
#define OS_WINDOWS_8					0x0400
#define OS_WINDOWS_SERVER_2008_R2		0x0200
#define OS_WINDOWS_7					0x0100
#define OS_WINDOWS_SERVER_2008			0x0080
#define OS_WINDOWS_VISTA				0x0040
#define OS_WINDOWS_HOME_SERVER			0x0020
#define OS_WINDOWS_XP64					0x0010
#define OS_WINDOWS_SERVER_2003_R2		0x0008
#define OS_WINDOWS_SERVER_2003			0x0004
#define OS_WINDOWS_XP					0x0002
#define OS_WINDOWS_2000					0x0001
#define OS_UNKNOWN						0x0000
#define OS_WINDOWS_ALL					0xFFFF

#define OS_ABOVE(X)			(OS_WINDOWS_ALL & ~(X - 1)) //!< [X, HIGHEST_WINDOWS_OS] X Contained
#define OS_BELOW(X)			(X - 1)						//!< [LOWEST_WINDOWS_OS, X)  X NOT Contained
#define OS_BETWEEN(L, H)	(OS_BELOW(H) & OS_ABOVE(L))	//!< [L, H) L Contained, H NOT Contained

DWORD __stdcall OSVersion();
DWORD __stdcall OSGroup();
DWORD __stdcall OSPlatform();

////////////
//DEBUGGER//
////////////
struct PROCESS;
DWORD   __stdcall ProcessPID(PROCESS* _process);
HANDLE  __stdcall ProcessHandle(PROCESS* _process);
DWORD   __stdcall ProcessPlatform(PROCESS* _process);
LPCWSTR __stdcall ProcessName(PROCESS* _process);
LPVOID  __stdcall ProcessPEB(PROCESS* _process);

struct THREAD;
PROCESS* __stdcall ThreadProcess(THREAD* _thread);
DWORD    __stdcall ThreadTID(THREAD* _thread);
HANDLE   __stdcall ThreadHandle(THREAD* _thread);
LPVOID   __stdcall ThreadTEB(THREAD* _thread);

struct FUNCTION;

struct MODULE;
PROCESS*   __stdcall ModuleProcess(MODULE* _module);
LPVOID     __stdcall ModuleBase(MODULE* _module);
HMODULE    __stdcall ModuleHandle(MODULE* _module);
DWORD      __stdcall ModuleSize(MODULE* _module);
DWORD      __stdcall ModulePlatform(MODULE* _module);
LPCWSTR    __stdcall ModuleName(MODULE* _module);
FUNCTION*  __stdcall ModuleExportsFunction(MODULE* _module, UINT _index);
DWORD      __stdcall ModuleExportsSize(MODULE* _module);

MODULE* __stdcall FunctionModule(FUNCTION* _function);
LPVOID  __stdcall FunctionAddress(FUNCTION* _function);
LPCSTR  __stdcall FunctionName(FUNCTION* _function);

//OnCreateProcess event
#define DBG_DONT_DEBUG    0
#define DBG_DEBUG_PROCESS 1
#define DBG_DEBUG_TREE    2

struct INSPECTOR
{
	LPVOID context;

	UINT (__stdcall *OnCreateProcess)      (LPVOID _context, DWORD _pid, PROCESS* _process);
	VOID (__stdcall *OnExitProcess)        (LPVOID _context, DWORD _pid, DWORD _exitCode);
	VOID (__stdcall *OnCreateThread)       (LPVOID _context, DWORD _pid, THREAD* _thread);
	VOID (__stdcall *OnExitThread)         (LPVOID _context, DWORD _pid, DWORD _tid);
	VOID (__stdcall *OnLoadDll)            (LPVOID _context, DWORD _pid, MODULE* _module);
	VOID (__stdcall *OnUnloadDll)          (LPVOID _context, DWORD _pid, LPVOID _module);
	VOID (__stdcall *OnHardwareBreakpoint) (LPVOID _context, DWORD _pid, DWORD _tid, LPVOID _address);
	VOID (__stdcall *OnSoftwareBreakpoint) (LPVOID _context, DWORD _pid, DWORD _tid, LPVOID _address);
	VOID (__stdcall *OnException)          (LPVOID _context, DWORD _pid, DWORD _tid, BOOL _firstChance, EXCEPTION_RECORD* _exception);
	VOID (__stdcall *OnDebugString)        (LPVOID _context, DWORD _pid, LPCWSTR _debugString);
	VOID (__stdcall *OnRIP)                (LPVOID _context, DWORD _pid, DWORD _error);
};

struct DEBUGGER;

DEBUGGER* __stdcall DbgNew();
VOID      __stdcall DbgDelete(DEBUGGER* _dbg);
DWORD     __stdcall DbgAttach(DEBUGGER* _dbg, DWORD _pid, INSPECTOR* _inspector);
VOID      __stdcall DbgDetach(DEBUGGER* _dbg, BOOL _killOnExit);
DWORD     __stdcall DbgOriginalPid(DEBUGGER* _dbg);

//Session management
PROCESS*  __stdcall DbgSsGetProcess(DEBUGGER* _dbg, DWORD _pid);
THREAD*   __stdcall DbgSsGetThread(DEBUGGER* _dbg, DWORD _pid, DWORD _tid);
MODULE*   __stdcall DbgSsGetModule(DEBUGGER* _dbg, DWORD _pid, LPVOID _base);

DWORD    __stdcall DbgSsProcessesNumber(DEBUGGER* _dbg);
PROCESS* __stdcall DbgSsAccessProcess(DEBUGGER* _dbg, UINT _index);
DWORD    __stdcall DbgSsThreadsNumber(DEBUGGER* _dbg, DWORD _pid);
THREAD*  __stdcall DbgSsAccessThread(DEBUGGER* _dbg, DWORD _pid, UINT _index);
DWORD    __stdcall DbgSsModulesNumber(DEBUGGER* _dbg, DWORD _pid);
MODULE*  __stdcall DbgSsAccessModule(DEBUGGER* _dbg, DWORD _pid, UINT _index);


//Breakpoints management
#define DR0 0x01
#define DR1 0x02
#define DR2 0x04
#define DR3 0x08

BOOL __stdcall DbgBpNewSoftware(DEBUGGER* _dbg, DWORD _pid, LPVOID _address, BOOL _oneShot);
BOOL __stdcall DbgBpDelSoftware(DEBUGGER* _dbg, DWORD _pid, LPVOID _address);
BOOL __stdcall DbgBpNewHardware(DEBUGGER* _dbg, DWORD _pid, DWORD _tid, DWORD _debugRegister, LPVOID _address);
BOOL __stdcall DbgBpDelHardware(DEBUGGER* _dbg, DWORD _pid, DWORD _tid, DWORD _debugRegisterMask);

//Miscellaneous
LPVOID    __stdcall DbgFindApi(DEBUGGER* _dbg, DWORD _pid, LPCWSTR _library, LPCSTR _function);
MODULE*   __stdcall DbgModuleForAddress(DEBUGGER* _dbg, DWORD _pid, LPVOID _address);
ULONG_PTR __stdcall DbgStackRead(DEBUGGER* _dbg, DWORD _pid, DWORD _tid, INT _displacementInWordsFromStackPointer);
ULONG_PTR __stdcall DbgStackReadParameter(DEBUGGER* _dbg, DWORD _pid, DWORD _tid, UINT _parameter);
ULONG_PTR __stdcall DbgStackReturnAddress(DEBUGGER* _dbg, DWORD _pid, DWORD _tid);


///////////////////
//PROCESS MONITOR//
///////////////////
typedef VOID(__stdcall *LPFN_PMONNEWPROCESS)(DWORD _parentPid, DWORD _pid, LPCWSTR _applicationName, LPCWSTR _commandLine);

BOOL __stdcall PmStart(LPFN_PMONNEWPROCESS _onNewProcessCallback);
BOOL __stdcall PmStop();









//////////////////
//FUNCTION TYPES//
//////////////////
typedef DWORD (__stdcall *FN_OSVersion)();
typedef DWORD (__stdcall *FN_OSGroup)();
typedef DWORD (__stdcall *FN_OSPlatform)();

typedef DWORD    (__stdcall *FN_ProcessPID)     (PROCESS* _process);
typedef HANDLE   (__stdcall *FN_ProcessHandle)  (PROCESS* _process);
typedef DWORD    (__stdcall *FN_ProcessPlatform)(PROCESS* _process);
typedef LPCWSTR  (__stdcall *FN_ProcessName)    (PROCESS* _process);
typedef LPVOID   (__stdcall *FN_ProcessPEB)     (PROCESS* _process);

typedef PROCESS* (__stdcall *FN_ThreadProcess)(THREAD* _thread);
typedef DWORD    (__stdcall *FN_ThreadTID)    (THREAD* _thread);
typedef HANDLE   (__stdcall *FN_ThreadHandle) (THREAD* _thread);
typedef LPVOID   (__stdcall *FN_ThreadTEB)    (THREAD* _thread);

typedef PROCESS*  (__stdcall *FN_ModuleProcess)        (MODULE* _module);
typedef LPVOID    (__stdcall *FN_ModuleBase)           (MODULE* _module);
typedef HMODULE   (__stdcall *FN_ModuleHandle)         (MODULE* _module);
typedef DWORD     (__stdcall *FN_ModuleSize)           (MODULE* _module);
typedef DWORD     (__stdcall *FN_ModulePlatform)       (MODULE* _module);
typedef LPCWSTR   (__stdcall *FN_ModuleName)           (MODULE* _module);
typedef FUNCTION* (__stdcall *FN_ModuleExportsFunction)(MODULE* _module, UINT _index);
typedef DWORD     (__stdcall *FN_ModuleExportsSize)    (MODULE* _module);

typedef MODULE* (__stdcall *FN_FunctionModule) (FUNCTION* _function);
typedef LPVOID  (__stdcall *FN_FunctionAddress)(FUNCTION* _function);
typedef LPCSTR  (__stdcall *FN_FunctionName)   (FUNCTION* _function);

typedef DEBUGGER* (__stdcall *FN_DbgNew)();
typedef VOID      (__stdcall *FN_DbgDelete)(DEBUGGER* _dbg);
typedef DWORD     (__stdcall *FN_DbgAttach)(DEBUGGER* _dbg, DWORD _pid, INSPECTOR* _inspector);
typedef VOID      (__stdcall *FN_DbgDetach)(DEBUGGER* _dbg, BOOL _killOnExit);
typedef DWORD     (__stdcall *FN_DbgOriginalPid)(DEBUGGER* _dbg);

typedef PROCESS*  (__stdcall *FN_DbgSsGetProcess)     (DEBUGGER* _dbg, DWORD _pid);
typedef THREAD*   (__stdcall *FN_DbgSsGetThread)      (DEBUGGER* _dbg, DWORD _pid, DWORD _tid);
typedef MODULE*   (__stdcall *FN_DbgSsGetModule)      (DEBUGGER* _dbg, DWORD _pid, LPVOID _base);
typedef DWORD     (__stdcall *FN_DbgSsProcessesNumber)(DEBUGGER* _dbg);
typedef PROCESS*  (__stdcall *FN_DbgSsAccessProcess)  (DEBUGGER* _dbg, UINT _index);
typedef DWORD     (__stdcall *FN_DbgSsThreadsNumber)  (DEBUGGER* _dbg, DWORD _pid);
typedef THREAD*   (__stdcall *FN_DbgSsAccessThread)   (DEBUGGER* _dbg, DWORD _pid, UINT _index);
typedef DWORD     (__stdcall *FN_DbgSsModulesNumber)  (DEBUGGER* _dbg, DWORD _pid);
typedef MODULE*   (__stdcall *FN_DbgSsAccessModule)   (DEBUGGER* _dbg, DWORD _pid, UINT _index);

typedef BOOL (__stdcall *FN_DbgBpNewSoftware)(DEBUGGER* _dbg, DWORD _pid, LPVOID _address, BOOL _oneShot);
typedef BOOL (__stdcall *FN_DbgBpDelSoftware)(DEBUGGER* _dbg, DWORD _pid, LPVOID _address);
typedef BOOL (__stdcall *FN_DbgBpNewHardware)(DEBUGGER* _dbg, DWORD _pid, DWORD _tid, DWORD _debugRegister, LPVOID _address);
typedef BOOL (__stdcall *FN_DbgBpDelHardware)(DEBUGGER* _dbg, DWORD _pid, DWORD _tid, DWORD _debugRegisterMask);

typedef LPVOID    (__stdcall *FN_DbgFindApi)           (DEBUGGER* _dbg, DWORD _pid, LPCWSTR _library, LPCSTR _function);
typedef MODULE*   (__stdcall *FN_DbgModuleForAddress)  (DEBUGGER* _dbg, DWORD _pid, LPVOID _address);
typedef ULONG_PTR (__stdcall *FN_DbgStackRead)         (DEBUGGER* _dbg, DWORD _pid, DWORD _tid, INT _displacementInWordsFromStackPointer);
typedef ULONG_PTR (__stdcall *FN_DbgStackReadParameter)(DEBUGGER* _dbg, DWORD _pid, DWORD _tid, UINT _parameter);
typedef ULONG_PTR (__stdcall *FN_DbgStackReturnAddress)(DEBUGGER* _dbg, DWORD _pid, DWORD _tid);

typedef BOOL (__stdcall *FN_PmStart)(LPFN_PMONNEWPROCESS _onNewProcessCallback);
typedef BOOL (__stdcall *FN_PmStop) ();

#endif
