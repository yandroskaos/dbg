#ifndef __TOOLS_H__
#define __TOOLS_H__

#include <windows.h>
#include <eh.h>
#include <string>
using namespace std;

//Paths
#define FILENAME(FULL_PATH) FULL_PATH.substr(FULL_PATH.find_last_of(L'\\') + 1)
#define PATH(FULL_PATH) FULL_PATH.substr(0, FULL_PATH.find_last_of(L'\\'))

//States
#define STATE_CHANGE(S, FROM, TO) InterlockedCompareExchange(S, TO, FROM)
#define STATE_GUARD(S, FROM, TO) if(STATE_CHANGE(S, FROM, TO) != FROM) return FALSE

//RAII
template<typename R>
class RAII
{
protected:
	R resource;
public:
	RAII(const R& _resource) : resource(_resource) {}
	virtual ~RAII(){}
};

/**
* @brief RAII class to free memory automatically.
* HGLOBAL = HLOCAL = HANDLE = void*
*/
#define RAII_USE_DELETE			1
#define RAII_USE_DELETE_ARRAY	2
#define RAII_USE_FREE			3
#define RAII_USE_HEAP_FREE		4
#define RAII_USE_LOCAL_FREE		5
#define RAII_USE_GLOBAL_FREE	6

class RAII_MemoryAllocation : public RAII<LPCVOID>
{
private:
	UINT   how;
	HANDLE heap;
public:
	RAII_MemoryAllocation(UINT _how, LPCVOID _memory);
	RAII_MemoryAllocation(HANDLE _heap, LPCVOID _memory);
	virtual ~RAII_MemoryAllocation();
};

#define RAII_FREE_ON_EXIT(HOW, WHAT) RAII_MemoryAllocation var_##WHAT(HOW, WHAT)

/**
* @brief RAII class to synchronize a block of code (Enter/Leave).
*/
class RAII_CriticalSection : public RAII<CRITICAL_SECTION*>
{
public:
	explicit RAII_CriticalSection(CRITICAL_SECTION* _section);
	virtual ~RAII_CriticalSection();
};

#define RAII_SERIALIZE_BLOCK(CS) RAII_CriticalSection var_##CS(&CS)

/**
* @brief RAII class to allow translation from SEH to C++ exceptions.
* This is useful to allow destructors to be run in context where C++ objects
* like strings are allocated.
* The thrown exception is a DWORD with the SEH code
*/
class RAII_SEHTranslator
{
	_se_translator_function newTranslator;
	_se_translator_function oldTranslator;
public:
	 RAII_SEHTranslator();
	~RAII_SEHTranslator();
};

/**
* @brief Macros to ease the use of C++ try/catch blocks with SEH translation enabled. 
*/
#define TRY RAII_SEHTranslator sehTranslator; try
#define CATCH(CODE) catch(DWORD CODE)

#endif
