#include "Tools.h"

 RAII_MemoryAllocation::RAII_MemoryAllocation(UINT _how, LPCVOID _memory)
	: RAII(_memory), heap(GetProcessHeap()), how(_how)
{
}

RAII_MemoryAllocation::RAII_MemoryAllocation(HANDLE _heap, LPCVOID _memory)
	: RAII(_memory), heap(_heap), how(RAII_USE_HEAP_FREE)
{
}

RAII_MemoryAllocation::~RAII_MemoryAllocation()
{
	if(resource)
	{
		switch(how)
		{
		case RAII_USE_DELETE       : delete   resource;                   break;
		case RAII_USE_DELETE_ARRAY : delete[] resource;                   break;
		case RAII_USE_FREE         : free((void*)resource);               break;
		case RAII_USE_HEAP_FREE    : HeapFree(heap, 0, (LPVOID)resource); break;
		case RAII_USE_LOCAL_FREE   : LocalFree((HLOCAL)resource);         break;
		case RAII_USE_GLOBAL_FREE  : GlobalFree((HGLOBAL)resource);       break;
		}
	}
}


RAII_CriticalSection::RAII_CriticalSection(CRITICAL_SECTION* _section)
	: RAII(_section)
{
	EnterCriticalSection(resource);
}

RAII_CriticalSection::~RAII_CriticalSection()
{
	LeaveCriticalSection(resource);
}

static void __cdecl SEH_2_CPP(unsigned int _u, EXCEPTION_POINTERS* _ex)
{
	throw _ex->ExceptionRecord->ExceptionCode;
}

RAII_SEHTranslator::RAII_SEHTranslator() : newTranslator(SEH_2_CPP)
{
	oldTranslator = _set_se_translator(newTranslator);
}

RAII_SEHTranslator::~RAII_SEHTranslator()
{
	_set_se_translator(oldTranslator);
}
