#include "../inc/dbg.h"

static BOOL IsWindowsVersion(WORD wMajorVersion, WORD wMinorVersion)
{
	OSVERSIONINFOEXW osvi = { sizeof(osvi), 0, 0, 0, 0, {0}, 0, 0 };
	DWORDLONG const dwlConditionMask = VerSetConditionMask(VerSetConditionMask(0, VER_MAJORVERSION, VER_GREATER_EQUAL), VER_MINORVERSION, VER_GREATER_EQUAL);

	osvi.dwMajorVersion = wMajorVersion;
	osvi.dwMinorVersion = wMinorVersion;

	return VerifyVersionInfoW(&osvi, VER_MAJORVERSION | VER_MINORVERSION, dwlConditionMask);
}

#define IsWindows10()    IsWindowsVersion(0x0A, 0x00)
#define IsWindows8Dot1() IsWindowsVersion(0x06, 0x03)

DWORD __stdcall OSVersion()
{
	static DWORD cached = 0;
	if(cached)
		return cached;

	OSVERSIONINFOEXW osvi;
	ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

	if(!GetVersionExW((OSVERSIONINFO*) &osvi))
		return OS_UNKNOWN;

	if(IsWindows10())
		return cached = (osvi.wProductType == VER_NT_WORKSTATION) ? OS_WINDOWS_10 : OS_WINDOWS_SERVER_10;

	if(IsWindows8Dot1())
		return cached = (osvi.wProductType == VER_NT_WORKSTATION) ? OS_WINDOWS_81 : OS_WINDOWS_SERVER_2012_R2;

	if(osvi.dwMajorVersion == 6)
	{
		if(osvi.dwMinorVersion == 2)
		{
			return cached = (osvi.wProductType == VER_NT_WORKSTATION) ? OS_WINDOWS_8 : OS_WINDOWS_SERVER_2012;
		}
		if(osvi.dwMinorVersion == 1)
		{
			return cached = (osvi.wProductType == VER_NT_WORKSTATION) ? OS_WINDOWS_7 : OS_WINDOWS_SERVER_2008_R2;
		}
		if(osvi.dwMinorVersion == 0)
		{
			return cached = (osvi.wProductType == VER_NT_WORKSTATION) ? OS_WINDOWS_VISTA : OS_WINDOWS_SERVER_2008;
		}
	}
	else if(osvi.dwMajorVersion == 5)
	{
		if(osvi.dwMinorVersion == 2)
		{
			if(osvi.wSuiteMask & VER_SUITE_WH_SERVER)
				return cached = OS_WINDOWS_HOME_SERVER;

			if(osvi.wProductType == VER_NT_WORKSTATION && OSPlatform() == 64)
				return cached = OS_WINDOWS_XP64;

			if(GetSystemMetrics(SM_SERVERR2) != 0)
				return cached = OS_WINDOWS_SERVER_2003_R2;

			return cached = OS_WINDOWS_SERVER_2003;
		}
		if(osvi.dwMinorVersion == 1)
		{
			return cached = OS_WINDOWS_XP;
		}
		if(osvi.dwMinorVersion == 0)
		{
			return cached = OS_WINDOWS_2000;
		}	
	}

	return OS_UNKNOWN;
}

DWORD __stdcall OSGroup()
{
	DWORD os = OSVersion();

	if(os == OS_WINDOWS_SERVER_10)
		return OS_WINDOWS_10;

	if(os == OS_WINDOWS_SERVER_2012_R2)
		return OS_WINDOWS_81;

	if(os == OS_WINDOWS_SERVER_2012)
		return OS_WINDOWS_8;

	if(os == OS_WINDOWS_SERVER_2008_R2)
		return OS_WINDOWS_7;

	if(os == OS_WINDOWS_SERVER_2008)
		return OS_WINDOWS_VISTA;

	if(os == OS_WINDOWS_HOME_SERVER
		//|| os == OS_WINDOWS_XP64
		|| os == OS_WINDOWS_SERVER_2003_R2)
		return OS_WINDOWS_SERVER_2003;

	return os;
}

DWORD __stdcall OSPlatform()
{
	static DWORD cached = 0;
	if(cached)
		return cached;

	typedef void (WINAPI *LPFN_GETNATIVESYSTEMINFO)(LPSYSTEM_INFO);
	static LPFN_GETNATIVESYSTEMINFO fnGetNativeSystemInfo = 0;
	
	if(!fnGetNativeSystemInfo)
		fnGetNativeSystemInfo = (LPFN_GETNATIVESYSTEMINFO)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetNativeSystemInfo");
	
	SYSTEM_INFO info;
	ZeroMemory(&info, sizeof(SYSTEM_INFO));

	if(fnGetNativeSystemInfo)
	{
		fnGetNativeSystemInfo(&info);
	}
	else
	{
		GetSystemInfo(&info);
	}

	if(info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
		return cached = 64;
	//else if(info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
	return cached = 32;
}
