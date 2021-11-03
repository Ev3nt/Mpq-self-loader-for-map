#include <Windows.h>
#include <string>

#define MakePtr(a, b) (LPVOID)((DWORD)a + (DWORD)b)

HMODULE gameBase = GetModuleHandle("game.dll");
HMODULE stormBase = GetModuleHandle("storm.dll");
typedef BOOL(WINAPI* _SFileOpenFileAsArchive)(DWORD a0, LPCSTR lpArchiveName, DWORD dwPriority, DWORD dwFlags, HANDLE* hMpq);
typedef BOOL(WINAPI* _SFileOpenArchive)(LPCSTR lpArchiveName, DWORD dwPriority, DWORD dwFlags, HANDLE* hMpq);
typedef BOOL(WINAPI* _SFileOpenFileEx)(HANDLE handle, LPCSTR filename, BYTE mode, HANDLE* result);
typedef BOOL(WINAPI* _SFileCloseFile)(HANDLE hFile);
typedef BOOL(WINAPI* _SFileCloseArchive)(HANDLE hArchive);
typedef BOOL(__fastcall* _loadMap)(DWORD);
typedef BOOL(__fastcall* _unloadMap)(DWORD, DWORD, DWORD, DWORD);
_SFileOpenFileAsArchive SFileOpenFileAsArchive;
_SFileOpenArchive SFileOpenArchive;
_SFileOpenFileEx SFileOpenFileEx;
_SFileCloseFile SFileCloseFile;
_SFileCloseArchive SFileCloseArchive;
_loadMap loadMap;
_unloadMap unloadMap;

BOOL __fastcall loadMap_Detour(DWORD a0);
BOOL __fastcall unloadMap_Detour(DWORD a0, DWORD a1, DWORD a2, DWORD a3);

void call(LPVOID address, LPVOID function);

HMODULE module = NULL;
HANDLE mixMpq = NULL;

//----------------------------------------------------------------------------------

BOOL APIENTRY DllMain(HMODULE hModule, UINT ul_reason_for_call, LPVOID lpReserve)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		if (gameBase)
		{
			DisableThreadLibraryCalls(hModule);

			SFileOpenFileAsArchive = (_SFileOpenFileAsArchive)GetProcAddress(stormBase, (LPCSTR)293);
			SFileOpenArchive = (_SFileOpenArchive)GetProcAddress(stormBase, (LPCSTR)266);
			SFileOpenFileEx = (_SFileOpenFileEx)GetProcAddress(stormBase, (LPCSTR)268);
			SFileCloseFile = (_SFileCloseFile)GetProcAddress(stormBase, (LPCSTR)253);
			SFileCloseArchive = (_SFileCloseArchive)GetProcAddress(stormBase, (LPCSTR)252);
			loadMap = (_loadMap)MakePtr(gameBase, 0xe580);
			unloadMap = (_unloadMap)MakePtr(gameBase, 0x3a3ad0);

			module = hModule;

			call(MakePtr(gameBase, 0x5a3b28), loadMap_Detour);
			call(MakePtr(gameBase, 0x594b18), unloadMap_Detour);
		}
		else
		{
			return FALSE;
		}
	}

	return TRUE;
}

//----------------------------------------------------------------------------------

BOOL __fastcall loadMap_Detour(DWORD a0)
{
	BOOL retval = loadMap(a0);

	if (!mixMpq)
	{
		char nameBuffer[MAX_PATH];
		ZeroMemory(nameBuffer, sizeof(nameBuffer));

		GetModuleFileName(module, nameBuffer, sizeof(nameBuffer));
		std::string name = nameBuffer;

		size_t begin = name.size();
		for (; begin > 0 && name[begin - 1] != '\\'; begin--);

		HANDLE hFile;
		if (SFileOpenFileEx(*(HANDLE*)MakePtr(gameBase, 0xaae788), name.substr(begin, name.size() - begin - 4).c_str(), NULL, &hFile))
		{
			SFileOpenArchive(name.c_str(), 9, NULL, &mixMpq);

			SFileCloseFile(hFile);
		}
	}

	return retval;
}

BOOL __fastcall unloadMap_Detour(DWORD a0, DWORD a1, DWORD a2, DWORD a3)
{
	if (mixMpq)
	{
		SFileCloseArchive(mixMpq);

		mixMpq = NULL;
	}

	return unloadMap(a0, a1, a2, a3);
}

void call(LPVOID address, LPVOID function)
{
	DWORD oldProtect;
	VirtualProtect(address, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
	*(BYTE*)address = 0xe8;
	*(DWORD*)((DWORD)address + 1) = (DWORD)function - ((DWORD)address + 5);
	VirtualProtect(address, 5, oldProtect, NULL);
}