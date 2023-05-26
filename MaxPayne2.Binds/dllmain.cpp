#include <Windows.h>
#include <cstdint>
#include <thread>
#include <iostream>
#include "IniReader.h"
#include <vector>
#include "Hooking.Patterns.h"


bool Hook(void* hookAddr, void* ourFunc, int len)
{
	if (len < 5)
		return false;

	DWORD protection;

	VirtualProtect(hookAddr, len, PAGE_EXECUTE_READWRITE, &protection);

	DWORD relativeAddress = ((DWORD)ourFunc - (DWORD)hookAddr) - 5;

	*(BYTE*)hookAddr = 0xE9; // jmp
	*(DWORD*)((DWORD)hookAddr + 1) = relativeAddress;

	DWORD temp;
	VirtualProtect(hookAddr, len, protection, &temp);

	return true;
}

int quickSaveKeyCode, quickLoadKeyCode;
DWORD jumpBk;
__declspec(naked) void ourFunc()
{
	__asm {
		cmp eax, quickSaveKeyCode
		jne label1
		mov eax, 0x74

		label1:
			cmp eax, quickLoadKeyCode
			jne label2
			mov eax, 0x78
			jmp label2

		label2 : // can use trampoline hook
			add eax, 0x0FFFFFFE5
			cmp eax, 0x60

			jmp[jumpBk]
	}
}

DWORD WINAPI MainThread(LPVOID param)
{
	static CIniReader iniReader("");

	HMODULE hModule = GetModuleHandle("MaxPayne2.exe");
	DWORD hookAddr = (DWORD)hook::module_pattern(hModule, "83 C0 E5 83 F8 60").get(0).get<DWORD>(0);

	std::string quickSaveKey = iniReader.ReadString("KEYS", "QuickSaveKey", "");
	std::string quickLoadKey = iniReader.ReadString("KEYS", "QuickLoadKey", "");

	std::transform(quickSaveKey.begin(), quickSaveKey.end(), quickSaveKey.begin(), ::toupper);
	std::transform(quickLoadKey.begin(), quickLoadKey.end(), quickLoadKey.begin(), ::toupper);

	std::map<std::string, int> keyMap{
		{"F1", VK_F1},
		{"F2", VK_F2},
		{"F3", VK_F3},
		{"F4", VK_F4},
		{"F5", VK_F5},
		{"F6", VK_F6},
		{"F7", VK_F7},
		{"F8", VK_F8},
		{"F9", VK_F9},
		{"F10", VK_F10},
		{"F11", VK_F11},
		{"F12", VK_F12},
	};

	for (char c = 'A'; c <= 'Z'; ++c)
	{
		std::string key(1, c);
		keyMap[key] = c;
	}

	for (int i = 0; i <= 9; ++i)
	{
		std::string key = std::to_string(i);
		keyMap[key] = i + '0';
	}

	quickSaveKeyCode = keyMap[quickSaveKey];
	quickLoadKeyCode = keyMap[quickLoadKey];

	//HKL myKL = LoadKeyboardLayout("00000409", 0x00000001);

	//quickSaveKeyCode = VkKeyScanEx(quickSaveKey[0], myKL);
	//quickLoadKeyCode = VkKeyScanEx(quickLoadKey[0], myKL);

	int length = 6;

	jumpBk = hookAddr + length;

	Hook((void*)hookAddr, ourFunc, length);

	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
	if (reason == DLL_PROCESS_ATTACH)
	{
		CreateThread(0, 0, MainThread, hModule, 0, 0);
	}
	return TRUE;
}