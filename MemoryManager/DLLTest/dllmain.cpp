#include <vector>
#include <iostream>
#include "Hook.hpp"

#pragma region New Functions

void __declspec(naked)			newSend()
{
	__asm
	{
		PUSHAD
		PUSHFD
	}

	std::cout << "New Send !" << std::endl;

	__asm
	{
		POPFD
		POPAD
		RET
	}
}

void __declspec(naked)			newRecv()
{
	__asm
	{
		PUSHAD
		PUSHFD
	}

	std::cout << "New Recv !" << std::endl;

	__asm
	{
		POPFD
		POPAD
		RET
	}
}

#pragma endregion

std::vector<Hook*>				hooks;
void							WinApiHook()
{
	const HMODULE				hWs2_32 = GetModuleHandleA("wsock32.dll");
	const FARPROC				pSend = GetProcAddress(hWs2_32, "send");
	const FARPROC				pRecv = GetProcAddress(hWs2_32, "recv");
	const FARPROC				pSendTo = GetProcAddress(hWs2_32, "sendto");
	const FARPROC				pRecvFrom = GetProcAddress(hWs2_32, "recvfrom");
	/*const FARPROC				pWsaSend = GetProcAddress(hWs2_32, "WSASend");
	const FARPROC				pWsaRecv = GetProcAddress(hWs2_32, "WSARecv");
	const FARPROC				pWsaSendTo = GetProcAddress(hWs2_32, "WSASendTo");
	const FARPROC				pWsaRecvFrom = GetProcAddress(hWs2_32, "WSARecvFrom");*/

	Hook						*hookSend = new Hook(TO_ADDY(pSend), TO_ADDY(&newSend), 0x0D);
	Hook						*hookRecv = new Hook(TO_ADDY(pRecv), TO_ADDY(&newRecv), 0x0B);

	std::cout << "Send : 0x" << std::hex << pSend << std::endl;
	std::cout << "Recv : 0x" << std::hex << pRecv << std::endl;
	std::cout << "SendTo : 0x" << std::hex << pSendTo << std::endl;
	std::cout << "RecvFrom : 0x" << std::hex << pRecvFrom << std::endl;
	/*std::cout << "WSASend : 0x" << std::hex << pWsaSend << std::endl;
	std::cout << "WSARecv : 0x" << std::hex << pWsaRecv << std::endl;
	std::cout << "WSASendTo : 0x" << std::hex << pWsaSendTo << std::endl;
	std::cout << "WSARecvFrom : 0x" << std::hex << pWsaRecvFrom << std::endl;*/

	if (!hookSend->hook())
		std::cout << "Unable to hook 'send' function" << std::endl;
	if (!hookRecv->hook())
		std::cout << "Unable to hook 'recv' function" << std::endl;

	hooks.push_back(hookSend);
	hooks.push_back(hookRecv);
}

void						WinApiUnhook()
{
	for (Hook *hook : hooks)
	{
		if (!hook->unhook())
			std::cout << "Unable to Unhook !" << std::endl;
		std::cout << "Unhook done !" << std::endl;
		delete hook;
	}
}

BOOL WINAPI					DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID)
{
	/* Hook WINAPI function */
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(hinstDLL);

		AllocConsole();
		freopen("CONOUT$", "w", stdout);
		freopen("CONOUT$", "w", stderr);

		WinApiHook();
	}
	/* Unhook WINAPI functions */
	else if (fdwReason == DLL_PROCESS_DETACH)
	{
		WinApiUnhook();
	}

	return TRUE;
}
