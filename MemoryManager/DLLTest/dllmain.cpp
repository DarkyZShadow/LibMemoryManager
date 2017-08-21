#include <vector>
#include <iostream>
#include "Hook.hpp"

#pragma region New Functions

void __declspec(naked)			newSend()
{
	std::cout << "New Send !" << std::endl;
	__asm RET;
}

void __declspec(naked)			newRecv()
{
	std::cout << "New Recv !" << std::endl;
	__asm RET;
}

#pragma endregion

std::vector<Hook*>				hooks;
void							WinApiHook()
{
	/* Search funtions from 'wsock32.dll' */
	const HMODULE				hWsock32 = GetModuleHandleA("wsock32.dll");
	const FARPROC				pSend = GetProcAddress(hWsock32, "send");
	const FARPROC				pRecv = GetProcAddress(hWsock32, "recv");
	const FARPROC				pSendTo = GetProcAddress(hWsock32, "sendto");
	const FARPROC				pRecvFrom = GetProcAddress(hWsock32, "recvfrom");

	/* Search funtions from 'ws2_32.dll' */
	const HMODULE				hWs2_32 = GetModuleHandleA("ws2_32.dll");
	const FARPROC				pSend2 = GetProcAddress(hWs2_32, "send");
	const FARPROC				pRecv2 = GetProcAddress(hWs2_32, "recv");
	const FARPROC				pSendTo2 = GetProcAddress(hWs2_32, "sendto");
	const FARPROC				pRecvFrom2 = GetProcAddress(hWs2_32, "recvfrom");
	const FARPROC				pWsaSend2 = GetProcAddress(hWs2_32, "WSASend");
	const FARPROC				pWsaRecv2 = GetProcAddress(hWs2_32, "WSARecv");
	const FARPROC				pWsaSendTo2 = GetProcAddress(hWs2_32, "WSASendTo");
	const FARPROC				pWsaRecvFrom2 = GetProcAddress(hWs2_32, "WSARecvFrom");

	/* Detour funtions from 'wsock32.dll' */
	Hook						*hookSend = new Hook(TO_ADDY(pSend), TO_ADDY(&newSend));
	Hook						*hookRecv = new Hook(TO_ADDY(pRecv), TO_ADDY(&newRecv));

	/* Detour funtions from 'ws2_32.dll' */
	Hook						*hookSend2 = new Hook(TO_ADDY(pSend2), TO_ADDY(&newSend));
	Hook						*hookRecv2 = new Hook(TO_ADDY(pRecv2), TO_ADDY(&newRecv));

	/* Print some addresses */
	std::cout << "hWsock32 : 0x" << std::hex << hWsock32 << std::endl;
	std::cout << "hWs2_32 : 0x" << std::hex << hWs2_32 << std::endl;
	std::cout << "Send : 0x" << std::hex << pSend << std::endl;
	std::cout << "Recv : 0x" << std::hex << pRecv << std::endl;
	std::cout << "SendTo : 0x" << std::hex << pSendTo << std::endl;
	std::cout << "RecvFrom : 0x" << std::hex << pRecvFrom << std::endl;
	std::cout << "Send2 : 0x" << std::hex << pSend2 << std::endl;
	std::cout << "Recv2 : 0x" << std::hex << pRecv2 << std::endl;
	std::cout << "SendTo2 : 0x" << std::hex << pSendTo2 << std::endl;
	std::cout << "RecvFrom2 : 0x" << std::hex << pRecvFrom2 << std::endl;
	std::cout << "WSASend2 : 0x" << std::hex << pWsaSend2 << std::endl;
	std::cout << "WSARecv2 : 0x" << std::hex << pWsaRecv2 << std::endl;
	std::cout << "WSASendTo2 : 0x" << std::hex << pWsaSendTo2 << std::endl;
	std::cout << "WSARecvFrom2 : 0x" << std::hex << pWsaRecvFrom2 << std::endl;

	/*  Some checks*/
	if (!hookSend->hook())
		std::cout << "Unable to hook 'send' function" << std::endl;
	if (!hookRecv->hook())
		std::cout << "Unable to hook 'recv' function" << std::endl;
	if (!hookSend2->hook())
		std::cout << "Unable to hook 'send2' function" << std::endl;
	if (!hookRecv2->hook())
		std::cout << "Unable to hook 'recv2' function" << std::endl;

	/* Save hooks */
	hooks.push_back(hookSend);
	hooks.push_back(hookRecv);
	hooks.push_back(hookSend2);
	hooks.push_back(hookRecv2);
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
