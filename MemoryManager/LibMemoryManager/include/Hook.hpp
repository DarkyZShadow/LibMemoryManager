#pragma once
#ifndef __LMM_HOOK_HPP__
#define __LMM_HOOK_HPP__

#include <vector>
#include <Windows.h>

typedef DWORD						address_t;
typedef std::vector<address_t>		address_list_t;

#define TO_ADDY(addy)				reinterpret_cast<address_t>(addy)
#define TO_PADDY(addy)				reinterpret_cast<address_t*>(addy)

class								Hook
{
	private:
		bool						isHooked;
		DWORD						trampOldProtect;
		size_t						hookSize;
		address_t					origFunction;
		address_t					newFunction;
		byte						*trampoline;
		byte						*patch;

	public:
		Hook(address_t origFunction, address_t newFunction, size_t hookSize = 5)
		{
			if (isAlreadyHooked(origFunction))
			{
				this->isHooked = false;
				this->hookSize = 0;
				return;
			}

			this->origFunction = origFunction;
			this->newFunction = newFunction;
			this->hookSize = hookSize;
			this->isHooked = false;
			this->trampoline = new byte[hookSize + 14] /* PUSHAD + PUSHFD + CALL newFunction + POPFD + POPAD + old_bytes + JMP size */;
			this->patch = new byte[5] { 0xE9, 0x00, 0x00, 0x00, 0x00 };

			this->trampoline[0] = 0x60; /* PUSHAD opcode */
			this->trampoline[1] = 0x9C; /* PUSHFD opcode */
			/* 8B6C24 10        MOV EBP,DWORD PTR SS:[ESP+10] */
			this->trampoline[2] = 0x8B;
			this->trampoline[3] = 0x6C;
			this->trampoline[4] = 0x24;
			this->trampoline[5] = 0x10;
			/* 83ED 04        	SUB EBP, 4 */
			this->trampoline[6] = 0x83;
			this->trampoline[7] = 0xED;
			this->trampoline[8] = 0x04;
			this->trampoline[9] = 0xE8; /* CALL opcode */
			this->trampoline[14] = 0x9D; /* POPFD opcode */
			this->trampoline[15] = 0x61; /* POPAD opcode */
			this->trampoline[hookSize + 16] = 0xE9; /* JMP opcode */
			*TO_PADDY(&this->trampoline[10]) = newFunction - TO_ADDY(this->trampoline) - 14; /* Call new function */
			*TO_PADDY(&this->trampoline[hookSize + 17]) = origFunction - TO_ADDY(this->trampoline) - 21; /* JMP return to origFunction */
			*TO_PADDY(&this->patch[1]) = TO_ADDY(this->trampoline) - origFunction - 5; /* to - from - 5 (JMP size) */ 
		}

		~Hook()
		{
			this->unhook();
			delete[] patch;
			delete[] trampoline;
		}

		bool						hook()
		{
			DWORD					oldProtect;

			if (this->isHooked || this->hookSize < 5)
				return false;

			/* Modify 'trampoline' protection */
			if (!VirtualProtect(this->trampoline, hookSize + 21, PAGE_EXECUTE_READWRITE, &trampOldProtect))
				return false;

			/* Modify 'origFunction' protection */
			if (!VirtualProtect((LPVOID)this->origFunction, hookSize, PAGE_EXECUTE_READWRITE, &oldProtect))
				return false;

			/* Save old bytes */
			memcpy(this->trampoline + 16, (LPVOID)this->origFunction, this->hookSize);

			/* NOP hook location */
			memset((LPVOID)this->origFunction, 0x90, this->hookSize);

			/* Set hook (size(5) = JMP size) */
			memcpy((LPVOID)this->origFunction, this->patch, 5);

			/* Restore protection */
			if (!VirtualProtect((LPVOID)this->origFunction, hookSize, oldProtect, &oldProtect))
				return false;

			this->isHooked = true;
			return true;
		}

		bool						unhook()
		{
			DWORD					oldProtect;

			if (!this->isHooked)
				return false;

			/* Modify protection */
			if (!VirtualProtect((LPVOID)this->origFunction, hookSize, PAGE_EXECUTE_READWRITE, &oldProtect))
				return false;

			/* Restore old bytes */
			memcpy((void*)this->origFunction, this->trampoline + 16, this->hookSize);

			/* Restore protection */
			if (!VirtualProtect((LPVOID)this->origFunction, hookSize, oldProtect, &oldProtect))
				return false;

			/* Restore 'trampoline' protection */
			if (!VirtualProtect(this->trampoline, hookSize + 21, trampOldProtect, &trampOldProtect))
				return false;

			this->isHooked = false;
			return true;
		}

	private:
		bool						isAlreadyHooked(address_t addy)
		{
			static address_list_t	hooked_addies;

			for (auto hooked_addy : hooked_addies)
				if (hooked_addy == addy)
					return true;
			hooked_addies.push_back(addy);
			return false;
		}
};

#endif
