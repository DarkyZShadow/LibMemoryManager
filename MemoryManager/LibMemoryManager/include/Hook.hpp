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
			this->trampoline[2] = 0xE8; /* CALL opcode */
			this->trampoline[7] = 0x9D; /* POPFD opcode */
			this->trampoline[8] = 0x61; /* POPAD opcode */
			this->trampoline[hookSize + 9] = 0xE9; /* JMP opcode */
			*TO_PADDY(&this->trampoline[3]) = newFunction - TO_ADDY(this->trampoline) - 7; /* Call new function */
			*TO_PADDY(&this->trampoline[hookSize + 10]) = origFunction - TO_ADDY(this->trampoline) - 14; /* JMP return to origFunction - 9 */
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
			if (!VirtualProtect(this->trampoline, hookSize + 14, PAGE_EXECUTE_READWRITE, &trampOldProtect))
				return false;

			/* Modify 'origFunction' protection */
			if (!VirtualProtect((LPVOID)this->origFunction, hookSize, PAGE_EXECUTE_READWRITE, &oldProtect))
				return false;

			/* Save old bytes */
			memcpy(this->trampoline + 9, (LPVOID)this->origFunction, this->hookSize);

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
			memcpy((void*)this->origFunction, this->trampoline + 9, this->hookSize);

			/* Restore protection */
			if (!VirtualProtect((LPVOID)this->origFunction, hookSize, oldProtect, &oldProtect))
				return false;

			/* Restore 'trampoline' protection */
			if (!VirtualProtect(this->trampoline, hookSize + 14, trampOldProtect, &trampOldProtect))
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
