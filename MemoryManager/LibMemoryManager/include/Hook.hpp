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
		byte					*origBytes;
		bool						isHooked;
		size_t						hookSize;
		address_t					origFunction;
		address_t					newFunction;
		byte						*patch;

	public:
		Hook(address_t origFunction, address_t newFunction, size_t hookSize)
		{
			if (isAlreadyHooked(origFunction))
			{
				this->hookSize = 0;
				return;
			}

			this->origFunction = origFunction;
			this->newFunction = newFunction;
			this->hookSize = hookSize;
			this->isHooked = false;
			this->origBytes = new byte[hookSize + 5] /* + JMP size */;
			this->patch = new byte[10]{ 0xE8, 0x00, 0x00, 0x00, 0x00, 0xE9, 0x00, 0x00, 0x00, 0x00 };

			this->origBytes[hookSize] = 0xE9; /* JMP opcode */
			*TO_PADDY(&this->origBytes[hookSize + 1]) = origFunction - TO_ADDY(this->origBytes) - 5; /* (to + hookSize) - (from - hookSize) - 5 */
			*TO_PADDY(&this->patch[1]) = newFunction - origFunction - 5; /* to - from - 5 (call size) */
			*TO_PADDY(&this->patch[6]) = TO_ADDY(this->origBytes) - origFunction - 10; /* to - (from - 5) - 5 (JMP size) */
		}

		~Hook()
		{
			this->unhook();
			delete[] patch;
			delete[] origBytes;
		}

		bool					hook()
		{
			DWORD				oldProtect;

			if (this->isHooked || this->hookSize < 10)
				return false;

			/* Modify protection */
			if (!VirtualProtect((LPVOID)this->origFunction, hookSize, PAGE_EXECUTE_READWRITE, &oldProtect))
				return false;

			/* Save old bytes */
			memcpy(this->origBytes, (LPVOID)this->origFunction, this->hookSize);

			/* NOP hook location */
			memset((LPVOID)this->origFunction, 0x90, this->hookSize);

			/* Set hook (size(10) = CALL size + JMP size) */
			memcpy((LPVOID)this->origFunction, this->patch, 10);

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
			memcpy((void*)this->origFunction, this->origBytes, this->hookSize);

			/* Restore protection */
			if (!VirtualProtect((LPVOID)this->origFunction, hookSize, oldProtect, &oldProtect))
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
