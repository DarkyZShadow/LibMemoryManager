#pragma once
#ifndef __MEMORY_MANAGER_HPP__
#define __MEMORY_MANAGER_HPP__

#include <comdef.h>				/* _bstr_t */
#include <Windows.h>
#include <tlhelp32.h>

class							MemoryManager
{
	private:
		DWORD					_pId;
		HANDLE					_pHandle;
		bool					_isReady;

	public:
		#pragma region Constructors

		MemoryManager(DWORD pId)
		{
			this->_pId = pId;
			_isReady = _openProcess(pId);
		}

		MemoryManager(const char *procName)
		{
			this->_pId = _getPIdFromName(procName);
			_isReady = _openProcess(this->_pId);
		}

		MemoryManager(const char *lpClassName, const char *lpWindowName)
		{
			HWND				hWnd;

			hWnd = FindWindowA(lpClassName, lpWindowName);
			if (!hWnd)
				return;
			GetWindowThreadProcessId(hWnd, &this->_pId);
			_isReady = _openProcess(this->_pId);
		}

		#pragma endregion

		#pragma region Destructor

		~MemoryManager()
		{

		}

		#pragma endregion

		#pragma region Public Functions

		DWORD					getPId()
		{
			return _pId;
		}

		bool					isReady()
		{
			return _isReady;
		}

		#pragma endregion

		#pragma region Read

		char					readInt8(DWORD addy)
		{
			char				result;

			ReadProcessMemory(this->_pHandle, (void*)addy, &result, sizeof(result), nullptr);
			return result;
		}

		byte					readUInt8(DWORD addy)
		{
			byte				result;

			ReadProcessMemory(this->_pHandle, (void*)addy, &result, sizeof(result), nullptr);
			return result;
		}

		#pragma endregion

	private:
		bool					_openProcess(DWORD pId)
		{
			return (_pHandle = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE, false, pId));
		}

		DWORD					_getPIdFromName(const char *procName)
		{
			PROCESSENTRY32		pe32;
			HANDLE				hSnapshot(NULL);

			pe32.dwSize = sizeof(PROCESSENTRY32);
			hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

			if (Process32First(hSnapshot, &pe32))
			{
				while (Process32Next(hSnapshot, &pe32))
				{
					if (strcmp(_bstr_t(pe32.szExeFile), procName) == 0)
						break;
				}
			}

			if (hSnapshot != INVALID_HANDLE_VALUE)
				CloseHandle(hSnapshot);

			return pe32.th32ProcessID;
		}
};

#endif // !__MEMORY_MANAGER_HPP__
