#include "stdafx.h"
#include "Scanner.h"

namespace MemoryScanner {

	Scanner::Scanner()
	{ }

	Scanner::Scanner(const char* processName)
	{
		m_Process = getProcess(processName);
	}

	Scanner::~Scanner()
	{ }

	void Scanner::scanInt(const unsigned int& value)
	{
		m_ProcessHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, m_Process.th32ProcessID);

		if (m_ProcessHandle == INVALID_HANDLE_VALUE)
		{
			std::cout << "Error: Couldn't open process. Try to run as admin." << std::endl;
			return;
		}

		memoryAddresses.clear();

		SYSTEM_INFO sysInfo = { 0 };
		GetSystemInfo(&sysInfo);

		auto aStart = (long long)sysInfo.lpMinimumApplicationAddress;
		auto aEnd = (long long)sysInfo.lpMaximumApplicationAddress;

		const int SIZE = sizeof(value);

		while (aStart < aEnd)
		{
			MEMORY_BASIC_INFORMATION mbi = { 0 };

			if (!VirtualQueryEx(m_ProcessHandle, (LPCVOID)aStart, &mbi, sizeof(mbi)))
			{
				printf("%s", "Failed VirtualQuery");
				CloseHandle(m_ProcessHandle);
			}

			if (mbi.State == MEM_COMMIT && ((mbi.Protect & PAGE_GUARD) == 0) && ((mbi.Protect == PAGE_NOACCESS) == 0))
			{
				auto isWritable = ((mbi.Protect & PAGE_READWRITE) != 0 || (mbi.Protect & PAGE_WRITECOPY) != 0 || (mbi.Protect & PAGE_EXECUTE_READWRITE) != 0 || (mbi.Protect & PAGE_EXECUTE_WRITECOPY) != 0);

				if (isWritable)
				{
					auto dump = new BYTE[mbi.RegionSize];
					memset(dump, 0x00, mbi.RegionSize);
					ReadProcessMemory(m_ProcessHandle, mbi.BaseAddress, dump, mbi.RegionSize, NULL);
					for (auto i = 0; i < mbi.RegionSize - SIZE; i += SIZE) // skip unaligned memory
					{
						if (free)
						{
							if (unsigned int((dump[i + 3]) << 24 |
								(dump[i + 2]) << 16 |
								(dump[i + 1]) << 8 |
								(dump[i + 0])) == value)
							{
								long long wAddr = (long long)mbi.BaseAddress + i;
								memoryAddresses.push_back(wAddr);
							}
						}
					}

					delete[] dump;
				}
			}

			aStart += mbi.RegionSize;
		}

		CloseHandle(m_ProcessHandle);
	}

	void Scanner::scanIntAt(unsigned long long& address)
	{
		m_ProcessHandle = OpenProcess(PROCESS_VM_READ, false, m_Process.th32ProcessID);

		if (m_ProcessHandle == INVALID_HANDLE_VALUE)
		{
			std::cout << "Error: Couldn't open process. Try to run as admin." << std::endl;
			return;
		}

		memoryAddresses.clear();

		const int valueSize = sizeof(int);
		auto dump = new BYTE[valueSize];

		if (!ReadProcessMemory(m_ProcessHandle, (LPCVOID)address, dump, valueSize, NULL))
		{
			std::cout << "Failed to read memory!" << std::endl;
		}

		std::cout << "Value of " << (LPCVOID)address << ": " <<
			unsigned int((dump[3]) << 24 |
			(dump[2]) << 16 |
			(dump[1]) << 8 |
			(dump[0])) << std::endl;

		memoryAddresses.push_back(address);

		delete[] dump;

		CloseHandle(m_ProcessHandle);
	}

	void Scanner::nextInt(const unsigned int& value)
	{
		m_ProcessHandle = OpenProcess(PROCESS_VM_READ, false, m_Process.th32ProcessID);

		DWORD bytesRead = 0;
		const int valueSize = sizeof(value);
		BYTE buffer[valueSize];
		std::vector<long long> addressesToRemove;

		for (const auto& address : memoryAddresses)
		{
			ReadProcessMemory(m_ProcessHandle, (LPCVOID)address, &buffer, valueSize, NULL);

			if (int((buffer[3]) << 24 |
				(buffer[2]) << 16 |
				(buffer[1]) << 8 |
				(buffer[0])) != value)
			{
				addressesToRemove.push_back(address);
			}
		}

		for (const auto& address : addressesToRemove)
		{
			memoryAddresses.erase(std::remove(memoryAddresses.begin(), memoryAddresses.end(), address), memoryAddresses.end());
		}

		CloseHandle(m_ProcessHandle);
	}

	void Scanner::writeInt(const unsigned int& value)
	{
		m_ProcessHandle = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, false, m_Process.th32ProcessID);

		const int SIZE = sizeof(value);
		BYTE buffer[SIZE];
		getBytes(value, buffer, 0);

		for (const auto& address : memoryAddresses)
		{
			WriteProcessMemory(m_ProcessHandle, (LPVOID)address, &buffer, SIZE, NULL);
		}

		CloseHandle(m_ProcessHandle);
	}

	void Scanner::writeIntAt(const long long &address, const unsigned int& value)
	{
		m_ProcessHandle = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, false, m_Process.th32ProcessID);

		const int SIZE = sizeof(value);
		BYTE buffer[SIZE];
		getBytes(value, buffer, 0);

		WriteProcessMemory(m_ProcessHandle, (LPVOID)address, &buffer, SIZE, NULL);

		CloseHandle(m_ProcessHandle);
	}

	unsigned int Scanner::getInt32(const BYTE bytes[], int startIndex)
	{
		return unsigned int((bytes[startIndex + 3]) << 24 |
			(bytes[startIndex + 2]) << 16 |
			(bytes[startIndex + 1]) << 8 |
			(bytes[startIndex + 0]));
	}

	PROCESSENTRY32 Scanner::getProcess(const char* processName)
	{
		PROCESSENTRY32 entry;
		entry.dwSize = sizeof(PROCESSENTRY32);

		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

		if (Process32First(snapshot, &entry) == TRUE)
		{
			while (Process32Next(snapshot, &entry) == TRUE)
			{
				_bstr_t b(entry.szExeFile);
				if (_stricmp(b, processName) == 0)
				{
					m_WindowHandle = findMainWindow(entry.th32ProcessID);

					const int size = 128;
					wchar_t title[size];
					GetWindowText(m_WindowHandle, title, size);
					std::wstring ws(title);
					std::string str(ws.begin(), ws.end());
					std::cout << str.c_str() << std::endl;

					CloseHandle(snapshot);
					return entry;
				}
			}
		}

		std::cout << "Error: Couldn't find process." << std::endl;
		CloseHandle(snapshot);
		return entry;
	}

	HWND Scanner::findMainWindow(unsigned long pID)
	{
		handle_data data;
		data.process_id = pID;
		data.best_handle = 0;
		EnumWindows(enum_windows_callback, (LPARAM)&data);
		return data.best_handle;
	}

	BOOL Scanner::isMainWindow(HWND handle)
	{
		return GetWindow(handle, GW_OWNER) == (HWND)0 && IsWindowVisible(handle);
	}

	BOOL CALLBACK Scanner::enum_windows_callback(HWND handle, LPARAM lParam)
	{
		handle_data& data = *(handle_data*)lParam;
		unsigned long process_id = 0;
		GetWindowThreadProcessId(handle, &process_id);
		if (data.process_id != process_id || !isMainWindow(handle)) {
			return TRUE;
		}
		data.best_handle = handle;
		return FALSE;
	}

	void Scanner::setProcess(const char* processName)
	{
		m_Process = getProcess(processName);
	}

	size_t Scanner::getAddressCount()
	{
		return memoryAddresses.size();
	}

	void Scanner::getBytes(const unsigned int& value, BYTE buffer[], int startIndex)
	{
		buffer[startIndex] = value;
		buffer[startIndex + 1] = value >> 8;
		buffer[startIndex + 2] = value >> 16;
		buffer[startIndex + 3] = value >> 24;
	}

}