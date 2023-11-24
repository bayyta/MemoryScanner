#pragma once
#include <iostream>
#include <vector>
#include <Windows.h>
#include <cstdio>
#include <tlhelp32.h>
#include <comdef.h>
#include <algorithm>

namespace MemoryScanner {

	typedef unsigned char BYTE;

	struct handle_data {
		unsigned long process_id;
		HWND best_handle;
	};

	class Scanner {
	private:
		PROCESSENTRY32 m_Process;
		HANDLE m_ProcessHandle;
		HWND m_WindowHandle;
		std::vector<unsigned long long> memoryAddresses;
	private:
		HWND findMainWindow(unsigned long pID);
		static BOOL isMainWindow(HWND handle);
		static BOOL CALLBACK enum_windows_callback(HWND handle, LPARAM lParam);
		PROCESSENTRY32 getProcess(const char* processName);
		unsigned int getInt32(const BYTE bytes[], int startIndex);
		void getBytes(const unsigned int& value, BYTE buffer[], int startIndex);
	public:
		Scanner();
		Scanner(const char* processName);
		~Scanner();
		void scanInt(const unsigned int& value);
		void scanIntAt(unsigned long long& address);
		void nextInt(const unsigned int& value);
		void writeInt(const unsigned int& value);
		void writeIntAt(const long long &address, const unsigned int& value);
		void setProcess(const char* processName);
		size_t getAddressCount();
	};



}
