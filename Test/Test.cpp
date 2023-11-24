#include "stdafx.h"
#include "scanner.h"
#include <iostream>
#include <string>

int main()
{
	using namespace MemoryScanner;

	Scanner scanner;

	std::cout << "Process: ";
	std::string name;
	std::getline(std::cin, name);
	scanner.setProcess(name.c_str());

	while (true)
	{
		std::cout << "Command: ";
		std::string input;
		std::cin >> input;

		if (input == "scanInt")
		{
			std::cout << "Value: ";
			int val;
			std::cin >> val;

			std::cout << "Scanning..." << std::endl;
			scanner.scanInt(val);
			std::cout << scanner.getAddressCount() << " memory addresses found!" << std::endl;
		}
		else if (input == "scanIntAt")
		{
			std::cout << "Address: ";
			unsigned long long address;
			std::cin >> address;

			std::cout << "Scanning..." << std::endl;
			scanner.scanIntAt(address);
		}
		else if (input == "nextInt")
		{
			std::cout << "Value: ";
			int val;
			std::cin >> val;

			std::cout << "Scanning..." << std::endl;
			scanner.nextInt(val);
			std::cout << scanner.getAddressCount() << " memory addresses found!" << std::endl;
		}
		else if (input == "writeInt")
		{
			std::cout << "Value: ";
			int val;
			std::cin >> val;

			std::cout << "Writing..." << std::endl;
			scanner.writeInt(val);
			std::cout << "Done!" << std::endl;
		}

	}

	return 0;
}

