#include "MemoryManager.hpp"
#include <iostream>


int				main(int argc, char **argv)
{
	MemoryManager mm1(5572);
	MemoryManager mm2("NostaleX.dat");
	MemoryManager mm3(NULL, "NosTale");

	std::cout << mm1.getPId() << "\t" << mm2.getPId() << "\t" << mm3.getPId() << std::endl;
	std::cout << (mm1.isReady() ? "true" : "false") << "\t" << (mm2.isReady() ? "true" : "false")
			  << "\t" << (mm3.isReady() ? "true" : "false") << std::endl;
	std::cout << mm1.readUInt8(0x08866B98) << "\t" << mm2.readUInt8(0x08866B99) << "\t" << mm3.readUInt8(0x08866B9A) << std::endl;
	system("PAUSE");

	return EXIT_SUCCESS;
}
