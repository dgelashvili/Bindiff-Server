#include <iostream>
#include "Adder.h"

int main() {
	std::cout << "Hello, BinDiff project!\n";
	Adder adder = Adder(2, 3);
	std::cout << adder.add() << std::endl;
	return 0;
}
