#include <iostream>
#include <Adder.h>

int main() {
	Adder adder = Adder(2, 3);
	std::cout << adder.add() << std::endl;
	return 0;
}
