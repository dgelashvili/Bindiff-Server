#include "Adder.h"

Adder::Adder(const int a, const int b) {
	a_ = a;
	b_ = b;
}

Adder::~Adder() = default;

int Adder::add() const {
	return a_ + b_;
}
