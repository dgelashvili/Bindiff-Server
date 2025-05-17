#ifndef ADDER_H
#define ADDER_H

class Adder {
public:
	Adder(int a, int b);

	~Adder();

	[[nodiscard]] int add() const;

private:
	int a_;
	int b_;
};

#endif //ADDER_H
