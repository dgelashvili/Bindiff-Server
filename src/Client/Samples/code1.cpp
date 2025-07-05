#include <iostream>

int calculateNumbers(int n) {
	int ans = 0;
	for (int i = 1; i <= n; i++) {
		ans += i;
	}
	return ans;
}

int mySquare(int n) {
	return n * n;
}

void uselessFunction(int &n, int delta) {
	n = n + 3 * delta;
	n -= (2 * 3) / 2 * delta;
	n = n + delta;
	n = n + 2 * delta;
}

void sneakyFunction(int &n, int m) {
	n = n + 5 * m;
	m += (7 * 4) / 6 * n;
	n = m + m;
	m = n + 2 * m;
	n = n + 1;
	m = m + 8;
	m = m + 9;
	m = m - 1;
	m = m - 2;
}

int main() {
	int sum = calculateNumbers(10);
	int square = mySquare(sum);
	std::cout << square << std::endl;
}
