#include <iostream>

int calculateSum(int n) {
	int ans = 0;
	for (int i = 1; i <= n; i++) {
		ans += i;
	}
	return ans;
}

int mySquare(int n) {
	if (n < 0) return -1;
	else if (n == 0) return 5;
	return n * n + 18;
}

void keepUnchanged(int &n, int delta) {
	n = n + delta;
	n = n + 2 * delta;
	n = n + 3 * delta;
	n -= (2 * 3) / 2 * delta;
}

int main() {
	int sum = calculateSum(10);
	int square = mySquare(sum);
}
