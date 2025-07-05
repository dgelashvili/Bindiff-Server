#include "MnemonicTable.h"

MnemonicTable::MnemonicTable() {
	index = 0;
	std::vector sieve(10000, false);
	for (int i = 2; i < 10000; i++) {
		if (sieve[i]) continue;
		for (int j = i * i; j < 10000; j += i) {
			sieve[j] = true;
		}
		primes.push_back(i);
	}
}

int MnemonicTable::get(const std::string &mnemonic) {
	if (!mnemonic_table.count(mnemonic)) {
		add(mnemonic);
	}
	return mnemonic_table[mnemonic];
}

void MnemonicTable::add(const std::string &mnemonic) {
	mnemonic_table[mnemonic] = primes[index];
	index++;
}
