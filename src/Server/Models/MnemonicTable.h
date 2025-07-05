#ifndef MNEMONICTABLE_H
#define MNEMONICTABLE_H

#include <string>
#include <unordered_map>
#include <vector>

class MnemonicTable {
public:
	MnemonicTable();

	int get(const std::string& mnemonic);

private:
	void add(const std::string& mnemonic);

private:
	std::unordered_map<std::string, int> mnemonic_table;
	std::vector<int> primes;
	int index;
};

#endif //MNEMONICTABLE_H
