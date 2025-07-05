#ifndef BINDIFFCONTENT_H
#define BINDIFFCONTENT_H

#include <string>
#include <vector>

#include "binexport2.pb.h"
#include "Models/Function.h"
#include "Models/MnemonicTable.h"

class BinExportContent {
public:
	explicit BinExportContent(const std::string& file_bytes, MnemonicTable* mnemonic_table);

	const BinExport2& get_raw();
	const std::vector<Function>& get_functions();
	std::unordered_map<uint64_t, std::string>& get_address_to_name_map();

private:
	void fill_flow_graph_address_map();
private:
	BinExport2 binexport_raw_;
	std::unordered_map<uint64_t, const BinExport2_FlowGraph*> flow_graph_address_map_;
	std::vector<Function> functions_;
	std::unordered_map<uint64_t, std::string> address_to_name_map_;
	MnemonicTable *mnemonic_table_;
};

#endif //BINDIFFCONTENT_H
