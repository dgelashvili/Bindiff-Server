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
	const std::vector<int>& get_caller_neighbours(int graph_index) const;
	const std::vector<int>& get_callee_neighbours(int graph_index) const;
	int get_index_from_address(uint64_t address);

private:
	void fill_flow_graph_address_map();
	void fill_call_index_graph();
	void fill_address_to_index_map();
private:
	BinExport2 binexport_raw_;
	std::unordered_map<uint64_t, const BinExport2_FlowGraph*> flow_graph_address_map_;
	std::vector<Function> functions_;
	std::unordered_map<uint64_t, std::string> address_to_name_map_;
	MnemonicTable *mnemonic_table_;
	std::vector<std::vector<std::vector<int>>> call_index_graph_;
	std::unordered_map<uint64_t, int> address_to_index_map_;
};

#endif //BINDIFFCONTENT_H
