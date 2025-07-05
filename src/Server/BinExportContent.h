#ifndef BINDIFFCONTENT_H
#define BINDIFFCONTENT_H

#include <string>
#include <vector>

#include "binexport2.pb.h"

class BinExportContent {
public:
	explicit BinExportContent(const std::string& file_bytes);

	const BinExport2& get_raw();
	const std::vector<std::string>& get_function_names() const;
	const std::vector<uint64_t>& get_function_addresses() const;
	const std::vector<int>& get_function_block_counts() const;
	const std::vector<int>& get_function_instruction_counts() const;
	std::unordered_map<uint64_t, std::string>& get_address_to_name_map();

private:
	void fill_flow_graph_address_map();
private:
	BinExport2 binexport_raw_;
	std::unordered_map<uint64_t, const BinExport2_FlowGraph*> flow_graph_address_map_;

	std::vector<std::string> function_names_;
	std::vector<uint64_t> function_addresses_;
	std::vector<int> function_block_counts_;
	std::vector<int> function_instruction_counts_;
	std::unordered_map<uint64_t, std::string> address_to_name_map_;
};

#endif //BINDIFFCONTENT_H
