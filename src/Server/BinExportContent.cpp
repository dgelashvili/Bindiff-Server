#include "BinExportContent.h"

BinExportContent::BinExportContent(const std::string &file_bytes) {
	if (!binexport_raw_.ParseFromString(file_bytes)) {
		throw std::runtime_error("Failed to parse BinExport file");
	}

	fill_flow_graph_address_map();

	for (const auto& func : binexport_raw_.call_graph().vertex()) {
		functions_.push_back(Function(&binexport_raw_, &func, nullptr));
		address_to_name_map_[func.address()] = functions_[functions_.size() - 1].get_name();
	}
}

const BinExport2 &BinExportContent::get_raw() {
	return binexport_raw_;
}

const std::vector<Function> &BinExportContent::get_functions() {
	return functions_;
}

std::unordered_map<uint64_t, std::string> &BinExportContent::get_address_to_name_map() {
	return address_to_name_map_;
}

void BinExportContent::fill_flow_graph_address_map() {
	for (auto& flow_graph : binexport_raw_.flow_graph()) {
		if (!flow_graph.has_entry_basic_block_index()) continue;

		const int entry_block_index = flow_graph.entry_basic_block_index();

		if (entry_block_index >= binexport_raw_.basic_block_size()) continue;
		const auto& entry_block = binexport_raw_.basic_block()[entry_block_index];

		if (entry_block.instruction_index_size() == 0) continue;
		const auto& first_range = entry_block.instruction_index(0);

		const int instr_index = first_range.begin_index();
		if (instr_index >= binexport_raw_.instruction_size()) continue;

		const auto& instr = binexport_raw_.instruction(instr_index);
		flow_graph_address_map_[instr.address()] = &flow_graph;
	}
}
