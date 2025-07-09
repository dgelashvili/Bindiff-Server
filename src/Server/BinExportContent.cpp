#include "BinExportContent.h"

BinExportContent::BinExportContent(const std::string &file_bytes, MnemonicTable* mnemonic_table) {
	if (!binexport_raw_.ParseFromString(file_bytes)) {
		throw std::runtime_error("Failed to parse BinExport file");
	}
	mnemonic_table_ = mnemonic_table;

	fill_flow_graph_address_map();
	fill_call_index_graph();

	for (int index = 0; index < binexport_raw_.call_graph().vertex().size(); index++) {
		const auto& func = binexport_raw_.call_graph().vertex()[index];
		functions_.emplace_back(
			&binexport_raw_,
			&func,
			flow_graph_address_map_[func.address()],
			mnemonic_table,
			call_index_graph_,
			index);
		address_to_name_map_[func.address()] = functions_[functions_.size() - 1].get_name();
	}

	fill_address_to_index_map();
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

const std::vector<int> &BinExportContent::get_caller_neighbours(const int graph_index) const {
	return call_index_graph_[graph_index][1];
}

const std::vector<int> &BinExportContent::get_callee_neighbours(const int graph_index) const {
	return call_index_graph_[graph_index][0];
}

int BinExportContent::get_index_from_address(const uint64_t address) {
	return address_to_index_map_[address];
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

void BinExportContent::fill_call_index_graph() {
	call_index_graph_.resize(
		binexport_raw_.call_graph().vertex_size(), std::vector(3, std::vector<int>()));
	for (auto& edge : binexport_raw_.call_graph().edge()) {
		const int caller_index = edge.source_vertex_index();
		const int callee_index = edge.target_vertex_index();
		if (caller_index != callee_index) {
			call_index_graph_[caller_index][0].push_back(callee_index);
			call_index_graph_[callee_index][1].push_back(caller_index);
		} else {
			call_index_graph_[caller_index][2].push_back(callee_index);
		}
	}
}

void BinExportContent::fill_address_to_index_map() {
	for (int function_index = 0; function_index < functions_.size(); function_index++) {
		address_to_index_map_[functions_[function_index].get_address()] = function_index;
	}
}
