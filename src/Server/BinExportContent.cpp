#include "BinExportContent.h"

BinExportContent::BinExportContent(const std::string &file_bytes) {
	if (!binexport_raw_.ParseFromString(file_bytes)) {
		throw std::runtime_error("Failed to parse BinExport file");
	}

	fill_flow_graph_address_map();

	for (const auto& func : binexport_raw_.call_graph().vertex()) {
		if (!func.demangled_name().empty()) {
			function_names_.push_back(func.demangled_name());
		} else if (!func.mangled_name().empty()) {
			function_names_.push_back(func.mangled_name());
		} else {
			function_names_.push_back("");
		}
		function_addresses_.push_back(func.address());
		address_to_name_map_[func.address()] = function_names_[function_names_.size() - 1];

		if (flow_graph_address_map_.count(func.address())) {
			const auto& flow_graph = flow_graph_address_map_[func.address()];
			function_block_counts_.push_back(flow_graph->basic_block_index_size());

			int instruction_count = 0;
			for (const auto& block_index : flow_graph->basic_block_index()) {
				const auto& block = binexport_raw_.basic_block()[block_index];

				for (const auto& range : block.instruction_index()) {
					if (!range.has_begin_index()) continue;
					const int begin = range.begin_index();
					const int end = range.has_end_index() ? range.end_index() : begin + 1;
					instruction_count += (end - begin);
				}
			}
			function_instruction_counts_.push_back(instruction_count);
		} else {
			function_block_counts_.push_back(0);
			function_instruction_counts_.push_back(0);
		}
	}

	for (int i = 0; i < function_addresses_.size(); i++) {
		std::cout << function_names_[i] << " "
			<< function_block_counts_[i] << " "
			<< function_instruction_counts_[i] << std::endl;
	}
}

const BinExport2 &BinExportContent::get_raw() {
	return binexport_raw_;
}

const std::vector<std::string>& BinExportContent::get_function_names() const {
	return function_names_;
}

const std::vector<std::uint64_t>& BinExportContent::get_function_addresses() const {
	return function_addresses_;
}

const std::vector<int>& BinExportContent::get_function_block_counts() const {
	return function_block_counts_;
}

const std::vector<int>& BinExportContent::get_function_instruction_counts() const {
	return function_instruction_counts_;
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
