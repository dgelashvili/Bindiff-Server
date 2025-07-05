#include "Function.h"

Function::Function(
	const BinExport2* binexport_raw,
	const BinExport2_CallGraph_Vertex* vertex,
	const BinExport2_FlowGraph* flow_graph) :
	address_(calculate_address(vertex)),
	name_(calculate_name(vertex)),
	basic_block_count_(calculate_basic_block_count(flow_graph)),
	function_instruction_count_(calculate_function_instruction_count(binexport_raw, flow_graph))
{
}

uint64_t Function::get_address() const {
	return address_;
}

std::string Function::get_name() const {
	return name_;
}

int Function::get_basic_block_count() const {
	return basic_block_count_;
}

int Function::get_function_instruction_count() const {
	return function_instruction_count_;
}

uint64_t Function::calculate_address(const BinExport2_CallGraph_Vertex *vertex) {
	return vertex->address();
}

std::string Function::calculate_name(const BinExport2_CallGraph_Vertex *vertex) {
	if (!vertex->demangled_name().empty()) {
		return vertex->demangled_name();
	}
	if (!vertex->mangled_name().empty()) {
		return vertex->mangled_name();
	}
	return "";
}

int Function::calculate_basic_block_count(const BinExport2_FlowGraph *flow_graph) {
	if (!flow_graph) {
		return 0;
	}
	return flow_graph->basic_block_index_size();
}

int Function::calculate_function_instruction_count(
	const BinExport2* binexport_raw,
	const BinExport2_FlowGraph *flow_graph) {
	if (!flow_graph) {
		return 0;
	}
	int instruction_count = 0;
	for (const auto& block_index : flow_graph->basic_block_index()) {
		const auto& block = binexport_raw->basic_block()[block_index];

		for (const auto& range : block.instruction_index()) {
			if (!range.has_begin_index()) continue;
			const int begin = range.begin_index();
			const int end = range.has_end_index() ? range.end_index() : begin + 1;
			instruction_count += (end - begin);
		}
	}
	return instruction_count;
}
