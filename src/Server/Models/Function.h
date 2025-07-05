#ifndef FUNCTION_H
#define FUNCTION_H

#include <string>

#include "binexport2.pb.h"

class Function {
public:
	Function(
		const BinExport2* binexport_raw,
		const BinExport2_CallGraph_Vertex* vertex,
		const BinExport2_FlowGraph* flow_graph);

	[[nodiscard]] uint64_t get_address() const;
	[[nodiscard]] std::string get_name() const;
	[[nodiscard]] int get_basic_block_count() const;
	[[nodiscard]] int get_function_instruction_count() const;

private:
	static uint64_t calculate_address(const BinExport2_CallGraph_Vertex* vertex);
	static std::string calculate_name(const BinExport2_CallGraph_Vertex* vertex);
	static int calculate_basic_block_count(const BinExport2_FlowGraph* flow_graph);
	static int calculate_function_instruction_count(const BinExport2* binexport_raw, const BinExport2_FlowGraph* flow_graph);

private:
	uint64_t address_;
	std::string name_;
	int basic_block_count_;
	int function_instruction_count_;
};

#endif //FUNCTION_H
