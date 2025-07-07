#ifndef FUNCTION_H
#define FUNCTION_H

#include <string>

#include "binexport2.pb.h"
#include "MnemonicTable.h"

class Function {
public:
	Function(
		const BinExport2* binexport_raw,
		const BinExport2_CallGraph_Vertex* vertex,
		const BinExport2_FlowGraph* flow_graph,
		MnemonicTable* mnemonic_table,
		const std::vector<std::vector<std::vector<int>>>& call_index_graph_,
		int vertex_index);

	[[nodiscard]] std::string get_hash() const;
	[[nodiscard]] uint64_t get_address() const;
	[[nodiscard]] std::string get_name() const;
	[[nodiscard]] int get_basic_block_count() const;
	[[nodiscard]] int get_function_instruction_count() const;
	[[nodiscard]] std::vector<std::string> get_mnemonics() const;
	[[nodiscard]] long long get_mnemonics_hash() const;
	[[nodiscard]] int get_loop_count() const;
	[[nodiscard]] int get_outgoing_degree() const;
	[[nodiscard]] int get_incoming_degree() const;
	[[nodiscard]] int get_recursive_degree() const;

private:
	static std::string calculate_hash(const BinExport2* binexport_raw, const BinExport2_FlowGraph* flow_graph);
	static uint64_t calculate_address(const BinExport2_CallGraph_Vertex* vertex);
	static std::string calculate_name(const BinExport2_CallGraph_Vertex* vertex);
	static int calculate_basic_block_count(const BinExport2_FlowGraph* flow_graph);
	static int calculate_function_instruction_count(const BinExport2* binexport_raw, const BinExport2_FlowGraph* flow_graph);
	static std::vector<std::string> calculate_mnemonics(const BinExport2* binexport_raw, const BinExport2_FlowGraph* flow_graph);
	long long calculate_mnemonics_hash(MnemonicTable* mnemonic_table);
	static int calculate_loop_count(const BinExport2_FlowGraph* flow_graph);
	static int calculate_outgoing_degree(const std::vector<std::vector<std::vector<int>>>& call_index_graph_, int vertex_index) ;
	static int calculate_ingoing_degree(const std::vector<std::vector<std::vector<int>>>& call_index_graph_, int vertex_index) ;
	static int calculate_recursive_degree(const std::vector<std::vector<std::vector<int>>>& call_index_graph_, int vertex_index) ;

private:
	std::string hash_;
	uint64_t address_;
	std::string name_;
	int basic_block_count_;
	int function_instruction_count_;
	std::vector<std::string> mnemonics_;
	long long mnemonics_hash_;
	int loop_count_;
	int outgoing_degree_;
	int ingoing_degree_;;
	int recursive_degree_;
};

#endif //FUNCTION_H
