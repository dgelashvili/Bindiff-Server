#include "BinExportContent.h"

BinExportContent::BinExportContent(const std::string &file_bytes) {
	if (!binexport_raw_.ParseFromString(file_bytes)) {
		throw std::runtime_error("Failed to parse BinExport file");
	}

	for (const auto& func : binexport_raw_.call_graph().vertex()) {
		function_names_.push_back(func.mangled_name());
		function_addresses_.push_back(func.address());
	}
}

const BinExport2 &BinExportContent::get_raw() {
	return binexport_raw_;
}

std::vector<std::string> BinExportContent::get_function_names() {
	return function_names_;
}

std::vector<std::uint64_t> BinExportContent::get_function_addresses() {
	return function_addresses_;
}
