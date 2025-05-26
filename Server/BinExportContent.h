#ifndef BINDIFFCONTENT_H
#define BINDIFFCONTENT_H

#include <string>
#include <vector>
#include "binexport2.pb.h"

class BinExportContent {
public:
	explicit BinExportContent(const std::string& file_bytes);

	const BinExport2& get_raw();
	std::vector<std::string> get_function_names();
	std::vector<std::uint64_t> get_function_addresses();

private:
	BinExport2 binexport_raw_;
	std::vector<std::string> function_names_;
	std::vector<std::uint64_t> function_addresses_;
};

#endif //BINDIFFCONTENT_H
