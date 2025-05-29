#include "BinDiffClient.h"

int main() {
	const BinDiffClient client(
		grpc::CreateChannel(
			"localhost:50051",
			grpc::InsecureChannelCredentials()));

	const std::string id = client.Upload("../src/Client/test_binDiff_1.exe.BinExport");
	auto function_names = client.Get(id);
	for (const auto& function_name : function_names) {
		std::cout << function_name << "\n";
	}

	return 0;
}
