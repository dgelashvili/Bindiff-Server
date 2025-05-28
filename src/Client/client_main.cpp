#include "BinDiffClient.h"

int main() {
	const BinDiffClient client(
		grpc::CreateChannel(
			"localhost:50051",
			grpc::InsecureChannelCredentials()));

	const std::string id = client.Upload("../src/Client/test_binDiff_1.exe.BinExport");
	std::string fake_id = client.Upload("../src/Client/client_main.cpp");
	std::string nonexistent_id = client.Upload("../src/Client/nonexistent.BinExport");

	auto should_be_empty = client.Get("random_id");
	auto function_names = client.Get(id);
	for (const auto& function_name : function_names) {
		std::cout << function_name << "\n";
	}

	return 0;
}
