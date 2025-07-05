#include "BinDiffClient.h"

int main() {
	const BinDiffClient client(
		grpc::CreateChannel(
			"localhost:50051",
			grpc::InsecureChannelCredentials()));

	const std::string id_1 = client.Upload("../src/Client/code1.BinExport");
	const std::string id_2 = client.Upload("../src/Client/code2.BinExport");

	const auto matches = client.Diff(id_1, id_2);
	for (const auto&[name_primary, name_secondary, similarity, confidence] : matches) {
		std::cout << name_primary << " got matched with " << name_secondary << "\n";
		std::cout << "similarity: " << similarity << " with confidence: " << confidence << "\n";
		std::cout << "\n";
	}

	return 0;
}
