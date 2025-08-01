#include "BinDiffClient.h"

int main() {
    const BinDiffClient client(
        grpc::CreateChannel(
            "localhost:50051",
            grpc::InsecureChannelCredentials()));

    const std::string id_1 = client.Upload("../src/Client/Samples/code1.BinExport");
    const std::string id_2 = client.Upload("../src/Client/Samples/code2.BinExport");

    const auto matches = client.Diff(id_1, id_2);
    std::vector<std::pair<std::string, std::string>> suspicious_matches;
    for (const auto&[address_primary, address_secondary, name_primary, name_secondary, similarity, confidence] : matches) {

        std::cout << name_primary << " with address " << address_primary <<
            " got matched with " << name_secondary << " with address " << address_secondary << "\n";
        std::cout << "similarity: " << similarity << " with confidence: " << confidence << "\n";
        std::cout << "\n";

        if (name_primary != name_secondary) {
            suspicious_matches.emplace_back(name_primary, name_secondary);
        }
    }

    std::cout << "Total number of matches: " << matches.size() << std::endl << std::endl;

    std::cout << "Out of them " << suspicious_matches.size() << " are suspicious!" << std::endl << std::endl;
    for (const auto&[name_primary, name_secondary] : suspicious_matches) {
        std::cout << name_primary << " got matched with " << name_secondary << std::endl << std::endl;
    }

    return 0;
}
