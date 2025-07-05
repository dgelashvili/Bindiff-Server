#ifndef BINDIFFCLIENT_H
#define BINDIFFCLIENT_H

#include <string>
#include <vector>

#include "grpcpp/grpcpp.h"
#include "bin_diff.grpc.pb.h"
#include "Server/MatchingAlgorithms/MatchingAlgorithm.h"

struct MatchByName{
	std::string name_primary{};
	std::string name_secondary{};
	float similarity{};
	float confidence{};
};

class BinDiffClient {
public:
	explicit BinDiffClient(const std::shared_ptr<grpc::Channel>& channel);

	[[nodiscard]] std::string Upload(const std::string& file_path) const;
	[[nodiscard]] std::vector<std::string> Get(const std::string& id) const;
	[[nodiscard]] std::vector<MatchByName> Diff(const std::string& id_1, const std::string& id_2) const;

private:
	std::unique_ptr<bin_diff::BinDiffServer::Stub> stub_;
};

#endif //BINDIFFCLIENT_H
