#ifndef BINDIFFSERVER_H
#define BINDIFFSERVER_H

#include "bin_diff.grpc.pb.h"
#include "BinDiffCache.h"
#include "BinDiffEngine.h"
#include "Models/MnemonicTable.h"

class BinDiffServer final : public bin_diff::BinDiffServer::Service {
public:
	::grpc::Status Upload(
		grpc::ServerContext *context,
		const bin_diff::UploadRequest *request,
		bin_diff::UploadReply *response) override;

	::grpc::Status Diff(
		grpc::ServerContext *context,
		const bin_diff::DiffRequest *request,
		bin_diff::DiffReply *response) override;

	// This method is temporary and is used for testing
	::grpc::Status Get(
		grpc::ServerContext *context,
		const bin_diff::GetRequest *request,
		bin_diff::GetReply *response) override;

private:
	BinDiffCache bin_diff_cache_;
	BinDiffEngine bin_diff_engine;
	MnemonicTable mnemonic_table_;
};

#endif //BINDIFFSERVER_H
