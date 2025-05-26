#ifndef BINDIFFSERVER_H
#define BINDIFFSERVER_H

#include "bin_diff.grpc.pb.h"
#include "BinDiffCache.h"

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

private:
	BinDiffCache bin_diff_cache_;
};

#endif //BINDIFFSERVER_H
