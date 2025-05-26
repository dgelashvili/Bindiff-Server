#include "BinDiffServer.h"

#include "sha256Wrapper.h"

grpc::Status BinDiffServer::Upload(
	grpc::ServerContext *context,
	const bin_diff::UploadRequest *request,
	bin_diff::UploadReply *response) {

	std::string id = sha_256(request->content());
	response->set_id(id);
	if (bin_diff_cache_.contains(id)) return grpc::Status::OK;

	const auto content = std::make_shared<BinExportContent>(request->content());
	bin_diff_cache_.add(id, content);
	return grpc::Status::OK;
}

grpc::Status BinDiffServer::Diff(
	grpc::ServerContext *context,
	const bin_diff::DiffRequest *request,
	bin_diff::DiffReply *response) {
	return grpc::Status::OK;
}
