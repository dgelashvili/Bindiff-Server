#include "BinDiffServer.h"
#include "sha256Wrapper.h"

grpc::Status BinDiffServer::Upload(
	grpc::ServerContext *context,
	const bin_diff::UploadRequest *request,
	bin_diff::UploadReply *response) {

	std::string id = sha_256(request->content());
	response->set_id(id);
	if (bin_diff_cache_.contains(id)) return grpc::Status::OK;

	try {
		const auto content = std::make_shared<BinExportContent>(request->content());
		bin_diff_cache_.add(id, content);
		return grpc::Status::OK;
	} catch (const std::runtime_error& e) {
		return {grpc::StatusCode::ABORTED, e.what()};
	} catch (...) {
		return {grpc::StatusCode::UNKNOWN, "Unknown error"};
	}
}

grpc::Status BinDiffServer::Diff(
	grpc::ServerContext *context,
	const bin_diff::DiffRequest *request,
	bin_diff::DiffReply *response) {
	return grpc::Status::OK;
}

grpc::Status BinDiffServer::Get(
	grpc::ServerContext *context,
	const bin_diff::GetRequest *request,
	bin_diff::GetReply *response) {

	const std::string& id = request->id();
	try {
		std::shared_ptr<BinExportContent> bin_export_content = bin_diff_cache_.get(id);
		for (const auto& function_name : bin_export_content->get_function_names()) {
			response->add_function_names(function_name);
		}
		return grpc::Status::OK;
	} catch (const std::runtime_error& e) {
		return {grpc::StatusCode::NOT_FOUND, e.what()};
	} catch (...) {
		return {grpc::StatusCode::UNKNOWN, "Unknown error"};
	}
}
