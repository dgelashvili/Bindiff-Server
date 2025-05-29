#include "BinDiffClient.h"
#include <fstream>

BinDiffClient::BinDiffClient(const std::shared_ptr<grpc::Channel> &channel):
	stub_(bin_diff::BinDiffServer::NewStub(channel)) {}

std::string BinDiffClient::Upload(const std::string &file_path) const {
	grpc::ClientContext context;

	std::ifstream file(file_path, std::ios::binary);
	if (!file || !file.is_open()) {
		std::cerr << "File does not exist or failed to open: " << file_path << std::endl;
		return "";
	}
	std::string file_data((std::istreambuf_iterator<char>(file)),
						  std::istreambuf_iterator<char>());

	bin_diff::UploadRequest request;
	bin_diff::UploadReply reply;
	request.set_content(file_data);

	if (const grpc::Status status = stub_->Upload(&context, request, &reply); status.ok()) {
		return reply.id();
	} else {
		std::cerr << status.error_code() << ": " << status.error_message() << std::endl;
		return "";
	}
}

std::vector<std::string> BinDiffClient::Get(const std::string &id) const {
	grpc::ClientContext context;

	bin_diff::GetRequest request;
	bin_diff::GetReply reply;
	request.set_id(id);

	if (const grpc::Status status = stub_->Get(&context, request, &reply); status.ok()) {
		std::vector<std::string> function_names;
		for (const auto& function_name : reply.function_names()) {
			function_names.push_back(function_name);
		}
		return function_names;
	} else {
		std::cerr << status.error_code() << ": " << status.error_message() << std::endl;
		return {};
	}
}
