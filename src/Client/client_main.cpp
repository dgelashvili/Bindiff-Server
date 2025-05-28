#include <iostream>
#include <fstream>

#include "grpcpp/grpcpp.h"
#include "bin_diff.grpc.pb.h"

class BinDiffClient {
public:
	explicit BinDiffClient(const std::shared_ptr<grpc::Channel>& channel):
		stub_(bin_diff::BinDiffServer::NewStub(channel)) {};

	[[nodiscard]] std::string Upload(const std::string& file_path) const {
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

	void Get(const std::string& id) const {
		grpc::ClientContext context;

		bin_diff::GetRequest request;
		bin_diff::GetReply reply;
		request.set_id(id);

		if (const grpc::Status status = stub_->Get(&context, request, &reply); status.ok()) {
			for (const auto& function_name : reply.function_names()) {
				std::cout << function_name << std::endl;
			}
		} else {
			std::cerr << status.error_code() << ": " << status.error_message() << std::endl;
		}
	}

private:
	std::unique_ptr<bin_diff::BinDiffServer::Stub> stub_;
};

int main() {
	const BinDiffClient client(
		grpc::CreateChannel(
			"localhost:50051",
			grpc::InsecureChannelCredentials()));

	const std::string id = client.Upload("../src/Client/test_binDiff_1.exe.BinExport");
	std::string fake_id = client.Upload("../src/Client/client_main.cpp");
	std::string nonexistent_id = client.Upload("../src/Client/nonexistent.BinExport");

	client.Get("random_id");
	client.Get(id);

	return 0;
}
