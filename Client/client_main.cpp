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
		std::string file_data((std::istreambuf_iterator<char>(file)),
							  std::istreambuf_iterator<char>());

		bin_diff::UploadRequest request;
		bin_diff::UploadReply reply;
		request.set_content(file_data);

		if (const grpc::Status status = stub_->Upload(&context, request, &reply); status.ok()) {
			return reply.id();
		} else {
			std::cout << status.error_code() << ": " << status.error_message() << std::endl;
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
			std::cout << status.error_code() << ": " << status.error_message() << std::endl;
		}
	}

private:
	std::unique_ptr<bin_diff::BinDiffServer::Stub> stub_;
};

int main() {
	const BinDiffClient client(grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials()));
	const std::string id = client.Upload("../Client/test_binDiff_1.exe.BinExport");
	std::string fake_id = client.Upload("../Client/client_main.cpp");

	std::cout << std::endl;
	client.Get("random_id");
	std::cout << std::endl;

	client.Get(id);
	return 0;
}