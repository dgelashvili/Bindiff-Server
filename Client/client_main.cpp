#include <iostream>
#include <fstream>
#include "grpcpp/grpcpp.h"
#include "binexportParser.grpc.pb.h"

class BinexportParserClient {
private:
	std::unique_ptr<binexportParser::Parser::Stub> stub_;
public:
	explicit BinexportParserClient(const std::shared_ptr<grpc::Channel>& channel): stub_(binexportParser::Parser::NewStub(channel)) {};

	void Parse() const {
		grpc::ClientContext context;

		std::ifstream file("../Client/test_binDiff_1.exe.BinExport", std::ios::binary);
		std::string file_data((std::istreambuf_iterator<char>(file)),
							  std::istreambuf_iterator<char>());

		binexportParser::ParseRequest request;
		binexportParser::ParseReply reply;
		request.set_content(file_data);

		if (const grpc::Status status = stub_->Parse(&context, request, &reply); status.ok()) {
			for (const auto& elem : reply.names()) {
				std::cout << elem << std::endl;
			}
		} else {
			std::cout << status.error_code() << ": " << status.error_message() << std::endl;
		}
	}
};

int main() {
	const BinexportParserClient client(grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials()));
	client.Parse();
	return 0;
}