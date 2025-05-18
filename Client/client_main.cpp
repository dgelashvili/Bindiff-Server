#include <iostream>
#include <fstream>
#include <grpcpp/grpcpp.h>
#include <bindiff.grpc.pb.h>

class HelloWorldClient {
	private:
		std::unique_ptr<bindiff::BinExportService::Stub> stub_;
	public:
		explicit HelloWorldClient(const std::shared_ptr<grpc::Channel>& channel): stub_(bindiff::BinExportService::NewStub(channel)) {};

		void SayHello() const {
			grpc::ClientContext context;

			std::ifstream file("/home/demetre/Bindiff-Server/Client/test_binDiff_1.exe.BinExport", std::ios::binary);
			std::string file_data((std::istreambuf_iterator<char>(file)),
								  std::istreambuf_iterator<char>());

			bindiff::BinExportRequest request;
			bindiff::BinExportResponse reply;
			request.set_binexport_data(file_data);

			if (const grpc::Status status = stub_->UploadBinExport(&context, request, &reply); status.ok()) {
				for (const auto& elem : reply.function_names()) {
					std::cout << elem << std::endl;
				}
			} else {
				std::cout << status.error_code() << ": " << status.error_message() << std::endl;
			}
		}
};

int main() {
	const HelloWorldClient client(grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials()));
	client.SayHello();
	return 0;
}
