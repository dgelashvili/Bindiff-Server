#include <iostream>
#include <grpcpp/grpcpp.h>
#include <binexport2.grpc.pb.h>
#include <bindiff.grpc.pb.h>

class HelloWorldServer final : public bindiff::BinExportService::Service {
	grpc::Status UploadBinExport(
		grpc::ServerContext *context,
		const bindiff::BinExportRequest *request,
		bindiff::BinExportResponse *response) override {

		BinExport2::CallGraph call_graph;
		if (!call_graph.ParseFromString(request->binexport_data())) {
			return {grpc::StatusCode::INVALID_ARGUMENT, "Failed to parse BinExport data"};
		}

		std::cout << call_graph.DebugString() << std::endl;
		for (const auto& function : call_graph.vertex()) {
			response->add_function_names(std::to_string(function.address()));
		}

		return grpc::Status::OK;
	}
};

int main() {
	const std::string address = "localhost:50051";
	grpc::ServerBuilder builder;
	builder.AddListeningPort(address, grpc::InsecureServerCredentials());

	HelloWorldServer service;
	builder.RegisterService(&service);

	const std::unique_ptr<grpc::Server> server = builder.BuildAndStart();

	std::cout << "Server listening on " << address << std::endl;

	server->Wait();
	return 0;
}
