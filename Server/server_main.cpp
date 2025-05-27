#include "grpcpp/grpcpp.h"
#include "BinDiffServer.h"

void BuildAndStartServer(const std::string& server_address) {
	grpc::ServerBuilder builder;
	builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());

	BinDiffServer service;
	builder.RegisterService(&service);

	const std::unique_ptr<grpc::Server> server = builder.BuildAndStart();

	server->Wait();
}

int main() {
	const std::string address = "localhost:50051";

	BuildAndStartServer(address);

	return 0;
}
