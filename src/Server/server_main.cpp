#include "grpcpp/grpcpp.h"
#include "BinDiffServer.h"

void BuildAndStartServer(const std::string& server_address) {
	grpc::ServerBuilder builder;
	builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
	builder.SetMaxReceiveMessageSize(16 * 1024 * 1024 * 10);

	BinDiffServer service;
	builder.RegisterService(&service);

	const std::unique_ptr<grpc::Server> server = builder.BuildAndStart();
	std::cout << "Server listening on " << server_address << std::endl;

	server->Wait();
}

int main() {
	const std::string address = "0.0.0.0:50051";

	BuildAndStartServer(address);

	return 0;
}
