#include <iostream>
#include <grpcpp/grpcpp.h>
#include <helloworld.grpc.pb.h>

class HelloWorldServer final : public helloworld::Greeter::Service {
	::grpc::Status SayHello(
		grpc::ServerContext *context,
		const helloworld::HelloRequest *request,
		helloworld::HelloReply *response) override {

		response->set_message("Demetre " + request->name());
		return ::grpc::Status::OK;
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
