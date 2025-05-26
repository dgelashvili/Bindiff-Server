#include <iostream>
#include "grpcpp/grpcpp.h"
#include "binexport2.pb.h"
#include "binexportParser.grpc.pb.h"

class BinexportParserServer final : public binexportParser::Parser::Service {
	::grpc::Status Parse(
		grpc::ServerContext *context,
		const binexportParser::ParseRequest *request,
		binexportParser::ParseReply *response) override {

		BinExport2 binexport;

		if (!binexport.ParseFromString(request->content())) {
			std::cerr << "Failed to parse BinExport file" << std::endl;
			return {grpc::StatusCode::INVALID_ARGUMENT, "Failed to parse BinExport data"};
		}

		for (const auto& function : binexport.call_graph().vertex()) {
			response->add_names(function.mangled_name());
		}

		return ::grpc::Status::OK;
	}
};

int main() {
	const std::string address = "localhost:50051";
	grpc::ServerBuilder builder;
	builder.AddListeningPort(address, grpc::InsecureServerCredentials());

	BinexportParserServer service;
	builder.RegisterService(&service);

	const std::unique_ptr<grpc::Server> server = builder.BuildAndStart();

	std::cout << "Server listening on " << address << std::endl;

	server->Wait();
	return 0;
}
