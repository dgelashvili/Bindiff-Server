#include <iostream>
#include <sha256Wrapper.h>

#include "grpcpp/grpcpp.h"
#include "binexport2.pb.h"
#include "binexportParser.grpc.pb.h"
#include "BinDiffServer.h"

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
			response->add_names(sha_256(function.mangled_name()));
		}

		return ::grpc::Status::OK;
	}
};

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
