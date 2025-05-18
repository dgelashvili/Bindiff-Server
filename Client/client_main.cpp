#include <iostream>
#include <grpcpp/grpcpp.h>
#include <helloworld.grpc.pb.h>

class HelloWorldClient {
	private:
		std::unique_ptr<helloworld::Greeter::Stub> stub_;
	public:
		explicit HelloWorldClient(const std::shared_ptr<grpc::Channel>& channel): stub_(helloworld::Greeter::NewStub(channel)) {};

		void SayHello() const {
			grpc::ClientContext context;
			helloworld::HelloRequest request;
			helloworld::HelloReply reply;
			request.set_name("Takusi");
			if (const grpc::Status status = stub_->SayHello(&context, request, &reply); status.ok()) {
				std::cout << reply.message() << std::endl;
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
