#include <gtest/gtest.h>

#include "BinDiffClient.h"

TEST(BinDiffIntegrationTest, UploadAndGetFunctions) {
	const BinDiffClient client(grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials()));

	const std::string file_path = "../../test/test_files/test_binDiff_1.exe.BinExport";
	const std::string id = client.Upload(file_path);

	ASSERT_FALSE(id.empty()) << "Nonempty ID should be returned for correct input file.";

	const std::vector<std::string> function_names = client.Get(id);
	ASSERT_FALSE(function_names.empty()) << "Nonempty function_names should be retrieved from valid Get().";
}

TEST(BinDiffIntegrationTest, UploadInvalidFile) {
	const BinDiffClient client(grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials()));

	const std::string file_path = "../../test/test_files/test_no_binexport.cpp";
	const std::string id = client.Upload(file_path);

	ASSERT_TRUE(id.empty()) << "Invalid file should not be parsed.";
}

TEST(BinDiffIntegrationTest, UploadNonExistentFile) {
	const BinDiffClient client(grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials()));

	const std::string file_path = "../../test/test_files/nonexistent.BinExport";
	const std::string id = client.Upload(file_path);

	ASSERT_TRUE(id.empty()) << "Nonexistent file can't be opened.";
}

TEST(BinDiffIntegrationTest, GetWithInvalidID) {
	const BinDiffClient client(grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials()));

	std::vector<std::string> result = client.Get("nonexistent_ID");

	ASSERT_TRUE(result.empty()) << "Get should return nothing for nonexistent ID.";
}
