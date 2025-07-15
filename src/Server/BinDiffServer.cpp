#include "BinDiffServer.h"
#include "sha256Wrapper.h"

grpc::Status BinDiffServer::Upload(
	grpc::ServerContext *context,
	const bin_diff::UploadRequest *request,
	bin_diff::UploadReply *response) {

	std::string id = sha_256(request->content());
	response->set_id(id);
	if (bin_diff_cache_.contains(id)) return grpc::Status::OK;

	try {
		const auto content = std::make_shared<BinExportContent>(request->content(), &mnemonic_table_);
		bin_diff_cache_.add(id, content);
		return grpc::Status::OK;
	} catch (const std::runtime_error& e) {
		return {grpc::StatusCode::ABORTED, e.what()};
	} catch (...) {
		return {grpc::StatusCode::UNKNOWN, "Unknown error"};
	}
}

grpc::Status BinDiffServer::Diff(
	grpc::ServerContext *context,
	const bin_diff::DiffRequest *request,
	bin_diff::DiffReply *response) {

	const std::string& primary_id = request->id_1();
	const std::string& secondary_id = request->id_2();
	try {
		const std::shared_ptr<BinExportContent> primary_content = bin_diff_cache_.get(primary_id);
		const std::shared_ptr<BinExportContent> secondary_content = bin_diff_cache_.get(secondary_id);

		std::vector<Match> matches;
		std::vector<std::pair<uint64_t, std::string>> unmatched_primaries;
		std::vector<std::pair<uint64_t, std::string>> unmatched_secondaries;

		if (bin_diff_cache_.contains(primary_id, secondary_id)) {
			const auto tuple = bin_diff_cache_.get(primary_id, secondary_id);
			std::tie(matches, unmatched_primaries, unmatched_secondaries) = tuple;
		} else {
			matches = bin_diff_engine.match(primary_content, secondary_content);
			unmatched_primaries = bin_diff_engine.get_unmatched_primaries();
			unmatched_secondaries = bin_diff_engine.get_unmatched_secondaries();
			const auto tuple = std::make_tuple(matches, unmatched_primaries, unmatched_secondaries);
			bin_diff_cache_.add(primary_id, secondary_id, tuple);
		}

		for (const auto& match : matches) {
			auto* new_match = response->add_matches();

			new_match->set_address_primary(match.address_primary);
			new_match->set_address_secondary(match.address_secondary);
			new_match->set_name_primary(primary_content->get_address_to_name_map()[match.address_primary]);
			new_match->set_name_secondary(secondary_content->get_address_to_name_map()[match.address_secondary]);
			new_match->set_similarity(match.similarity);
			new_match->set_confidence(match.confidence);
		}

		for (const auto& p : unmatched_primaries) {
			auto* new_unmatched_func = response->add_unmatched_primary();

			new_unmatched_func->set_address(p.first);
			new_unmatched_func->set_name(p.second);
		}

		for (const auto& p : unmatched_secondaries) {
			auto* new_unmatched_func = response->add_unmatched_secondary();

			new_unmatched_func->set_address(p.first);
			new_unmatched_func->set_name(p.second);
		}

		return grpc::Status::OK;
	} catch (const std::runtime_error& e) {
		return {grpc::StatusCode::NOT_FOUND, e.what()};
	} catch (...) {
		return {grpc::StatusCode::UNKNOWN, "Unknown error"};
	}
}

grpc::Status BinDiffServer::Get(
	grpc::ServerContext *context,
	const bin_diff::GetRequest *request,
	bin_diff::GetReply *response) {

	const std::string& id = request->id();
	try {
		std::shared_ptr<BinExportContent> bin_export_content = bin_diff_cache_.get(id);
		for (const auto& function : bin_export_content->get_functions()) {
			auto* function_info = response->add_functions();
			function_info->set_address(function.get_address());
			function_info->set_name(function.get_name());
		}
		return grpc::Status::OK;
	} catch (const std::runtime_error& e) {
		return {grpc::StatusCode::NOT_FOUND, e.what()};
	} catch (...) {
		return {grpc::StatusCode::UNKNOWN, "Unknown error"};
	}
}
