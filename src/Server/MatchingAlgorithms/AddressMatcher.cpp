#include "AddressMatcher.h"

void AddressMatcher::match(
	const std::shared_ptr<BinExportContent>& primary,
	const std::shared_ptr<BinExportContent>& secondary,
	std::vector<Match>& out_matches,
	std::vector<PotentialMatches>& unmatched_groups) const {

	std::vector<PotentialMatches> new_unmatched_groups;
	for (int i = 0; i < unmatched_groups.size(); i++) {
		match_specific_bucket(primary, secondary, out_matches, unmatched_groups, i, new_unmatched_groups);
	}
	for (const auto& bucket : new_unmatched_groups) {
		unmatched_groups.push_back(bucket);
	}
}

void AddressMatcher::match_specific_bucket(
	const std::shared_ptr<BinExportContent>& primary,
	const std::shared_ptr<BinExportContent>& secondary,
	std::vector<Match>& out_matches,
	std::vector<PotentialMatches>& unmatched_groups,
	int index,
	std::vector<PotentialMatches>& new_unmatched_groups) const {

	std::map<uint64_t, PotentialMatches> potential_matches;
	PotentialMatches specific_bucket = unmatched_groups[index];
	unmatched_groups.erase(unmatched_groups.begin() + index);

	for (const auto& function : specific_bucket.primary) {
		uint64_t function_address = primary->get_functions()[function].get_address();
		potential_matches[function_address].primary.push_back(function);
	}
	for (const auto& function : specific_bucket.secondary) {
		uint64_t function_address = secondary->get_functions()[function].get_address();
		potential_matches[function_address].secondary.push_back(function);
	}

	PotentialMatches remaining_bucket;
	for (const auto& it : potential_matches) {
		PotentialMatches structure_matches = it.second;
		if (structure_matches.primary.size() == 1 && structure_matches.secondary.size() == 1) {
			Match match;
			match.address_primary = it.first;
			match.address_secondary = it.first;
			const auto& p_func = primary->get_functions()[structure_matches.primary[0]];
			const auto& s_func = secondary->get_functions()[structure_matches.secondary[0]];
			match.similarity = calculate_similarity(primary, secondary, p_func, s_func, out_matches);
			match.confidence = calculate_confidence(primary, secondary, p_func, s_func, out_matches);
			out_matches.push_back(match);
		} else {
			for (const auto& function : structure_matches.primary) {
				remaining_bucket.primary.push_back(function);
			}
			for (const auto& function : structure_matches.secondary) {
				remaining_bucket.secondary.push_back(function);
			}
		}
	}
	new_unmatched_groups.push_back(remaining_bucket);
}

float AddressMatcher::calculate_similarity(const std::shared_ptr<BinExportContent>& primary,
	const std::shared_ptr<BinExportContent>& secondary,
	const Function &p_func, const Function &s_func,
	const std::vector<Match>& existing_matches) const{
	return 1.0;
}

float AddressMatcher::calculate_confidence(const std::shared_ptr<BinExportContent>& primary,
	const std::shared_ptr<BinExportContent>& secondary,
	const Function &p_func, const Function &s_func,
	const std::vector<Match>& existing_matches) const{
	return 1.0;
}