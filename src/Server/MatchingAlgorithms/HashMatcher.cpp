#include "HashMatcher.h"

void HashMatcher::match(
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

void HashMatcher::match_specific_bucket(
	const std::shared_ptr<BinExportContent>& primary,
	const std::shared_ptr<BinExportContent>& secondary,
	std::vector<Match>& out_matches,
	std::vector<PotentialMatches>& unmatched_groups,
	const int index,
	std::vector<PotentialMatches>& new_unmatched_groups) {

	std::unordered_map<std::string, PotentialMatches> potential_matches;
	PotentialMatches specific_bucket = unmatched_groups[index];
	unmatched_groups.erase(unmatched_groups.begin() + index);

	for (const auto& function : specific_bucket.primary) {
		std::string function_hash = primary->get_functions()[function].get_hash();
		potential_matches[function_hash].primary.push_back(function);
	}
	for (const auto& function : specific_bucket.secondary) {
		std::string function_hash = secondary->get_functions()[function].get_hash();
		potential_matches[function_hash].secondary.push_back(function);
	}

	PotentialMatches remaining_bucket;
	for (const auto& it : potential_matches) {
		PotentialMatches hash_matches = it.second;
		if (hash_matches.primary.size() == 1 && hash_matches.secondary.size() == 1) {
			Match match;
			match.address_primary = primary->get_functions()[hash_matches.primary[0]].get_address();
			match.address_secondary = secondary->get_functions()[hash_matches.secondary[0]].get_address();
			match.similarity = 1.0;
			match.confidence = 1.0;
			out_matches.push_back(match);
		} else {
			for (const auto& function : hash_matches.primary) {
				remaining_bucket.primary.push_back(function);
			}
			for (const auto& function : hash_matches.secondary) {
				remaining_bucket.secondary.push_back(function);
			}
		}
	}
	new_unmatched_groups.push_back(remaining_bucket);
}
