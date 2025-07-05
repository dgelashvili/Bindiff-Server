#include "MnemonicsHashMatcher.h"

void MnemonicsHashMatcher::match(
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

void MnemonicsHashMatcher::match_specific_bucket(
	const std::shared_ptr<BinExportContent>& primary,
	const std::shared_ptr<BinExportContent>& secondary,
	std::vector<Match>& out_matches,
	std::vector<PotentialMatches>& unmatched_groups,
	const int index,
	std::vector<PotentialMatches>& new_unmatched_groups) {

	std::unordered_map<long long, PotentialMatches> potential_matches;
	PotentialMatches specific_bucket = unmatched_groups[index];
	unmatched_groups.erase(unmatched_groups.begin() + index);

	for (const auto& function : specific_bucket.primary) {
		long long function_mnemonics_hash = primary->get_functions()[function].get_mnemonics_hash();
		potential_matches[function_mnemonics_hash].primary.push_back(function);
	}
	for (const auto& function : specific_bucket.secondary) {
		long long function_mnemonics_hash = secondary->get_functions()[function].get_mnemonics_hash();
		potential_matches[function_mnemonics_hash].secondary.push_back(function);
	}

	PotentialMatches remaining_bucket;
	for (const auto& it : potential_matches) {
		PotentialMatches mnemonics_hash_matches = it.second;
		if (mnemonics_hash_matches.primary.size() == 1 && mnemonics_hash_matches.secondary.size() == 1) {
			Match match;
			match.address_primary = primary->get_functions()[mnemonics_hash_matches.primary[0]].get_address();
			match.address_secondary = secondary->get_functions()[mnemonics_hash_matches.secondary[0]].get_address();
			match.similarity = 1.0;
			match.confidence = 1.0;
			out_matches.push_back(match);
		} else {
			for (const auto& function : mnemonics_hash_matches.primary) {
				remaining_bucket.primary.push_back(function);
			}
			for (const auto& function : mnemonics_hash_matches.secondary) {
				remaining_bucket.secondary.push_back(function);
			}
		}
	}
	new_unmatched_groups.push_back(remaining_bucket);
}
