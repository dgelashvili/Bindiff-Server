#include "NameMatcher.h"

#include <string>
#include <unordered_map>

void NameMatcher::match(
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

void NameMatcher::match_specific_bucket(
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
		std::string function_name = primary->get_functions()[function].get_name();
		potential_matches[function_name].primary.push_back(function);
	}
	for (const auto& function : specific_bucket.secondary) {
		std::string function_name = secondary->get_functions()[function].get_name();
		potential_matches[function_name].secondary.push_back(function);
	}

	PotentialMatches remaining_bucket;
	for (const auto& it : potential_matches) {
		PotentialMatches name_matches = it.second;
		if (name_matches.primary.size() == 1 && name_matches.secondary.size() == 1) {
			Match match;
			match.address_primary = primary->get_functions()[name_matches.primary[0]].get_address();
			match.address_secondary = secondary->get_functions()[name_matches.secondary[0]].get_address();
			match.similarity = 1.0;
			match.confidence = 1.0;
			out_matches.push_back(match);
		} else {
			for (const auto& function : name_matches.primary) {
				remaining_bucket.primary.push_back(function);
			}
			for (const auto& function : name_matches.secondary) {
				remaining_bucket.secondary.push_back(function);
			}
		}
	}
	new_unmatched_groups.push_back(remaining_bucket);
}
