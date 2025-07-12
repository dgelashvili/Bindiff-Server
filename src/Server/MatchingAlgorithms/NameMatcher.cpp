#include "NameMatcher.h"
#include "ContentSimilarityCalculator.h"
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
	std::vector<PotentialMatches>& new_unmatched_groups) const {

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

	PotentialMatches lone_functions_bucket;
	for (const auto& it : potential_matches) {
		PotentialMatches name_matches = it.second;
		if (name_matches.primary.size() == 1 && name_matches.secondary.size() == 1) {
			Match match;
			match.address_primary = primary->get_functions()[name_matches.primary[0]].get_address();
			match.address_secondary = secondary->get_functions()[name_matches.secondary[0]].get_address();
			const auto& p_func = primary->get_functions()[name_matches.primary[0]];
			const auto& s_func = secondary->get_functions()[name_matches.secondary[0]];
			match.similarity = calculate_similarity(primary, secondary, p_func, s_func, out_matches);
			match.confidence = calculate_confidence(primary, secondary, p_func, s_func, out_matches);
			float content_similarity = ContentSimilarityCalculator::calculate_content_similarity(p_func, s_func);
			float name_confidence = ContentSimilarityCalculator::calculate_name_based_confidence(p_func, s_func, content_similarity);
			match.similarity = content_similarity;
			match.confidence = name_confidence;

			out_matches.push_back(match);
		} else if (!name_matches.primary.empty() && !name_matches.secondary.empty()) {
			PotentialMatches new_bucket;
			for (const auto& function : name_matches.primary) {
				new_bucket.primary.push_back(function);
			}
			for (const auto& function : name_matches.secondary) {
				new_bucket.secondary.push_back(function);
			}
			new_unmatched_groups.push_back(new_bucket);
		} else {
			for (const auto& function : name_matches.primary) {
				lone_functions_bucket.primary.push_back(function);
			}
			for (const auto& function : name_matches.secondary) {
				lone_functions_bucket.secondary.push_back(function);
			}
		}
	}
	new_unmatched_groups.push_back(lone_functions_bucket);
}

float NameMatcher::calculate_similarity(const std::shared_ptr<BinExportContent>& primary,
	const std::shared_ptr<BinExportContent>& secondary,
	const Function &p_func, const Function &s_func,
	const std::vector<Match>& existing_matches) const{
	return 1.0;
}

float NameMatcher::calculate_confidence(const std::shared_ptr<BinExportContent>& primary,
	const std::shared_ptr<BinExportContent>& secondary,
	const Function &p_func, const Function &s_func,
	const std::vector<Match>& existing_matches) const{
	return 1.0;
}
