#include "CallDegreeMatcher.h"

void CallDegreeMatcher::match(
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

void CallDegreeMatcher::match_specific_bucket(
	const std::shared_ptr<BinExportContent>& primary,
	const std::shared_ptr<BinExportContent>& secondary,
	std::vector<Match>& out_matches,
	std::vector<PotentialMatches>& unmatched_groups,
	int index,
	std::vector<PotentialMatches>& new_unmatched_groups) {

	std::map<std::tuple<int, int, int>, PotentialMatches> potential_matches;
	PotentialMatches specific_bucket = unmatched_groups[index];
	unmatched_groups.erase(unmatched_groups.begin() + index);

	for (const auto& function : specific_bucket.primary) {
		std::tuple<int, int, int> p =
			std::make_tuple(
				primary->get_functions()[function].get_outgoing_degree(),
				primary->get_functions()[function].get_incoming_degree(),
				primary->get_functions()[function].get_recursive_degree());
		potential_matches[p].primary.push_back(function);
	}
	for (const auto& function : specific_bucket.secondary) {
		std::tuple<int, int, int> p =
			std::make_tuple(
				secondary->get_functions()[function].get_outgoing_degree(),
				secondary->get_functions()[function].get_incoming_degree(),
				secondary->get_functions()[function].get_recursive_degree());
		potential_matches[p].secondary.push_back(function);
	}

	PotentialMatches remaining_bucket;
	for (const auto& it : potential_matches) {
		PotentialMatches structure_matches = it.second;
		if (structure_matches.primary.size() == 1 && structure_matches.secondary.size() == 1) {
			Match match;
			match.address_primary = primary->get_functions()[structure_matches.primary[0]].get_address();
			match.address_secondary = secondary->get_functions()[structure_matches.secondary[0]].get_address();
			const auto& p_func = primary->get_functions()[structure_matches.primary[0]];
			const auto& s_func = secondary->get_functions()[structure_matches.secondary[0]];

			match.similarity = calculate_similarity(p_func, s_func);
			match.confidence = calculate_confidence(p_func, s_func);
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

float CallDegreeMatcher::calculate_similarity(const Function& p_func, const Function& s_func) {
	float similarity = 0.88f;
	if (p_func.get_basic_block_count() == s_func.get_basic_block_count()) {
		similarity += 0.08f;
	}
	if (p_func.get_loop_count() == s_func.get_loop_count()) {
		similarity += 0.04f;
	}
	return std::min(1.0f, similarity);
}

float CallDegreeMatcher::calculate_confidence(const Function& p_func, const Function& s_func) {
	float confidence = 0.75f;


	int total_calls = p_func.get_outgoing_degree() + p_func.get_incoming_degree();
	if (total_calls > 15) {
		confidence += 0.15f;
	} else if (total_calls > 8) {
		confidence += 0.10f;
	} else if (total_calls > 3) {
		confidence += 0.05f;
	}

	int recursive_calls = p_func.get_recursive_degree();
	if (recursive_calls > 0) {
		confidence += 0.08f;
	}

	if (total_calls == 0 && recursive_calls == 0) {
		confidence -= 0.10f;
	}

	return std::min(0.90f, confidence);
}