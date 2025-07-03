#include "BasicStructureMatcher.h"

#include <map>

void BasicStructureMatcher::match(
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

void BasicStructureMatcher::match_specific_bucket(
	const std::shared_ptr<BinExportContent>& primary,
	const std::shared_ptr<BinExportContent>& secondary,
	std::vector<Match>& out_matches,
	std::vector<PotentialMatches>& unmatched_groups,
	int index,
	std::vector<PotentialMatches>& new_unmatched_groups) {

	std::map<std::pair<int, int>, PotentialMatches> potential_matches;
	PotentialMatches specific_bucket = unmatched_groups[index];
	unmatched_groups.erase(unmatched_groups.begin() + index);

	for (const auto& function : specific_bucket.primary) {
		std::pair<int, int> p =
			std::make_pair(primary->get_functions()[function].get_basic_block_count(),
				primary->get_functions()[function].get_function_instruction_count());
		potential_matches[p].primary.push_back(function);
	}
	for (const auto& function : specific_bucket.secondary) {
		std::pair<int, int> p =
			std::make_pair(secondary->get_functions()[function].get_basic_block_count(),
				secondary->get_functions()[function].get_function_instruction_count());
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

float BasicStructureMatcher::calculate_similarity(const Function& p_func, const Function& s_func) {
	float similarity = 0.88f;
	if (p_func.get_loop_count() == s_func.get_loop_count()) {
		similarity += 0.06f;
	}
	if (p_func.get_outgoing_degree() == s_func.get_outgoing_degree()) {
		similarity += 0.04f;
	}
	if (p_func.get_incoming_degree() == s_func.get_incoming_degree()) {
		similarity += 0.02f;
	}
	return std::min(1.0f, similarity);
}

float BasicStructureMatcher::calculate_confidence(const Function& p_func, const Function& s_func) {
	float confidence = 0.75f;

	int complexity_score = p_func.get_basic_block_count() + p_func.get_loop_count() * 2;
	if (complexity_score > 15) {
		confidence += 0.15f;
	} else if (complexity_score > 8) {
		confidence += 0.10f;
	} else if (complexity_score > 3) {
		confidence += 0.05f;
	}

	std::string p_name = p_func.get_name();
	std::string s_name = s_func.get_name();
	if (!p_name.empty() && !s_name.empty() &&
		p_name.find("sub_") != 0 && s_name.find("sub_") != 0) {
		if (p_name == s_name) {
			confidence += 0.10f;
		}
		}

	return std::min(0.90f, confidence);
}
