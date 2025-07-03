#include "LoopStructureMatcher.h"

#include <map>

void LoopStructureMatcher::match(
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

void LoopStructureMatcher::match_specific_bucket(
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
				primary->get_functions()[function].get_loop_count());
		potential_matches[p].primary.push_back(function);
	}
	for (const auto& function : specific_bucket.secondary) {
		std::pair<int, int> p =
			std::make_pair(secondary->get_functions()[function].get_basic_block_count(),
				secondary->get_functions()[function].get_loop_count());
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

float LoopStructureMatcher::calculate_similarity(const Function& p_func, const Function& s_func) {
    float similarity = 0.85f;

    int p_instr = p_func.get_function_instruction_count();
    int s_instr = s_func.get_function_instruction_count();

    if (p_instr == s_instr) {
        similarity += 0.10f;
    } else {
        float diff_ratio = std::abs(p_instr - s_instr) / (float)std::max(p_instr, s_instr);
        if (diff_ratio > 0.3f) {
            similarity -= 0.15f;
        } else if (diff_ratio > 0.1f) {
            similarity -= 0.05f;
        }
    }

    if (p_func.get_outgoing_degree() == s_func.get_outgoing_degree()) {
        similarity += 0.05f;
    }

    return std::max(0.70f, std::min(1.0f, similarity));
}

float LoopStructureMatcher::calculate_confidence(const Function& p_func, const Function& s_func) {
    float confidence = 0.70f;

    int loop_complexity = std::max(p_func.get_loop_count(), s_func.get_loop_count());
    if (loop_complexity > 5) {
        confidence += 0.20f;
    } else if (loop_complexity > 2) {
        confidence += 0.15f;
    } else if (loop_complexity == 1) {
        confidence += 0.08f;
    }

    int total_complexity = p_func.get_basic_block_count() + loop_complexity * 3;
    if (total_complexity > 20) {
        confidence += 0.05f;
    }
    return std::min(0.85f, confidence);
}
