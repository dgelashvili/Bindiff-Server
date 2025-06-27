
#include "FuzzyMatcher.h"

void FuzzyMatcher::match(
    const std::shared_ptr<BinExportContent>& primary,
    const std::shared_ptr<BinExportContent>& secondary,
    std::vector<Match>& out_matches,
    std::vector<PotentialMatches>& unmatched_groups) const {

    // This should be the LAST matcher to run
    constexpr float MIN_SIMILARITY = 0.7f;

    PotentialMatches merged_unmatched;
    for (const auto& group : unmatched_groups) {
        merged_unmatched.primary.insert(merged_unmatched.primary.end(),
                                       group.primary.begin(), group.primary.end());
        merged_unmatched.secondary.insert(merged_unmatched.secondary.end(),
                                         group.secondary.begin(), group.secondary.end());
    }

    std::vector<std::tuple<int, int, float>> potential_matches;

    // Calculate similarity for all remaining pairs
    for (int p_idx : merged_unmatched.primary) {
        const auto& primary_func = primary->get_functions()[p_idx];

        for (int s_idx : merged_unmatched.secondary) {
            const auto& secondary_func = secondary->get_functions()[s_idx];

            if (is_potential_match(primary_func, secondary_func)) {
                float similarity = calculate_combined_similarity(primary_func, secondary_func);
                if (similarity >= MIN_SIMILARITY) {
                    potential_matches.emplace_back(p_idx, s_idx, similarity);
                }
            }
        }
    }

    // Sort by similarity (highest first)
    std::sort(potential_matches.begin(), potential_matches.end(),
             [](const auto& a, const auto& b) { return std::get<2>(a) > std::get<2>(b); });

    std::set<int> matched_primary, matched_secondary;

    // Greedily assign best matches
    for (const auto& [p_idx, s_idx, similarity] : potential_matches) {
        if (matched_primary.count(p_idx) || matched_secondary.count(s_idx)) continue;

        Match match;
        match.address_primary = primary->get_functions()[p_idx].get_address();
        match.address_secondary = secondary->get_functions()[s_idx].get_address();
        match.similarity = similarity;
        match.confidence = similarity > 0.9f ? 0.9f : 0.7f;

        out_matches.push_back(match);
        matched_primary.insert(p_idx);
        matched_secondary.insert(s_idx);
    }

    // Update unmatched groups
    PotentialMatches remaining;
    for (int idx : merged_unmatched.primary) {
        if (!matched_primary.count(idx)) {
            remaining.primary.push_back(idx);
        }
    }
    for (int idx : merged_unmatched.secondary) {
        if (!matched_secondary.count(idx)) {
            remaining.secondary.push_back(idx);
        }
    }

    unmatched_groups.clear();
    unmatched_groups.push_back(remaining);
}

float FuzzyMatcher::calculate_combined_similarity(
    const Function& primary_func,
    const Function& secondary_func) {

    // Instruction count similarity (normalized)
    int p_count = primary_func.get_function_instruction_count();
    int s_count = secondary_func.get_function_instruction_count();
    float instr_sim = 1.0f - std::min(1.0f, std::abs(p_count - s_count) / (float)std::max(p_count, s_count));

    // Basic block count similarity
    float bb_sim = (primary_func.get_basic_block_count() == secondary_func.get_basic_block_count()) ? 1.0f : 0.5f;

    // Call degree similarity
    float call_sim = 1.0f;
    if (primary_func.get_outgoing_degree() != secondary_func.get_outgoing_degree()) call_sim *= 0.8f;
    if (primary_func.get_incoming_degree() != secondary_func.get_incoming_degree()) call_sim *= 0.8f;

    // Loop count similarity
    float loop_sim = (primary_func.get_loop_count() == secondary_func.get_loop_count()) ? 1.0f : 0.7f;

    // Weighted combination
    return instr_sim * 0.4f + bb_sim * 0.3f + call_sim * 0.2f + loop_sim * 0.1f;
}

bool FuzzyMatcher::is_potential_match(
    const Function& primary_func,
    const Function& secondary_func,
    float threshold) {

    // Quick filters to avoid expensive similarity calculation
    int p_instr = primary_func.get_function_instruction_count();
    int s_instr = secondary_func.get_function_instruction_count();

    // If instruction counts differ by more than 50%, probably not a match
    if (std::abs(p_instr - s_instr) > std::max(p_instr, s_instr) * 0.5f) {
        return false;
    }

    // If basic block counts differ significantly, probably not a match
    int p_bb = primary_func.get_basic_block_count();
    int s_bb = secondary_func.get_basic_block_count();
    if (std::abs(p_bb - s_bb) > std::max(p_bb, s_bb) * 0.3f) {
        return false;
    }

    return true;
}
