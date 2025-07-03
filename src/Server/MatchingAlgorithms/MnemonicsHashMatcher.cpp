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
        if (function_mnemonics_hash != 0) {
            potential_matches[function_mnemonics_hash].primary.push_back(function);
        }
    }
    for (const auto& function : specific_bucket.secondary) {
        long long function_mnemonics_hash = secondary->get_functions()[function].get_mnemonics_hash();
        if (function_mnemonics_hash != 0) {
            potential_matches[function_mnemonics_hash].secondary.push_back(function);
        }
    }

    PotentialMatches lone_functions_bucket;
    for (const auto& it : potential_matches) {
        PotentialMatches mnemonics_hash_matches = it.second;

        if (mnemonics_hash_matches.primary.size() == 1 && mnemonics_hash_matches.secondary.size() == 1) {
            Match match;
            match.address_primary = primary->get_functions()[mnemonics_hash_matches.primary[0]].get_address();
            match.address_secondary = secondary->get_functions()[mnemonics_hash_matches.secondary[0]].get_address();

            const auto& p_func = primary->get_functions()[mnemonics_hash_matches.primary[0]];
            const auto& s_func = secondary->get_functions()[mnemonics_hash_matches.secondary[0]];

            match.similarity = calculate_similarity(p_func, s_func);
            match.confidence = calculate_confidence(p_func, s_func);
            out_matches.push_back(match);
        }
        else if (!mnemonics_hash_matches.primary.empty() && !mnemonics_hash_matches.secondary.empty()) {
            if (mnemonics_hash_matches.primary.size() == mnemonics_hash_matches.secondary.size() &&
                mnemonics_hash_matches.primary.size() <= 3) {
                handle_multiple_mnemonic_matches(primary, secondary, mnemonics_hash_matches, out_matches, it.first);
            } else {
                PotentialMatches new_bucket;
                for (const auto& function : mnemonics_hash_matches.primary) {
                    new_bucket.primary.push_back(function);
                }
                for (const auto& function : mnemonics_hash_matches.secondary) {
                    new_bucket.secondary.push_back(function);
                }
                new_unmatched_groups.push_back(new_bucket);
            }
        } else {
            for (const auto& function : mnemonics_hash_matches.primary) {
                lone_functions_bucket.primary.push_back(function);
            }
            for (const auto& function : mnemonics_hash_matches.secondary) {
                lone_functions_bucket.secondary.push_back(function);
            }
        }
    }
    new_unmatched_groups.push_back(lone_functions_bucket);
}


float MnemonicsHashMatcher::calculate_similarity(const Function& p_func, const Function& s_func) {
    float base_similarity = 0.92f;

    if (p_func.get_function_instruction_count() == s_func.get_function_instruction_count()) {
        base_similarity += 0.05f;
    }

    if (p_func.get_basic_block_count() == s_func.get_basic_block_count()) {
        base_similarity += 0.03f;
    }

    return std::min(1.0f, base_similarity);
}

float MnemonicsHashMatcher::calculate_confidence(const Function& p_func, const Function& s_func) {

    float base_confidence = 0.85f;

    int min_instructions = std::min(p_func.get_function_instruction_count(),
                                   s_func.get_function_instruction_count());

    if (min_instructions >= 20) {
        base_confidence += 0.08f;
    } else if (min_instructions >= 10) {
        base_confidence += 0.05f;
    } else if (min_instructions >= 5) {
        base_confidence += 0.02f;
    }

    std::string p_name = p_func.get_name();
    std::string s_name = s_func.get_name();

    if (!p_name.empty() && !s_name.empty() &&
        p_name.find("sub_") != 0 && s_name.find("sub_") != 0) {
        if (p_name == s_name) {
            base_confidence += 0.05f;
        }
    }

    return std::min(0.95f, base_confidence);
}

void MnemonicsHashMatcher::handle_multiple_mnemonic_matches(
    const std::shared_ptr<BinExportContent>& primary,
    const std::shared_ptr<BinExportContent>& secondary,
    const PotentialMatches& mnemonic_matches,
    std::vector<Match>& out_matches,
    long long mnemonic_hash) {

    std::vector<std::pair<int, int>> best_pairings = find_best_mnemonic_pairings(
        primary, secondary, mnemonic_matches);

    for (const auto& [p_idx, s_idx] : best_pairings) {
        Match match;
        match.address_primary = primary->get_functions()[p_idx].get_address();
        match.address_secondary = secondary->get_functions()[s_idx].get_address();

        const auto& p_func = primary->get_functions()[p_idx];
        const auto& s_func = secondary->get_functions()[s_idx];

        match.similarity = calculate_similarity(p_func, s_func);
        match.confidence = calculate_confidence(p_func, s_func) * 0.9f;
        out_matches.push_back(match);
    }
}

std::vector<std::pair<int, int>> MnemonicsHashMatcher::find_best_mnemonic_pairings(
    const std::shared_ptr<BinExportContent>& primary,
    const std::shared_ptr<BinExportContent>& secondary,
    const PotentialMatches& mnemonic_matches) {

    std::vector<std::pair<int, int>> pairings;
    std::vector<std::tuple<int, int, float>> similarities;

    for (int p_idx : mnemonic_matches.primary) {
        for (int s_idx : mnemonic_matches.secondary) {
            const auto& p_func = primary->get_functions()[p_idx];
            const auto& s_func = secondary->get_functions()[s_idx];

            float structural_sim = calculate_structural_similarity_for_disambiguation(p_func, s_func);
            similarities.emplace_back(p_idx, s_idx, structural_sim);
        }
    }

    std::sort(similarities.begin(), similarities.end(),
             [](const auto& a, const auto& b) { return std::get<2>(a) > std::get<2>(b); });

    std::set<int> used_primary, used_secondary;

    for (const auto& [p_idx, s_idx, sim] : similarities) {
        if (used_primary.count(p_idx) || used_secondary.count(s_idx)) continue;

        pairings.emplace_back(p_idx, s_idx);
        used_primary.insert(p_idx);
        used_secondary.insert(s_idx);
    }

    return pairings;
}

float MnemonicsHashMatcher::calculate_structural_similarity_for_disambiguation(
    const Function& p_func, const Function& s_func) {

    float similarity = 0.0f;

    if (p_func.get_function_instruction_count() == s_func.get_function_instruction_count()) {
        similarity += 0.4f;
    }
    if (p_func.get_basic_block_count() == s_func.get_basic_block_count()) {
        similarity += 0.3f;
    }
    if (p_func.get_loop_count() == s_func.get_loop_count()) {
        similarity += 0.1f;
    }
    if (p_func.get_outgoing_degree() == s_func.get_outgoing_degree()) {
        similarity += 0.1f;
    }
    if (p_func.get_incoming_degree() == s_func.get_incoming_degree()) {
        similarity += 0.1f;
    }

    return similarity;
}