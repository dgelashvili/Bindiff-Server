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
        if (!function_hash.empty()) {  // Only consider functions with valid hashes
            potential_matches[function_hash].primary.push_back(function);
        }
    }
    for (const auto& function : specific_bucket.secondary) {
        std::string function_hash = secondary->get_functions()[function].get_hash();
        if (!function_hash.empty()) {
            potential_matches[function_hash].secondary.push_back(function);
        }
    }

    PotentialMatches remaining_bucket;
    for (const auto& it : potential_matches) {
        PotentialMatches hash_matches = it.second;

        if (hash_matches.primary.size() == 1 && hash_matches.secondary.size() == 1) {
            Match match;
            match.address_primary = primary->get_functions()[hash_matches.primary[0]].get_address();
            match.address_secondary = secondary->get_functions()[hash_matches.secondary[0]].get_address();
            match.similarity = 1.0f;
            match.confidence = 1.0f;
            out_matches.push_back(match);
        }
        else if (!hash_matches.primary.empty() && !hash_matches.secondary.empty()) {
            handle_multiple_hash_matches(primary, secondary, hash_matches, out_matches, remaining_bucket, it.first);
        }
        else {
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

void HashMatcher::handle_multiple_hash_matches(
    const std::shared_ptr<BinExportContent>& primary,
    const std::shared_ptr<BinExportContent>& secondary,
    const PotentialMatches& hash_matches,
    std::vector<Match>& out_matches,
    PotentialMatches& remaining_bucket,
    const std::string& hash) {

    if (hash_matches.primary.size() == hash_matches.secondary.size()) {
        std::vector<std::pair<int, int>> best_pairings = find_best_pairings(
            primary, secondary, hash_matches, hash);

        if (best_pairings.size() == hash_matches.primary.size()) {
            for (const auto& [p_idx, s_idx] : best_pairings) {
                Match match;
                match.address_primary = primary->get_functions()[p_idx].get_address();
                match.address_secondary = secondary->get_functions()[s_idx].get_address();
                match.similarity = 1.0f;
                match.confidence = calculate_multiple_match_confidence(
                    primary->get_functions()[p_idx],
                    secondary->get_functions()[s_idx],
                    hash_matches.primary.size());
                out_matches.push_back(match);
            }
            return;
        }
    }

    PotentialMatches hash_specific_bucket;
    for (const auto& function : hash_matches.primary) {
        hash_specific_bucket.primary.push_back(function);
    }
    for (const auto& function : hash_matches.secondary) {
        hash_specific_bucket.secondary.push_back(function);
    }

    for (const auto& function : hash_matches.primary) {
        remaining_bucket.primary.push_back(function);
    }
    for (const auto& function : hash_matches.secondary) {
        remaining_bucket.secondary.push_back(function);
    }
}

std::vector<std::pair<int, int>> HashMatcher::find_best_pairings(
    const std::shared_ptr<BinExportContent>& primary,
    const std::shared_ptr<BinExportContent>& secondary,
    const PotentialMatches& hash_matches,
    const std::string& hash) {

    std::vector<std::pair<int, int>> pairings;

    if (hash_matches.primary.size() <= 3) {
        pairings = find_best_pairings_bruteforce(primary, secondary, hash_matches);
    } else {
        pairings = find_best_pairings_greedy(primary, secondary, hash_matches);
    }

    return pairings;
}

std::vector<std::pair<int, int>> HashMatcher::find_best_pairings_greedy(
    const std::shared_ptr<BinExportContent>& primary,
    const std::shared_ptr<BinExportContent>& secondary,
    const PotentialMatches& hash_matches) {

    std::vector<std::pair<int, int>> pairings;
    std::vector<std::tuple<int, int, float>> similarities;

    for (int p_idx : hash_matches.primary) {
        for (int s_idx : hash_matches.secondary) {
            const auto& p_func = primary->get_functions()[p_idx];
            const auto& s_func = secondary->get_functions()[s_idx];

            float similarity = calculate_additional_similarity(p_func, s_func);
            similarities.emplace_back(p_idx, s_idx, similarity);
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

std::vector<std::pair<int, int>> HashMatcher::find_best_pairings_bruteforce(
    const std::shared_ptr<BinExportContent>& primary,
    const std::shared_ptr<BinExportContent>& secondary,
    const PotentialMatches& hash_matches) {

    std::vector<std::pair<int, int>> best_pairings;
    float best_total_similarity = -1.0f;

    std::vector<int> secondary_indices = hash_matches.secondary;

    do {
        std::vector<std::pair<int, int>> current_pairings;
        float total_similarity = 0.0f;

        for (size_t i = 0; i < hash_matches.primary.size() && i < secondary_indices.size(); i++) {
            int p_idx = hash_matches.primary[i];
            int s_idx = secondary_indices[i];

            const auto& p_func = primary->get_functions()[p_idx];
            const auto& s_func = secondary->get_functions()[s_idx];

            float similarity = calculate_additional_similarity(p_func, s_func);
            total_similarity += similarity;
            current_pairings.emplace_back(p_idx, s_idx);
        }

        if (total_similarity > best_total_similarity) {
            best_total_similarity = total_similarity;
            best_pairings = current_pairings;
        }

    } while (std::next_permutation(secondary_indices.begin(), secondary_indices.end()));

    return best_pairings;
}

bool HashMatcher::are_names_similar(const std::string& name1, const std::string& name2) {
    if (name1.empty() || name2.empty()) {
        return false;
    }

    if (name1 == name2) {
        return true;
    }

    if (name1.find(name2) != std::string::npos || name2.find(name1) != std::string::npos) {
        return true;
    }

    auto find_base_name = [](const std::string& name) -> std::string {
        auto pos = name.find_last_of('_');
        if (pos != std::string::npos && pos < name.length() - 1) {
            std::string suffix = name.substr(pos + 1);
            if (!suffix.empty() && std::all_of(suffix.begin(), suffix.end(), ::isdigit)) {
                return name.substr(0, pos);
            }
        }
        return name;
    };

    std::string base1 = find_base_name(name1);
    std::string base2 = find_base_name(name2);

    if (base1 == base2 && base1.length() > 3) {
        return true;
    }

    auto is_compiler_generated = [](const std::string& name) -> bool {
        return name.find("sub_") == 0 ||
               name.find("loc_") == 0 ||
               name.find("nullsub_") == 0 ||
               name.find("j_") == 0 ||
               name.find("__") == 0;
    };

    if (is_compiler_generated(name1) || is_compiler_generated(name2)) {
        return false;
    }

    std::string lower1 = name1;
    std::string lower2 = name2;
    std::transform(lower1.begin(), lower1.end(), lower1.begin(), ::tolower);
    std::transform(lower2.begin(), lower2.end(), lower2.begin(), ::tolower);

    if (lower1 == lower2) {
        return true;
    }

    auto remove_decorations = [](const std::string& name) -> std::string {
        std::string clean = name;

        if (clean.find("_Z") == 0) clean = clean.substr(2);
        if (clean.find("__") == 0) clean = clean.substr(2);

        auto at_pos = clean.find('@');
        if (at_pos != std::string::npos) {
            clean = clean.substr(0, at_pos);
        }

        return clean;
    };

    std::string clean1 = remove_decorations(name1);
    std::string clean2 = remove_decorations(name2);

    if (clean1 == clean2 && clean1.length() > 2) {
        return true;
    }

    return false;
}

float HashMatcher::calculate_additional_similarity(const Function& p_func, const Function& s_func) {
    float similarity = 0.0f;

    if (!p_func.get_name().empty() && !s_func.get_name().empty()) {
        if (p_func.get_name() == s_func.get_name()) {
            similarity += 0.4f;
        } else if (are_names_similar(p_func.get_name(), s_func.get_name())) {
            similarity += 0.2f;
        }
    }

    uint64_t p_addr = p_func.get_address();
    uint64_t s_addr = s_func.get_address();

    if ((p_addr & 0xFFF) == (s_addr & 0xFFF)) {
        similarity += 0.1f;
    }

    if (p_func.get_basic_block_count() == s_func.get_basic_block_count()) similarity += 0.2f;
    if (p_func.get_loop_count() == s_func.get_loop_count()) similarity += 0.1f;
    if (p_func.get_outgoing_degree() == s_func.get_outgoing_degree()) similarity += 0.1f;
    if (p_func.get_incoming_degree() == s_func.get_incoming_degree()) similarity += 0.1f;

    return similarity;
}

float HashMatcher::calculate_multiple_match_confidence(
    const Function& p_func,
    const Function& s_func,
    int group_size) {

    float base_confidence = 1.0f;

    if (group_size == 2) {
        base_confidence = 0.95f;
    } else if (group_size == 3) {
        base_confidence = 0.90f;
    } else if (group_size <= 5) {
        base_confidence = 0.85f;
    } else {
        base_confidence = 0.80f;
    }

    if (!p_func.get_name().empty() && p_func.get_name() == s_func.get_name()) {
        base_confidence += 0.05f;
    }

    return std::min(1.0f, base_confidence);
}