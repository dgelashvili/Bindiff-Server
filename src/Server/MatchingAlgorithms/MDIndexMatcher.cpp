#include "MDIndexMatcher.h"
#include <map>

void MDIndexMatcher::match(
    const std::shared_ptr<BinExportContent>& primary,
    const std::shared_ptr<BinExportContent>& secondary,
    std::vector<Match>& out_matches,
    std::vector<PotentialMatches>& unmatched_groups) const {

    std::vector<PotentialMatches> new_unmatched_groups;

    for (int i = 0; i < unmatched_groups.size(); i++) {
        match_specific_bucket(primary, secondary, out_matches, unmatched_groups, i, new_unmatched_groups, false);
    }

    std::vector<PotentialMatches> relaxed_groups = new_unmatched_groups;
    new_unmatched_groups.clear();

    for (int i = 0; i < relaxed_groups.size(); i++) {
        std::vector<PotentialMatches> temp_groups = relaxed_groups;
        match_specific_bucket(primary, secondary, out_matches, temp_groups, i, new_unmatched_groups, true);
    }

    for (const auto& bucket : new_unmatched_groups) {
        unmatched_groups.push_back(bucket);
    }
}

void MDIndexMatcher::match_specific_bucket(
    const std::shared_ptr<BinExportContent>& primary,
    const std::shared_ptr<BinExportContent>& secondary,
    std::vector<Match>& out_matches,
    std::vector<PotentialMatches>& unmatched_groups,
    int index,
    std::vector<PotentialMatches>& new_unmatched_groups,
    bool use_relaxed) {

    std::map<std::string, PotentialMatches> potential_matches;
    PotentialMatches specific_bucket = unmatched_groups[index];
    unmatched_groups.erase(unmatched_groups.begin() + index);

    for (const auto& function : specific_bucket.primary) {
        std::string md_index = use_relaxed ?
            calculate_relaxed_md_index(primary->get_functions()[function]) :
            calculate_md_index(primary->get_functions()[function]);
        potential_matches[md_index].primary.push_back(function);
    }

    for (const auto& function : specific_bucket.secondary) {
        std::string md_index = use_relaxed ?
            calculate_relaxed_md_index(secondary->get_functions()[function]) :
            calculate_md_index(secondary->get_functions()[function]);
        potential_matches[md_index].secondary.push_back(function);
    }

    PotentialMatches remaining_bucket;
    for (const auto& it : potential_matches) {
        PotentialMatches md_matches = it.second;
        if (md_matches.primary.size() == 1 && md_matches.secondary.size() == 1) {
            Match match;
            match.address_primary = primary->get_functions()[md_matches.primary[0]].get_address();
            match.address_secondary = secondary->get_functions()[md_matches.secondary[0]].get_address();
            match.similarity = use_relaxed ? 0.8f : 0.9f;
            match.confidence = use_relaxed ? 0.7f : 0.85f;
            out_matches.push_back(match);
        } else {
            for (const auto& function : md_matches.primary) {
                remaining_bucket.primary.push_back(function);
            }
            for (const auto& function : md_matches.secondary) {
                remaining_bucket.secondary.push_back(function);
            }
        }
    }
    new_unmatched_groups.push_back(remaining_bucket);
}

std::string MDIndexMatcher::calculate_md_index(const Function& function) {

    std::string md_index = std::to_string(function.get_basic_block_count()) + "_" +
                          std::to_string(function.get_function_instruction_count()) + "_" +
                          std::to_string(function.get_outgoing_degree()) + "_" +
                          std::to_string(function.get_incoming_degree()) + "_" +
                          std::to_string(function.get_loop_count());

    return md_index;
}

std::string MDIndexMatcher::calculate_relaxed_md_index(const Function& function) {
    std::string relaxed_index = std::to_string(function.get_basic_block_count()) + "_" +
                               std::to_string(function.get_outgoing_degree()) + "_" +
                               std::to_string(function.get_incoming_degree()) + "_" +
                               std::to_string(function.get_loop_count());

    return relaxed_index;
}