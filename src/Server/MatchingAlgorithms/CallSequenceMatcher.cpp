#include "CallSequenceMatcher.h"

void CallSequenceMatcher::match(
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

void CallSequenceMatcher::match_specific_bucket(
    const std::shared_ptr<BinExportContent>& primary,
    const std::shared_ptr<BinExportContent>& secondary,
    std::vector<Match>& out_matches,
    std::vector<PotentialMatches>& unmatched_groups,
    int index,
    std::vector<PotentialMatches>& new_unmatched_groups) {

    std::unordered_map<std::string, PotentialMatches> potential_matches;
    PotentialMatches specific_bucket = unmatched_groups[index];
    unmatched_groups.erase(unmatched_groups.begin() + index);

    for (const auto& function : specific_bucket.primary) {
        std::string call_signature = calculate_call_sequence_signature(
            primary, primary->get_functions()[function], out_matches);
        if (!call_signature.empty()) {
            potential_matches[call_signature].primary.push_back(function);
        }
    }

    for (const auto& function : specific_bucket.secondary) {
        std::string call_signature = calculate_call_sequence_signature(
            secondary, secondary->get_functions()[function], out_matches);
        if (!call_signature.empty()) {
            potential_matches[call_signature].secondary.push_back(function);
        }
    }

    PotentialMatches remaining_bucket;
    for (const auto& it : potential_matches) {
        PotentialMatches call_matches = it.second;
        if (call_matches.primary.size() == 1 && call_matches.secondary.size() == 1) {
            Match match;
            match.address_primary = primary->get_functions()[call_matches.primary[0]].get_address();
            match.address_secondary = secondary->get_functions()[call_matches.secondary[0]].get_address();
            match.similarity = 0.85f;
            match.confidence = 0.75f;
            out_matches.push_back(match);
        } else {
            for (const auto& function : call_matches.primary) {
                remaining_bucket.primary.push_back(function);
            }
            for (const auto& function : call_matches.secondary) {
                remaining_bucket.secondary.push_back(function);
            }
        }
    }

    // Add functions without calls back to remaining
    for (const auto& function : specific_bucket.primary) {
        std::string call_signature = calculate_call_sequence_signature(
            primary, primary->get_functions()[function], out_matches);
        if (call_signature.empty()) {
            remaining_bucket.primary.push_back(function);
        }
    }
    for (const auto& function : specific_bucket.secondary) {
        std::string call_signature = calculate_call_sequence_signature(
            secondary, secondary->get_functions()[function], out_matches);
        if (call_signature.empty()) {
            remaining_bucket.secondary.push_back(function);
        }
    }

    new_unmatched_groups.push_back(remaining_bucket);
}

std::string CallSequenceMatcher::calculate_call_sequence_signature(
    const std::shared_ptr<BinExportContent>& content,
    const Function& function,
    const std::vector<Match>& existing_matches) {

    // Build map of matched function addresses
    std::unordered_map<uint64_t, uint64_t> matched_functions;
    for (const auto& match : existing_matches) {
        matched_functions[match.address_primary] = match.address_secondary;
    }

    int function_index = content->get_index_from_address(function.get_address());
    const auto& callees = content->get_callee_neighbours(function_index);

    std::vector<std::string> call_sequence;

    for (int callee_idx : callees) {
        uint64_t callee_address = content->get_functions()[callee_idx].get_address();

        // If this called function is already matched, use a stable identifier
        if (matched_functions.count(callee_address)) {
            call_sequence.push_back("MATCHED_" + std::to_string(matched_functions[callee_address]));
        } else {
            // Use function characteristics as identifier
            const auto& callee_func = content->get_functions()[callee_idx];
            std::string func_sig = std::to_string(callee_func.get_basic_block_count()) + "_" +
                                  std::to_string(callee_func.get_function_instruction_count());
            call_sequence.push_back("UNMATCHED_" + func_sig);
        }
    }

    if (call_sequence.empty()) {
        return "";  // No calls
    }

    // Create signature from call sequence
    std::string signature;
    for (const auto& call : call_sequence) {
        signature += call + "|";
    }

    return signature;
}
