#include "CallSequenceMatcher.h"
#include <algorithm>

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

            auto [similarity, confidence] = calculate_similarity(
                primary, secondary,
                primary->get_functions()[call_matches.primary[0]],
                secondary->get_functions()[call_matches.secondary[0]],
                out_matches);
            
            match.similarity = similarity;
            match.confidence = confidence;
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

    std::unordered_map<uint64_t, uint64_t> matched_functions;
    for (const auto& match : existing_matches) {
        matched_functions[match.address_primary] = match.address_secondary;
    }

    int function_index = content->get_index_from_address(function.get_address());
    const auto& callees = content->get_callee_neighbours(function_index);

    std::vector<std::string> call_sequence;

    for (int callee_idx : callees) {
        uint64_t callee_address = content->get_functions()[callee_idx].get_address();

        if (matched_functions.count(callee_address)) {
            call_sequence.push_back("MATCHED_" + std::to_string(matched_functions[callee_address]));
        } else {
            const auto& callee_func = content->get_functions()[callee_idx];
            std::string func_sig = std::to_string(callee_func.get_basic_block_count()) + "_" +
                                  std::to_string(callee_func.get_function_instruction_count());
            call_sequence.push_back("UNMATCHED_" + func_sig);
        }
    }

    if (call_sequence.empty()) {
        return "";
    }

    std::string signature;
    for (const auto& call : call_sequence) {
        signature += call + "|";
    }

    return signature;
}

std::pair<float, float> CallSequenceMatcher::calculate_similarity(
    const std::shared_ptr<BinExportContent>& primary,
    const std::shared_ptr<BinExportContent>& secondary,
    const Function& func1,
    const Function& func2,
    const std::vector<Match>& existing_matches) {


    std::unordered_map<uint64_t, uint64_t> matched_functions;
    for (const auto& match : existing_matches) {
        matched_functions[match.address_primary] = match.address_secondary;
    }

    int func1_index = primary->get_index_from_address(func1.get_address());
    int func2_index = secondary->get_index_from_address(func2.get_address());
    
    const auto& callees1 = primary->get_callee_neighbours(func1_index);
    const auto& callees2 = secondary->get_callee_neighbours(func2_index);

    if (callees1.empty() && callees2.empty()) {
        float basic_sim = (func1.get_basic_block_count() == func2.get_basic_block_count() &&
                          func1.get_function_instruction_count() == func2.get_function_instruction_count()) ? 0.9f : 0.7f;
        return {basic_sim, 0.6f};
    }

    int matched_calls = 0;
    int similar_unmatched = 0;
    int total_calls = std::max(callees1.size(), callees2.size());

    if (total_calls == 0) {
        return {0.8f, 0.6f};
    }

    for (int callee1_idx : callees1) {
        uint64_t callee1_addr = primary->get_functions()[callee1_idx].get_address();
        
        if (matched_functions.count(callee1_addr)) {
            uint64_t matched_addr = matched_functions[callee1_addr];
            for (int callee2_idx : callees2) {
                if (secondary->get_functions()[callee2_idx].get_address() == matched_addr) {
                    matched_calls++;
                    break;
                }
            }
        } else {
            const auto& callee1_func = primary->get_functions()[callee1_idx];
            for (int callee2_idx : callees2) {
                const auto& callee2_func = secondary->get_functions()[callee2_idx];
                if (callee1_func.get_basic_block_count() == callee2_func.get_basic_block_count() &&
                    callee1_func.get_function_instruction_count() == callee2_func.get_function_instruction_count()) {
                    similar_unmatched++;
                    break;
                }
            }
        }
    }

    float match_ratio = static_cast<float>(matched_calls) / total_calls;
    float similar_ratio = static_cast<float>(similar_unmatched) / total_calls;
    
    float similarity = match_ratio * 0.8f + similar_ratio * 0.4f;
    
    similarity = std::min(similarity, 0.95f);
    similarity = std::max(similarity, 0.6f);

    float confidence = 0.5f;
    
    if (matched_calls > 0) {
        confidence += 0.2f * (static_cast<float>(matched_calls) / total_calls);
    }
    
    if (total_calls >= 3) {
        confidence += 0.15f;
    }
    if (total_calls >= 5) {
        confidence += 0.1f;
    }
    
    int dissimilar_calls = total_calls - matched_calls - similar_unmatched;
    if (dissimilar_calls > total_calls / 2) {
        confidence -= 0.15f;
    }

    confidence = std::min(confidence, 0.9f);
    confidence = std::max(confidence, 0.4f);

    return {similarity, confidence};
}
