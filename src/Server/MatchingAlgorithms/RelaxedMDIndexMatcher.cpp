#include "RelaxedMDIndexMatcher.h"

void RelaxedMDIndexMatcher::match(
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

void RelaxedMDIndexMatcher::match_specific_bucket(
    const std::shared_ptr<BinExportContent>& primary,
    const std::shared_ptr<BinExportContent>& secondary,
    std::vector<Match>& out_matches,
    std::vector<PotentialMatches>& unmatched_groups,
    int index,
    std::vector<PotentialMatches>& new_unmatched_groups) const {
    
    PotentialMatches specific_bucket = unmatched_groups[index];
    unmatched_groups.erase(unmatched_groups.begin() + index);
    
    std::vector<std::pair<std::string, int>> primary_signatures;
    std::vector<std::pair<std::string, int>> secondary_signatures;
    
    const auto& primary_functions = primary->get_functions();
    const auto& secondary_functions = secondary->get_functions();
    
    for (int func_idx : specific_bucket.primary) {
        const auto& func = primary_functions[func_idx];
        std::string relaxed_sig = calculate_relaxed_md_signature(func);
        primary_signatures.emplace_back(relaxed_sig, func_idx);
    }
    
    for (int func_idx : specific_bucket.secondary) {
        const auto& func = secondary_functions[func_idx];
        std::string relaxed_sig = calculate_relaxed_md_signature(func);
        secondary_signatures.emplace_back(relaxed_sig, func_idx);
    }
    
    PotentialMatches unmatched_in_bucket;
    std::set<int> matched_primary, matched_secondary;

    std::unordered_map<std::string, std::vector<int>> primary_by_sig;
    std::unordered_map<std::string, std::vector<int>> secondary_by_sig;
    
    for (const auto& [sig, idx] : primary_signatures) {
        primary_by_sig[sig].push_back(idx);
    }
    
    for (const auto& [sig, idx] : secondary_signatures) {
        secondary_by_sig[sig].push_back(idx);
    }
    
    for (const auto& [sig, primary_funcs] : primary_by_sig) {
        auto it = secondary_by_sig.find(sig);
        if (it != secondary_by_sig.end() && 
            primary_funcs.size() == 1 && it->second.size() == 1) {
            
            int p_idx = primary_funcs[0];
            int s_idx = it->second[0];
            
            const auto& p_func = primary_functions[p_idx];
            const auto& s_func = secondary_functions[s_idx];
            
            Match match;
            match.address_primary = p_func.get_address();
            match.address_secondary = s_func.get_address();
            match.similarity = calculate_similarity(primary, secondary, p_func, s_func, out_matches);
            match.confidence = calculate_confidence(primary, secondary, p_func, s_func, out_matches);
            
            out_matches.push_back(match);
            
            matched_primary.insert(p_idx);
            matched_secondary.insert(s_idx);
        }
    }
    
    for (const auto& [p_sig, p_idx] : primary_signatures) {
        if (matched_primary.find(p_idx) != matched_primary.end()) continue;
        
        int best_match = -1;
        float best_structural_similarity = 0.0f;
        
        for (const auto& [s_sig, s_idx] : secondary_signatures) {
            if (matched_secondary.find(s_idx) != matched_secondary.end()) continue;
            
            if (are_signatures_similar(p_sig, s_sig)) {
                const auto& p_func = primary_functions[p_idx];
                const auto& s_func = secondary_functions[s_idx];
                
                float structural_sim = 0.0f;
                if (p_func.get_basic_block_count() == s_func.get_basic_block_count()) structural_sim += 0.4f;
                if (p_func.get_loop_count() == s_func.get_loop_count()) structural_sim += 0.3f;
                if (p_func.get_outgoing_degree() == s_func.get_outgoing_degree()) structural_sim += 0.2f;
                if (p_func.get_incoming_degree() == s_func.get_incoming_degree()) structural_sim += 0.1f;
                
                if (structural_sim > best_structural_similarity) {
                    best_structural_similarity = structural_sim;
                    best_match = s_idx;
                }
            }
        }
        
        if (best_match != -1 && best_structural_similarity > 0.6f) {
            const auto& p_func = primary_functions[p_idx];
            const auto& s_func = secondary_functions[best_match];
            
            Match match;
            match.address_primary = p_func.get_address();
            match.address_secondary = s_func.get_address();
            match.similarity = calculate_similarity(primary, secondary, p_func, s_func, out_matches);
            match.confidence = calculate_confidence(primary, secondary, p_func, s_func, out_matches);
            
            match.confidence *= best_structural_similarity;
            
            out_matches.push_back(match);
            
            matched_primary.insert(p_idx);
            matched_secondary.insert(best_match);
        }
    }
    
    for (int func_idx : specific_bucket.primary) {
        if (matched_primary.find(func_idx) == matched_primary.end()) {
            unmatched_in_bucket.primary.push_back(func_idx);
        }
    }
    
    for (int func_idx : specific_bucket.secondary) {
        if (matched_secondary.find(func_idx) == matched_secondary.end()) {
            unmatched_in_bucket.secondary.push_back(func_idx);
        }
    }
    
    new_unmatched_groups.push_back(unmatched_in_bucket);
}

std::string RelaxedMDIndexMatcher::calculate_relaxed_md_signature(const Function& func) {

    int bb_count = func.get_basic_block_count();
    int loop_count = func.get_loop_count();
    int out_degree = func.get_outgoing_degree();
    int in_degree = func.get_incoming_degree();
    
    std::string bb_bucket;
    if (bb_count <= 1) bb_bucket = "tiny";
    else if (bb_count <= 3) bb_bucket = "small";
    else if (bb_count <= 8) bb_bucket = "medium";
    else if (bb_count <= 20) bb_bucket = "large";
    else bb_bucket = "huge";
    
    std::string loop_bucket;
    if (loop_count == 0) loop_bucket = "none";
    else if (loop_count == 1) loop_bucket = "single";
    else if (loop_count <= 3) loop_bucket = "few";
    else loop_bucket = "many";
    
    std::string call_bucket;
    int total_calls = out_degree + in_degree;
    if (total_calls == 0) call_bucket = "isolated";
    else if (total_calls <= 2) call_bucket = "minimal";
    else if (total_calls <= 8) call_bucket = "moderate";
    else if (total_calls <= 20) call_bucket = "active";
    else call_bucket = "central";
    
    int instr_count = func.get_function_instruction_count();
    std::string instr_bucket;
    if (instr_count <= 5) instr_bucket = "tiny";
    else if (instr_count <= 15) instr_bucket = "small";
    else if (instr_count <= 50) instr_bucket = "medium";
    else if (instr_count <= 150) instr_bucket = "large";
    else instr_bucket = "huge";
    
    return bb_bucket + "_" + loop_bucket + "_" + call_bucket + "_" + instr_bucket;
}

bool RelaxedMDIndexMatcher::are_signatures_similar(
    const std::string& sig1, 
    const std::string& sig2, 
    double tolerance) {
    
    if (sig1 == sig2) return true;
    
    auto parse_sig = [](const std::string& sig) -> std::vector<std::string> {
        std::vector<std::string> parts;
        std::string current;
        for (char c : sig) {
            if (c == '_') {
                if (!current.empty()) {
                    parts.push_back(current);
                    current.clear();
                }
            } else {
                current += c;
            }
        }
        if (!current.empty()) {
            parts.push_back(current);
        }
        return parts;
    };
    
    auto parts1 = parse_sig(sig1);
    auto parts2 = parse_sig(sig2);
    
    if (parts1.size() != parts2.size()) return false;
    
    int matching_parts = 0;
    for (size_t i = 0; i < parts1.size(); ++i) {
        if (parts1[i] == parts2[i]) {
            matching_parts++;
        }
    }
    
    double match_ratio = static_cast<double>(matching_parts) / parts1.size();
    return match_ratio >= 1.0 - tolerance;
}

float RelaxedMDIndexMatcher::calculate_similarity(
    const std::shared_ptr<BinExportContent>& primary,
    const std::shared_ptr<BinExportContent>& secondary,
    const Function &p_func, const Function &s_func,
    const std::vector<Match>& existing_matches) const {
    
    return 0.75f;
}

float RelaxedMDIndexMatcher::calculate_confidence(
    const std::shared_ptr<BinExportContent>& primary,
    const std::shared_ptr<BinExportContent>& secondary,
    const Function &p_func, const Function &s_func,
    const std::vector<Match>& existing_matches) const {
    
    float confidence = 0.65f;
    
    int complexity = p_func.get_basic_block_count() + p_func.get_loop_count() * 2;
    if (complexity > 15) {
        confidence += 0.15f;
    } else if (complexity > 8) {
        confidence += 0.10f;
    } else if (complexity > 3) {
        confidence += 0.05f;
    }
    
    int total_calls = p_func.get_outgoing_degree() + p_func.get_incoming_degree();
    if (total_calls > 10) {
        confidence += 0.10f;
    } else if (total_calls == 0) {
        confidence -= 0.10f;
    }
    
    return std::min(0.85f, std::max(0.4f, confidence));
}