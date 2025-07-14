#ifndef CONTENTSIMILARITYCALCULATOR_H
#define CONTENTSIMILARITYCALCULATOR_H

#include "Models/Function.h"
#include <algorithm>
#include <cmath>
#include <string>

class ContentSimilarityCalculator {
public:
    static float calculate_content_similarity(const Function& func1, const Function& func2) {
        float instruction_similarity = calculate_instruction_similarity(func1, func2);
        float structure_similarity = calculate_structure_similarity(func1, func2);
        float mnemonic_similarity = calculate_mnemonic_similarity(func1, func2);
        float call_similarity = calculate_call_similarity(func1, func2);
        float pattern_similarity = calculate_implementation_pattern_similarity(func1, func2);

        bool both_simple = (func1.get_basic_block_count() <= 3 && func2.get_basic_block_count() <= 3 &&
                           func1.get_loop_count() == 0 && func2.get_loop_count() == 0);

        if (both_simple) {
            return instruction_similarity * 0.30f +
                   structure_similarity * 0.10f +
                   mnemonic_similarity * 0.30f +
                   call_similarity * 0.10f +
                   pattern_similarity * 0.20f;
        }
        return instruction_similarity * 0.25f +
               structure_similarity * 0.15f +
               mnemonic_similarity * 0.35f +
               call_similarity * 0.1f +
               pattern_similarity * 0.15f;
    }

    static float calculate_name_based_confidence(const Function& func1, const Function& func2, float content_similarity) {
        bool names_match = !func1.get_name().empty() && func1.get_name() == func2.get_name();
        bool meaningful_names = !func1.get_name().empty() && !func2.get_name().empty() &&
                               func1.get_name().find("sub_") != 0 && func2.get_name().find("sub_") != 0;

        if (!names_match) {
            return 0.0f;
        }

        if (!meaningful_names) {
            return 0.6f;
        }

        float base_confidence = assess_implementation_compatibility(func1, func2);

        return apply_content_similarity_adjustment(base_confidence, content_similarity);
    }

private:

    static float assess_implementation_compatibility(const Function& func1, const Function& func2) {
        bool func1_recursive = func1.get_recursive_degree() > 0;
        bool func2_recursive = func2.get_recursive_degree() > 0;
        bool func1_has_loops = func1.get_loop_count() > 0;
        bool func2_has_loops = func2.get_loop_count() > 0;

        int complexity1 = func1.get_basic_block_count() + func1.get_loop_count() * 2 + func1.get_outgoing_degree();
        int complexity2 = func2.get_basic_block_count() + func2.get_loop_count() * 2 + func2.get_outgoing_degree();

        if ((func1_recursive && !func2_recursive && func2_has_loops) ||
            (func2_recursive && !func1_recursive && func1_has_loops)) {
            return 0.30f;
        }

        if (func1_recursive && func2_recursive) {
            float complexity_ratio = (float)std::min(complexity1, complexity2) / std::max(complexity1, complexity2);

            if (complexity_ratio < 0.6f) {
                return 0.45f;
            }
            return 0.65f;
        }

        if (!func1_recursive && !func2_recursive) {
            bool both_very_simple = (complexity1 <= 4 && complexity2 <= 8);
            if (both_very_simple) {
                return 0.75f;
            }

            bool both_iterative = (func1_has_loops && func2_has_loops);
            if (both_iterative) {
                return 0.60f;
            }

            return 0.70f;
        }

        if ((func1_recursive && !func2_recursive && !func2_has_loops) ||
            (func2_recursive && !func1_recursive && !func1_has_loops)) {
            return 0.40f;
        }
        return 0.5;
    }

    static float apply_content_similarity_adjustment(float base_confidence, float content_similarity) {
        if (content_similarity > 0.7f) {
            return std::min(0.95f, base_confidence + 0.10f);
        }
        if (content_similarity > 0.5f) {
            return base_confidence;
        }
        if (content_similarity > 0.3f) {
            return std::max(0.15f, base_confidence - 0.05f);
        }
        if (content_similarity > 0.2f) {
            return std::max(0.12f, base_confidence - 0.10f);
        }
        return std::max(0.08f, base_confidence - 0.15f);
    }

    static float calculate_instruction_similarity(const Function& func1, const Function& func2) {
        int count1 = func1.get_function_instruction_count();
        int count2 = func2.get_function_instruction_count();

        if (count1 == 0 && count2 == 0) return 1.0f;
        if (count1 == 0 || count2 == 0) return 0.0f;

        float ratio = (float)std::min(count1, count2) / std::max(count1, count2);

        if (ratio < 0.7f) {
            ratio *= 0.8f;
        }

        return ratio;
    }

    static float calculate_structure_similarity(const Function& func1, const Function& func2) {
        float similarity = 0.0f;

        int bb1 = func1.get_basic_block_count();
        int bb2 = func2.get_basic_block_count();
        if (bb1 == bb2) {
            similarity += 0.3f;
        } else if (bb1 > 0 && bb2 > 0) {
            float bb_ratio = (float)std::min(bb1, bb2) / std::max(bb1, bb2);
            similarity += bb_ratio * 0.3f;
        }

        int loop1 = func1.get_loop_count();
        int loop2 = func2.get_loop_count();
        if (loop1 == loop2) {
            similarity += 0.4f;
        } else {
            float penalty = std::abs(loop1 - loop2) * 0.15f;
            similarity -= penalty;
        }

        int out1 = func1.get_outgoing_degree();
        int out2 = func2.get_outgoing_degree();
        if (out1 == out2) {
            similarity += 0.3f;
        } else if (out1 + out2 > 0) {
            float out_ratio = (float)std::min(out1, out2) / std::max(out1 + 1, out2 + 1);
            similarity += out_ratio * 0.3f;
        } else {
            similarity += 0.3f;
        }

        return std::max(0.0f, similarity);
    }

    static float calculate_implementation_pattern_similarity(const Function& func1, const Function& func2) {
        bool func1_recursive = func1.get_recursive_degree() > 0;
        bool func2_recursive = func2.get_recursive_degree() > 0;
        bool func1_has_loops = func1.get_loop_count() > 0;
        bool func2_has_loops = func2.get_loop_count() > 0;


        if ((func1_recursive && !func2_recursive && func2_has_loops) ||
            (func2_recursive && !func1_recursive && func1_has_loops)) {
            return 0.15f;
        }

        if (func1_recursive && func2_recursive) {
            int rec1 = func1.get_recursive_degree();
            int rec2 = func2.get_recursive_degree();
            if (rec1 == rec2) {
                return 0.90f;
            }
            float ratio = (float)std::min(rec1, rec2) / std::max(rec1, rec2);
            return 0.60f + ratio * 0.30f;
        }

            if ((func1_has_loops || func1_recursive) != (func2_has_loops || func2_recursive)) {
                int complexity1 = func1.get_basic_block_count() + func1.get_loop_count() * 2;
                int complexity2 = func2.get_basic_block_count() + func2.get_loop_count() * 2;

                if (std::max(complexity1, complexity2) <= 8) {
                    return 0.70f;
                }
                return 0.55f;
            }

        if (!func1_has_loops && !func2_has_loops && !func1_recursive && !func2_recursive) {
            return 0.75f;
        }

        if ((func1_has_loops || func1_recursive) != (func2_has_loops || func2_recursive)) {
            return 0.60f;
        }

        return 0.65f;
    }

    static float calculate_mnemonic_similarity(const Function& func1, const Function& func2) {
        if (func1.get_mnemonics_hash() == func2.get_mnemonics_hash() && func1.get_mnemonics_hash() != 0) {
            return 1.0f;
        }

        const auto& mnemonics1 = func1.get_mnemonics();
        const auto& mnemonics2 = func2.get_mnemonics();

        if (mnemonics1.empty() && mnemonics2.empty()) {
            return 1.0f;
        }
        if (mnemonics1.empty() || mnemonics2.empty()) {
            return 0.0f;
        }

        bool has_call1 = false, has_call2 = false;
        bool has_loop_instr1 = false, has_loop_instr2 = false;
        bool has_cmp1 = false, has_cmp2 = false;

        for (const auto& mnemonic : mnemonics1) {
            std::string m = mnemonic;
            if (m.find("call") != std::string::npos) has_call1 = true;
            if (m.find("jmp") != std::string::npos || m.find("loop") != std::string::npos) has_loop_instr1 = true;
            if (m.find("cmp") != std::string::npos || m.find("test") != std::string::npos) has_cmp1 = true;
        }

        for (const auto& mnemonic : mnemonics2) {
            std::string m = mnemonic;
            if (m.find("call") != std::string::npos) has_call2 = true;
            if (m.find("jmp") != std::string::npos || m.find("loop") != std::string::npos) has_loop_instr2 = true;
            if (m.find("cmp") != std::string::npos || m.find("test") != std::string::npos) has_cmp2 = true;
        }

        float pattern_penalty = 0.0f;
        if (has_call1 != has_call2) pattern_penalty += 0.3f;
        if (has_loop_instr1 != has_loop_instr2) pattern_penalty += 0.4f;
        if (has_cmp1 != has_cmp2) pattern_penalty += 0.2f;

        float length_ratio = (float)std::min(mnemonics1.size(), mnemonics2.size()) /
                            std::max(mnemonics1.size(), mnemonics2.size());

        float base_similarity = length_ratio * 0.6f;
        float adjusted_similarity = std::max(0.0f, base_similarity - pattern_penalty);

        return adjusted_similarity;
    }

    static float calculate_call_similarity(const Function& func1, const Function& func2) {
        int in1 = func1.get_incoming_degree();
        int in2 = func2.get_incoming_degree();
        int out1 = func1.get_outgoing_degree();
        int out2 = func2.get_outgoing_degree();

        float in_similarity = 0.0f;
        if (in1 == in2) {
            in_similarity = 1.0f;
        } else if (in1 + in2 > 0) {
            in_similarity = (float)std::min(in1, in2) / std::max(in1, in2);
        }

        float out_similarity = 0.0f;
        if (out1 == out2) {
            out_similarity = 1.0f;
        } else if (out1 + out2 > 0) {
            out_similarity = (float)std::min(out1, out2) / std::max(out1, out2);
        }

        return (in_similarity + out_similarity) / 2.0f;
    }
};

#endif //CONTENTSIMILARITYCALCULATOR_H
