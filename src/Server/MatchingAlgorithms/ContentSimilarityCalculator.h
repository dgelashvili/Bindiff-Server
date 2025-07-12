#ifndef CONTENTSIMILARITYCALCULATOR_H
#define CONTENTSIMILARITYCALCULATOR_H

#include "Models/Function.h"
#include <algorithm>
#include <cmath>

class ContentSimilarityCalculator {
public:
    static float calculate_content_similarity(const Function& func1, const Function& func2) {
        float instruction_similarity = calculate_instruction_similarity(func1, func2);
        float structure_similarity = calculate_structure_similarity(func1, func2);
        float mnemonic_similarity = calculate_mnemonic_similarity(func1, func2);
        float call_similarity = calculate_call_similarity(func1, func2);

        return instruction_similarity * 0.4f +
               structure_similarity * 0.3f +
               mnemonic_similarity * 0.2f +
               call_similarity * 0.1f;
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

        if (content_similarity > 0.9f) {
            return 0.95f;
        } else if (content_similarity > 0.7f) {
            return 0.8f;
        } else if (content_similarity > 0.4f) {
            return 0.5f;
        } else if (content_similarity > 0.2f) {
            return 0.35f;
        } else {
            return 0.2f;
        }
    }

private:
    static float calculate_instruction_similarity(const Function& func1, const Function& func2) {
        int count1 = func1.get_function_instruction_count();
        int count2 = func2.get_function_instruction_count();

        if (count1 == 0 && count2 == 0) return 1.0f;
        if (count1 == 0 || count2 == 0) return 0.0f;

        float ratio = (float)std::min(count1, count2) / std::max(count1, count2);
        return ratio;
    }

    static float calculate_structure_similarity(const Function& func1, const Function& func2) {
        float similarity = 0.0f;

        int bb1 = func1.get_basic_block_count();
        int bb2 = func2.get_basic_block_count();
        if (bb1 == bb2) {
            similarity += 0.4f;
        } else if (bb1 > 0 && bb2 > 0) {
            float bb_ratio = (float)std::min(bb1, bb2) / std::max(bb1, bb2);
            similarity += bb_ratio * 0.4f;
        }

        int loop1 = func1.get_loop_count();
        int loop2 = func2.get_loop_count();
        if (loop1 == loop2) {
            similarity += 0.3f;
        } else if (loop1 + loop2 > 0) {
            float loop_ratio = (float)std::min(loop1, loop2) / std::max(loop1 + 1, loop2 + 1);
            similarity += loop_ratio * 0.3f;
        } else {
            similarity += 0.3f;
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

        return similarity;
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

        float length_ratio = (float)std::min(mnemonics1.size(), mnemonics2.size()) /
                            std::max(mnemonics1.size(), mnemonics2.size());

        return length_ratio * 0.5f;
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