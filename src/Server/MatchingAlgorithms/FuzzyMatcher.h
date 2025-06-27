//
// Created by takusi on 7/9/2025.
//

#ifndef FUZZYMATCHER_H
#define FUZZYMATCHER_H

#include "MatchingAlgorithm.h"

class FuzzyMatcher : public MatchingAlgorithm {
public:
	void match(
		const std::shared_ptr<BinExportContent>& primary,
		const std::shared_ptr<BinExportContent>& secondary,
		std::vector<Match>& out_matches,
		std::vector<PotentialMatches>& unmatched_groups) const override;

private:
	static float calculate_combined_similarity(
		const Function& primary_func,
		const Function& secondary_func);

	static bool is_potential_match(
		const Function& primary_func,
		const Function& secondary_func,
		float threshold = 0.7f);
};



#endif //FUZZYMATCHER_H
