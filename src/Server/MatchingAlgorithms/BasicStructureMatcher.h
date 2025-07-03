#ifndef BASICSTRUCTUREMATCHER_H
#define BASICSTRUCTUREMATCHER_H

#include "MatchingAlgorithm.h"

class BasicStructureMatcher : public MatchingAlgorithm {
public:
	~BasicStructureMatcher() override = default;

	void match(
		const std::shared_ptr<BinExportContent>& primary,
		const std::shared_ptr<BinExportContent>& secondary,
		std::vector<Match>& out_matches,
		std::vector<PotentialMatches>& unmatched_groups) const override;
private:
	static void match_specific_bucket(
		const std::shared_ptr<BinExportContent>& primary,
		const std::shared_ptr<BinExportContent>& secondary,
		std::vector<Match>& out_matches,
		std::vector<PotentialMatches>& unmatched_groups,
		int index,
		std::vector<PotentialMatches>& new_unmatched_groups);

	static float calculate_similarity(const Function &p_func, const Function &s_func);

	static float calculate_confidence(const Function &p_func, const Function &s_func);
};

#endif //BASICSTRUCTUREMATCHER_H
