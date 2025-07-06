#ifndef LOOPSTRUCTUREMATCHER_H
#define LOOPSTRUCTUREMATCHER_H

#include "MatchingAlgorithm.h"

class LoopStructureMatcher : public MatchingAlgorithm {
public:
	~LoopStructureMatcher() override = default;

	void match(
		const std::shared_ptr<BinExportContent>& primary,
		const std::shared_ptr<BinExportContent>& secondary,
		std::vector<Match>& out_matches,
		std::vector<PotentialMatches>& unmatched_groups) const override;

	[[nodiscard]] float calculate_similarity(const std::shared_ptr<BinExportContent>& primary,
		const std::shared_ptr<BinExportContent>& secondary,
		const Function &p_func, const Function &s_func,
		const std::vector<Match>& existing_matches) const override;

	[[nodiscard]] float calculate_confidence(const std::shared_ptr<BinExportContent>& primary,
		const std::shared_ptr<BinExportContent>& secondary,
		const Function &p_func, const Function &s_func,
		const std::vector<Match>& existing_matches) const override;

private:
	void match_specific_bucket(
		const std::shared_ptr<BinExportContent>& primary,
		const std::shared_ptr<BinExportContent>& secondary,
		std::vector<Match>& out_matches,
		std::vector<PotentialMatches>& unmatched_groups,
		int index,
		std::vector<PotentialMatches>& new_unmatched_groups) const;

};

#endif //LOOPSTRUCTUREMATCHER_H
