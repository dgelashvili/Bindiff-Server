#ifndef CALLSHAPEMATCHER_H
#define CALLSHAPEMATCHER_H

#include "MatchingAlgorithm.h"

class CallDegreeMatcher : public MatchingAlgorithm {
public:
	~CallDegreeMatcher() override = default;

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
};

#endif //CALLSHAPEMATCHER_H
