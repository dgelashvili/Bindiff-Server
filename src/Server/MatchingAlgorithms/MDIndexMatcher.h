#ifndef MDINDEXMATCHER_H
#define MDINDEXMATCHER_H

#include "MatchingAlgorithm.h"

class MDIndexMatcher : public MatchingAlgorithm {
public:
	~MDIndexMatcher() override = default;

	void match(
		const std::shared_ptr<BinExportContent>& primary,
		const std::shared_ptr<BinExportContent>& secondary,
		std::vector<Match>& out_matches,
		std::vector<PotentialMatches>& unmatched_groups) const override;

private:
	static std::string calculate_md_index(const Function& function);
	static std::string calculate_relaxed_md_index(const Function& function);

	static void match_specific_bucket(
		const std::shared_ptr<BinExportContent>& primary,
		const std::shared_ptr<BinExportContent>& secondary,
		std::vector<Match>& out_matches,
		std::vector<PotentialMatches>& unmatched_groups,
		int index,
		std::vector<PotentialMatches>& new_unmatched_groups,
		bool use_relaxed = false);
};

#endif //MDINDEXMATCHER_H