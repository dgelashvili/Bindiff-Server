#ifndef RELAXEDMDINDEXMATCHER_H
#define RELAXEDMDINDEXMATCHER_H

#include "MatchingAlgorithm.h"

class RelaxedMDIndexMatcher : public MatchingAlgorithm {
public:
	void match(
		const std::shared_ptr<BinExportContent>& primary,
		const std::shared_ptr<BinExportContent>& secondary,
		std::vector<Match>& out_matches,
		std::vector<PotentialMatches>& unmatched_groups) const override;

private:
	void match_specific_bucket(
		const std::shared_ptr<BinExportContent>& primary,
		const std::shared_ptr<BinExportContent>& secondary,
		std::vector<Match>& out_matches,
		std::vector<PotentialMatches>& unmatched_groups,
		int index,
		std::vector<PotentialMatches>& new_unmatched_groups) const;

	static std::string calculate_relaxed_md_signature(const Function& func);

	static bool are_signatures_similar(const std::string& sig1, const std::string& sig2, double tolerance = 0.2);

	[[nodiscard]] float calculate_similarity(const std::shared_ptr<BinExportContent>& primary,
		const std::shared_ptr<BinExportContent>& secondary,
		const Function &p_func, const Function &s_func,
		const std::vector<Match>& existing_matches) const override;

	[[nodiscard]] float calculate_confidence(const std::shared_ptr<BinExportContent>& primary,
		const std::shared_ptr<BinExportContent>& secondary,
		const Function &p_func, const Function &s_func,
		const std::vector<Match>& existing_matches) const override;
};

#endif //RELAXEDMDINDEXMATCHER_H
