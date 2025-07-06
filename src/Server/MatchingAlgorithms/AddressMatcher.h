#ifndef ADDRESSMATCHER_H
#define ADDRESSMATCHER_H

#include "MatchingAlgorithm.h"

class AddressMatcher : public MatchingAlgorithm {
public:
	~AddressMatcher() override = default;

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

#endif //ADDRESSMATCHER_H
