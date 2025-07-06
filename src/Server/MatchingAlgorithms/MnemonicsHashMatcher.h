#ifndef MNEMONICSHASHMATCHER_H
#define MNEMONICSHASHMATCHER_H

#include "MatchingAlgorithm.h"

class MnemonicsHashMatcher : public MatchingAlgorithm {
public:
	~MnemonicsHashMatcher() override = default;

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

	void handle_multiple_mnemonic_matches(
		const std::shared_ptr<BinExportContent>& primary,
		const std::shared_ptr<BinExportContent>& secondary,
		const PotentialMatches& mnemonic_matches,
		std::vector<Match>& out_matches,
		long long mnemonic_hash) const;

	static std::vector<std::pair<int, int>> find_best_mnemonic_pairings(
		const std::shared_ptr<BinExportContent>& primary,
		const std::shared_ptr<BinExportContent>& secondary,
		const PotentialMatches& mnemonic_matches);

	static float calculate_structural_similarity_for_disambiguation(
		const Function& p_func, const Function& s_func);

};

#endif //MNEMONICSHASHMATCHER_H
