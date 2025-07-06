#ifndef HASHMATCHER_H
#define HASHMATCHER_H

#include "MatchingAlgorithm.h"

class HashMatcher : public MatchingAlgorithm {
public:
	~HashMatcher() override = default;

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

	static bool are_names_similar(const std::string &name1, const std::string &name2);

	static float calculate_additional_similarity(const Function& p_func, const Function& s_func);
	static float calculate_multiple_match_confidence(const Function& p_func, const Function& s_func, int group_size);
	static std::vector<std::pair<int, int>> find_best_pairings_greedy(
	const std::shared_ptr<BinExportContent>& primary,
	const std::shared_ptr<BinExportContent>& secondary,
	const PotentialMatches& hash_matches);

	static std::vector<std::pair<int, int>> find_best_pairings_bruteforce(const std::shared_ptr<BinExportContent> &primary,
	                                                               const std::shared_ptr<BinExportContent> &secondary,
	                                                               const PotentialMatches &hash_matches);

	static std::vector<std::pair<int, int>> find_best_pairings(
	const std::shared_ptr<BinExportContent>& primary,
	const std::shared_ptr<BinExportContent>& secondary,
	const PotentialMatches& hash_matches,
	const std::string& hash);
	static void handle_multiple_hash_matches(
	const std::shared_ptr<BinExportContent>& primary,
	const std::shared_ptr<BinExportContent>& secondary,
	const PotentialMatches& hash_matches,
	std::vector<Match>& out_matches,
	PotentialMatches& remaining_bucket,
	const std::string& hash);
};

#endif //HASHMATCHER_H
