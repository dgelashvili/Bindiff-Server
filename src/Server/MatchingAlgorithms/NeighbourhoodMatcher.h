#ifndef NEIGHBOURHOODMATCHER_H
#define NEIGHBOURHOODMATCHER_H

#include "MatchingAlgorithm.h"

class NeighbourhoodMatcher : public MatchingAlgorithm {
public:
	~NeighbourhoodMatcher() override = default;

	void match(
		const std::shared_ptr<BinExportContent> &primary,
		const std::shared_ptr<BinExportContent> &secondary,
		std::vector<Match> &out_matches,
		std::vector<PotentialMatches> &unmatched_groups) const override;
	[[nodiscard]] float calculate_similarity(const std::shared_ptr<BinExportContent>& primary,
		const std::shared_ptr<BinExportContent>& secondary,
		const Function &p_func, const Function &s_func,
		const std::vector<Match>& existing_matches) const override;

	[[nodiscard]] float calculate_confidence(const std::shared_ptr<BinExportContent>& primary,
		const std::shared_ptr<BinExportContent>& secondary,
		const Function &p_func, const Function &s_func,
		const std::vector<Match>& existing_matches) const override;
private:
	static void fill_neighbour_score(
		std::map<std::pair<int, int>, std::pair<int, int>> &neighbour_score,
		const std::shared_ptr<BinExportContent> &primary,
		const std::shared_ptr<BinExportContent> &secondary,
		std::set<int> &primary_matched_indices,
		std::set<int> &secondary_matched_indices,
		std::vector<std::pair<int, int>> &matching_indices);
	static void fill_potential_matches(
		const std::shared_ptr<BinExportContent> &primary,
		const std::shared_ptr<BinExportContent> &secondary,
		std::unordered_map<int, std::vector<int>> &primary_to_secondary,
		std::unordered_map<int, std::vector<int>> &secondary_to_primary,
		std::map<std::pair<int, int>, std::pair<int, int>> &neighbour_score);

	static float calculate_similarity(const std::shared_ptr<BinExportContent> &primary,
	                                         const std::shared_ptr<BinExportContent> &secondary, int primary_index,
	                                         int secondary_index,
	                                         const std::map<std::pair<int, int>, std::pair<int, int>> &neighbour_score);

	static float calculate_confidence(const std::shared_ptr<BinExportContent> &primary,
	                                         const std::shared_ptr<BinExportContent> &secondary, int primary_index,
	                                         int secondary_index,
	                                         const std::map<std::pair<int, int>, std::pair<int, int>> &neighbour_score);
};

#endif //NEIGHBOURHOODMATCHER_H
