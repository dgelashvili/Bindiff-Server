#ifndef MATCHINGALGORITHM_H
#define MATCHINGALGORITHM_H

#include <vector>
#include <cstdint>

#include "BinExportContent.h"

struct Match{
	uint64_t address_primary{};
	uint64_t address_secondary{};
	float similarity{};
    float confidence{};
};

struct PotentialMatches {
	std::vector<int> primary;
	std::vector<int> secondary;
};

class MatchingAlgorithm {
public:
	virtual ~MatchingAlgorithm() = default;

	virtual void match(
		const std::shared_ptr<BinExportContent>& primary,
		const std::shared_ptr<BinExportContent>& secondary,
		std::vector<Match>& out_matches,
		std::vector<PotentialMatches>& unmatched_groups) const = 0;

private:
	[[nodiscard]] virtual float calculate_similarity(const std::shared_ptr<BinExportContent>& primary,
	const std::shared_ptr<BinExportContent>& secondary,
	const Function &p_func, const Function &s_func,
	const std::vector<Match>& existing_matches) const = 0;

	[[nodiscard]] virtual float calculate_confidence(const std::shared_ptr<BinExportContent>& primary,
	const std::shared_ptr<BinExportContent>& secondary,
	const Function &p_func, const Function &s_func,
	const std::vector<Match>& existing_matches) const = 0;
};



#endif //MATCHINGALGORITHM_H
