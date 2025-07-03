#include "BinDiffEngine.h"

#include "CallSequenceMatcher.h"
#include "MDIndexMatcher.h"
#include "AddressMatcher.h"
#include "HashMatcher.h"
#include "MnemonicsHashMatcher.h"
#include "NameMatcher.h"
#include "LoopStructureMatcher.h"
#include "BasicStructureMatcher.h"
#include "CallDegreeMatcher.h"
#include "NeighbourhoodMatcher.h"

BinDiffEngine::BinDiffEngine() {
	fill_matching_algorithms();
}

std::vector<Match> BinDiffEngine::match(
	const std::shared_ptr<BinExportContent>& primary,
	const std::shared_ptr<BinExportContent>& secondary) const {
	std::vector<Match> result;
	std::vector<PotentialMatches> potentialMatches;

	PotentialMatches initial;
	for (int i = 0; i < primary->get_functions().size(); i++) {
		initial.primary.push_back(i);
	}
	for (int i = 0; i < secondary->get_functions().size(); i++) {
		initial.secondary.push_back(i);
	}
	potentialMatches.push_back(std::move(initial));

	for (int i = 0; i < 4; i++) {
		const int previous_size = result.size();
		for (const auto& algorithm : matching_algorithms_) {
			algorithm->match(primary, secondary, result, potentialMatches);
		}
		if (previous_size == result.size()) {
			break;
		}
	}

	return result;
}

void BinDiffEngine::fill_matching_algorithms() {
	matching_algorithms_.push_back(std::make_unique<HashMatcher>());
	matching_algorithms_.push_back(std::make_unique<NameMatcher>());
	matching_algorithms_.push_back(std::make_unique<MnemonicsHashMatcher>());
	matching_algorithms_.push_back(std::make_unique<AddressMatcher>());
	matching_algorithms_.push_back(std::make_unique<MDIndexMatcher>());
	matching_algorithms_.push_back(std::make_unique<LoopStructureMatcher>());
	matching_algorithms_.push_back(std::make_unique<BasicStructureMatcher>());
	matching_algorithms_.push_back(std::make_unique<CallDegreeMatcher>());
	matching_algorithms_.push_back(std::make_unique<CallSequenceMatcher>());
	matching_algorithms_.push_back(std::make_unique<NeighbourhoodMatcher>());
}
