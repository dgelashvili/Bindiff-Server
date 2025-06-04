#include "BinDiffEngine.h"

#include "NameMatcher.h"
#include "BasicStructureMatcher.h"

BinDiffEngine::BinDiffEngine() {
	fill_matching_algorithms();
}

std::vector<Match> BinDiffEngine::match(
	const std::shared_ptr<BinExportContent>& primary,
	const std::shared_ptr<BinExportContent>& secondary) const {
	std::vector<Match> result;
	std::vector<PotentialMatches> potentialMatches;

	PotentialMatches initial;
	for (int i = 0; i < primary->get_function_addresses().size(); i++) {
		initial.primary.push_back(i);
	}
	for (int i = 0; i < secondary->get_function_addresses().size(); i++) {
		initial.secondary.push_back(i);
	}
	potentialMatches.push_back(std::move(initial));

	for (const auto& algorithm : matching_algorithms_) {
		algorithm->match(primary, secondary, result, potentialMatches);
	}

	return result;
}

void BinDiffEngine::fill_matching_algorithms() {
	matching_algorithms_.push_back(std::make_unique<BasicStructureMatcher>());
	matching_algorithms_.push_back(std::make_unique<NameMatcher>());
}
