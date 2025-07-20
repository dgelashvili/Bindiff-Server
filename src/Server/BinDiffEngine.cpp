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
#include "RelaxedMDIndexMatcher.h"

BinDiffEngine::BinDiffEngine() {
	fill_matching_algorithms();
}

std::vector<Match> BinDiffEngine::match(
	const std::shared_ptr<BinExportContent>& primary,
	const std::shared_ptr<BinExportContent>& secondary) {
	std::vector<Match> result;
	std::vector<PotentialMatches> potentialMatches;

	if (has_meaningful_names(primary) && has_meaningful_names(secondary)) {
		if (!matching_algorithms_.empty()) {
			matching_algorithms_.pop_back();
		}
	}

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
		for (int j = 0; j < matching_algorithms_.size(); j++) {
			if (i < 2 && (j >= 5 && j <= 8)) continue;
			matching_algorithms_[j]->match(primary, secondary, result, potentialMatches);
		}
		if (previous_size == result.size()) {
			break;
		}
	}

	unmatched_primaries.clear();
	unmatched_secondaries.clear();
	const std::vector<Function> primary_functions = primary->get_functions();
	const std::vector<Function> secondary_functions = secondary->get_functions();
	for (const auto& potential_match : potentialMatches) {
		for (const auto& primary_ind : potential_match.primary) {
			const auto& func = primary_functions[primary_ind];
			std::pair<uint64_t, std::string> p = std::make_pair(func.get_address(), func.get_name());
			unmatched_primaries.push_back(p);
		}
		for (const auto& secondary_ind : potential_match.secondary) {
			const auto& func = secondary_functions[secondary_ind];
			std::pair<uint64_t, std::string> p = std::make_pair(func.get_address(), func.get_name());
			unmatched_secondaries.push_back(p);
		}
	}

	return result;
}

bool BinDiffEngine::has_meaningful_names(const std::shared_ptr<BinExportContent>& content) {
    const auto& functions = content->get_functions();

    int total_functions = functions.size();
    int meaningful_names = 0;
    int auto_generated_names = 0;

    int sample_size = std::min(200, total_functions);

    for (int i = 0; i < sample_size; i++) {
        const std::string& name = functions[i].get_name();

        if (name.find("sub_") == 0 ||
            name.find("loc_") == 0 ||
            name.find("nullsub_") == 0 ||
            name.find("unk_") == 0 ||
            name.find("byte_") == 0 ||
            name.find("word_") == 0 ||
            name.find("dword_") == 0 ||
            name.find("qword_") == 0 ||
            name.find("off_") == 0 ||
            name.find("seg_") == 0 ||
            name.find("asc_") == 0 ||
            name.find("j_") == 0 ){
        	auto_generated_names++;
        } else {
            meaningful_names++;
        }
    }

    float meaningful_ratio = static_cast<float>(meaningful_names) / sample_size;

    return meaningful_ratio > 0.5f;
}

std::vector<std::pair<uint64_t, std::string> > BinDiffEngine::get_unmatched_primaries() const {
	return unmatched_primaries;
}

std::vector<std::pair<uint64_t, std::string> > BinDiffEngine::get_unmatched_secondaries() const {
	return unmatched_secondaries;
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
	matching_algorithms_.push_back(std::make_unique<RelaxedMDIndexMatcher>());
}
