#ifndef CALLSEQUENCEMATCHER_H
#define CALLSEQUENCEMATCHER_H

#include "MatchingAlgorithm.h"

class CallSequenceMatcher : public MatchingAlgorithm {
public:
	~CallSequenceMatcher() override = default;

	void match(
		const std::shared_ptr<BinExportContent>& primary,
		const std::shared_ptr<BinExportContent>& secondary,
		std::vector<Match>& out_matches,
		std::vector<PotentialMatches>& unmatched_groups) const override;

private:
	static std::string calculate_call_sequence_signature(
		const std::shared_ptr<BinExportContent>& content,
		const Function& function,
		const std::vector<Match>& existing_matches);

	static void match_specific_bucket(
		const std::shared_ptr<BinExportContent>& primary,
		const std::shared_ptr<BinExportContent>& secondary,
		std::vector<Match>& out_matches,
		std::vector<PotentialMatches>& unmatched_groups,
		int index,
		std::vector<PotentialMatches>& new_unmatched_groups);
};

#endif
