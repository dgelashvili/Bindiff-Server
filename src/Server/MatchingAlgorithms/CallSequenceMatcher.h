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

	[[nodiscard]] float calculate_similarity(
		const std::shared_ptr<BinExportContent>& primary,
		const std::shared_ptr<BinExportContent>& secondary,
		const Function& func1,
		const Function& func2,
		const std::vector<Match>& existing_matches) const override;

	[[nodiscard]] float calculate_confidence(
	const std::shared_ptr<BinExportContent>& primary,
	const std::shared_ptr<BinExportContent>& secondary,
	const Function& func1,
	const Function& func2,
	const std::vector<Match>& existing_matches) const override;

private:
	static std::string calculate_call_sequence_signature(
		const std::shared_ptr<BinExportContent>& content,
		const Function& function,
		const std::vector<Match>& existing_matches);

	void match_specific_bucket(
		const std::shared_ptr<BinExportContent>& primary,
		const std::shared_ptr<BinExportContent>& secondary,
		std::vector<Match>& out_matches,
		std::vector<PotentialMatches>& unmatched_groups,
		int index,
		std::vector<PotentialMatches>& new_unmatched_groups) const;
};

#endif
