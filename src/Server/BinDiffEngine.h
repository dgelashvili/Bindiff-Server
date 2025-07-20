#ifndef BINDIFFENGINE_H
#define BINDIFFENGINE_H

#include <vector>
#include <memory>

#include "MatchingAlgorithm.h"
#include "BinExportContent.h"

class BinDiffEngine {
public:
	BinDiffEngine();

	[[nodiscard]] std::vector<Match> match(
		const std::shared_ptr<BinExportContent>& primary,
		const std::shared_ptr<BinExportContent>& secondary);
	[[nodiscard]] std::vector<std::pair<uint64_t, std::string>> get_unmatched_primaries() const;
	[[nodiscard]] std::vector<std::pair<uint64_t, std::string>> get_unmatched_secondaries() const;

private:
	void fill_matching_algorithms();
	static bool has_meaningful_names(const std::shared_ptr<BinExportContent>& content);
private:
	std::vector<std::unique_ptr<MatchingAlgorithm>> matching_algorithms_;
	std::vector<std::pair<uint64_t, std::string>> unmatched_primaries;
	std::vector<std::pair<uint64_t, std::string>> unmatched_secondaries;
};

#endif //BINDIFFENGINE_H
