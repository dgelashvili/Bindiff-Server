#ifndef BINDIFFENGINE_H
#define BINDIFFENGINE_H

#include <vector>
#include <memory>

#include "MatchingAlgorithm.h"
#include "BinExportContent.h"

class BinDiffEngine {
public:
	BinDiffEngine();

	[[nodiscard]] std::vector<Match> match(const BinExportContent& primary, const BinExportContent& secondary) const;

private:
	void fill_matching_algorithms();
private:
	std::vector<std::unique_ptr<MatchingAlgorithm>> matching_algorithms_;
};

#endif //BINDIFFENGINE_H
