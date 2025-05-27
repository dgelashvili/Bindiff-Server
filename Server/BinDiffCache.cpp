#include "BinDiffCache.h"

void BinDiffCache::add(const std::string &id, const std::shared_ptr<BinExportContent> &content) {
	if (contains(id)) return;
	cache_[id] = content;
}

std::shared_ptr<BinExportContent> BinDiffCache::get(const std::string &id) {
	if (!contains(id)) {
		throw std::runtime_error("No parsed file with given ID");
	}
	return cache_[id];
}

bool BinDiffCache::contains(const std::string &id) {
	return cache_.find(id) != cache_.end();
}
