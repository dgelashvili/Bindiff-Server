#include "BinDiffCache.h"

void BinDiffCache::add(const std::string &id, const std::string &content) {
	if (contains(id)) return;
	cache_[id] = content;
}

std::string BinDiffCache::get(const std::string &id) {
	if (!contains(id)) return "";
	return cache_[id];
}

bool BinDiffCache::contains(const std::string &id) {
	return cache_.find(id) != cache_.end();
}
