#include "BinDiffCache.h"

void BinDiffCache::add(const std::string &id, const std::shared_ptr<BinExportContent> &content) {
	std::lock_guard lock(cache_mutex_);
	if (contains_without_lock(id)) return;
	cache_[id] = content;
}

std::shared_ptr<BinExportContent> BinDiffCache::get(const std::string &id) {
	std::lock_guard lock(cache_mutex_);
	if (!contains_without_lock(id)) {
		throw std::runtime_error("No parsed file with given ID");
	}
	return cache_[id];
}

bool BinDiffCache::contains(const std::string &id) {
	std::lock_guard lock(cache_mutex_);
	return contains_without_lock(id);
}

bool BinDiffCache::contains_without_lock(const std::string &id) {
	return cache_.find(id) != cache_.end();
}

