#include "BinDiffCache.h"

void BinDiffCache::add(const std::string &id, const std::shared_ptr<BinExportContent> &content) {
	std::lock_guard lock(cache_mutex_);
	if (contains_without_lock(id)) return;
	cache_[id] = content;
}

void BinDiffCache::add(
	const std::string &id_primary,
	const std::string &id_secondary,
	const std::tuple<
		std::vector<Match>,
		std::vector<std::pair<uint64_t, std::string> >,
		std::vector<std::pair<uint64_t, std::string> > >& diff_result) {
	diff_cache_[std::make_pair(id_primary, id_secondary)] = diff_result;
}

std::shared_ptr<BinExportContent> BinDiffCache::get(const std::string &id) {
	std::lock_guard lock(cache_mutex_);
	if (!contains_without_lock(id)) {
		throw std::runtime_error("No parsed file with given ID");
	}
	return cache_[id];
}

std::tuple<
	std::vector<Match>,
	std::vector<std::pair<uint64_t, std::string> >,
	std::vector<std::pair<uint64_t, std::string> > > BinDiffCache::get(const std::string &id_primary, const std::string &id_secondary) {
	return diff_cache_[std::make_pair(id_primary, id_secondary)];
}

bool BinDiffCache::contains(const std::string &id) {
	std::lock_guard lock(cache_mutex_);
	return contains_without_lock(id);
}

bool BinDiffCache::contains(const std::string &id_primary, const std::string &id_secondary) {
	std::lock_guard lock(cache_mutex_);
	return contains_without_lock(id_primary, id_secondary);
}

bool BinDiffCache::contains_without_lock(const std::string &id) {
	return cache_.find(id) != cache_.end();
}

bool BinDiffCache::contains_without_lock(const std::string &id_primary, const std::string &id_secondary) {
	return diff_cache_.find(std::make_pair(id_primary, id_secondary)) != diff_cache_.end();
}
