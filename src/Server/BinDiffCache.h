#ifndef BINDIFFCACHE_H
#define BINDIFFCACHE_H

#include <string>
#include <unordered_map>
#include <map>
#include <mutex>

#include "BinExportContent.h"
#include "MatchingAlgorithm.h"

class BinDiffCache {
public:
	void add(const std::string& id, const std::shared_ptr<BinExportContent> &content);
	void add(
		const std::string& id_primary,
		const std::string& id_secondary,
		const std::tuple<
			std::vector<Match>,
			std::vector<std::pair<uint64_t, std::string>>,
			std::vector<std::pair<uint64_t, std::string>>>& diff_result);
	std::shared_ptr<BinExportContent> get(const std::string& id);
	std::tuple<
		std::vector<Match>,
		std::vector<std::pair<uint64_t, std::string>>,
		std::vector<std::pair<uint64_t, std::string>>> get(const std::string& id_primary, const std::string& id_secondary);
	bool contains(const std::string& id);
	bool contains(const std::string& id_primary, const std::string& id_secondary);

private:
	bool contains_without_lock(const std::string& id);
	bool contains_without_lock(const std::string& id_primary, const std::string& id_secondary);

	std::unordered_map<std::string, std::shared_ptr<BinExportContent>> cache_;
	std::map<
		std::pair<std::string, std::string>,
		std::tuple<
			std::vector<Match>,
			std::vector<std::pair<uint64_t, std::string>>,
			std::vector<std::pair<uint64_t, std::string>>>
	> diff_cache_;
	std::mutex cache_mutex_;
};

#endif //BINDIFFCACHE_H
