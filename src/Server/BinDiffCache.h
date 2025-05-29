#ifndef BINDIFFCACHE_H
#define BINDIFFCACHE_H

#include <string>
#include <unordered_map>
#include <mutex>

#include "BinExportContent.h"

class BinDiffCache {
public:
	void add(const std::string& id, const std::shared_ptr<BinExportContent> &content);
	std::shared_ptr<BinExportContent> get(const std::string& id);
	bool contains(const std::string& id);

private:
	bool contains_without_lock(const std::string& id);

	std::unordered_map<std::string, std::shared_ptr<BinExportContent>> cache_;
	std::mutex cache_mutex_;
};

#endif //BINDIFFCACHE_H
