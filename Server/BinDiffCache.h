#ifndef BINDIFFCACHE_H
#define BINDIFFCACHE_H

#include <string>
#include <unordered_map>

#include "BinExportContent.h"

class BinDiffCache {
public:
	void add(const std::string& id, const std::shared_ptr<BinExportContent> &content);
	std::shared_ptr<BinExportContent> get(const std::string& id);
	bool contains(const std::string& id);

private:
	std::unordered_map<std::string, std::shared_ptr<BinExportContent>> cache_;
};

#endif //BINDIFFCACHE_H
