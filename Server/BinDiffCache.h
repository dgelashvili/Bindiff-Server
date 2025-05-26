#ifndef BINDIFFCACHE_H
#define BINDIFFCACHE_H

#include <string>
#include <unordered_map>

class BinDiffCache {
public:
	void add(const std::string& id, const std::string& content);
	std::string get(const std::string& id);
	bool contains(const std::string& id);

private:
	std::unordered_map<std::string, std::string> cache_;
};

#endif //BINDIFFCACHE_H
