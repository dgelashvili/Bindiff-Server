#include "sha256Wrapper.h"

#include "sha256.h"
#include <cstdio>

std::string sha_256(const std::string& input) {
	BYTE hash[SHA256_BLOCK_SIZE];
	SHA256_CTX ctx;

	sha256_init(&ctx);
	sha256_update(&ctx, reinterpret_cast<const BYTE*>(input.c_str()), input.length());
	sha256_final(&ctx, hash);

	std::string result;
	for (const unsigned char i : hash) {
		char buf[3];
		std::sprintf(buf, "%02x", i);
		result += buf;
	}

	return result;
}
