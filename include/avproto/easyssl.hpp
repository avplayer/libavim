#pragma once

#include <string>
#include <memory>

#include <openssl/x509.h>

inline std::string X509_to_string(X509* x509)
{
	unsigned char* out = nullptr;
	auto l = i2d_X509(x509, &out);

	std::string ret((const char*)out, l);
	CRYPTO_free(out);
	return ret;
}

inline std::shared_ptr<X509> X509_from_string(const std::string& str)
{
	auto len = str.length();
	const unsigned char* in = (const unsigned char*)str.data();
	return std::shared_ptr<X509>(d2i_X509(NULL, &in, len), X509_free);
}
