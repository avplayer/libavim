#pragma once

#include <string>
#include <memory>
#include <vector>
#include <functional>

#include <openssl/x509.h>
#include <openssl/rsa.h>

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

// 从 private 可以里 dump 出 public key
static inline RSA * RSA_DumpPublicKey(RSA * pkey)
{
	RSA * pubkey = RSA_new();

	pubkey->e = BN_dup(pkey->e);
	pubkey->n = BN_dup(pkey->n);

	return pubkey;
}

/*
 * 顾名思义，这个是简单 RSA , c++ 封装，专门对付 openssl 烂接口烂源码烂文档这种弱智库的
 */

std::string RSA_public_encrypt(RSA * rsa, const std::string & from);

std::string RSA_private_decrypt(RSA * rsa, const std::string & from);

std::string RSA_private_encrypt(RSA * rsa, const std::string & from);

std::string RSA_public_decrypt(RSA * rsa, const std::string & from);


std::shared_ptr<RSA> load_RSA_from_file(std::string filename, std::function<std::string()> password_cb = std::function<std::string()>());
std::shared_ptr<X509> load_X509_from_file(std::string filename, std::function<std::string()> password_cb = std::function<std::string()>());
