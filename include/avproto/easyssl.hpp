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

inline std::string RSA_public_encrypt(RSA * rsa, const std::string & from)
{
	std::string result;
	const int keysize = RSA_size(rsa);
	std::vector<unsigned char> block(keysize);
	const int chunksize = keysize  - RSA_PKCS1_PADDING_SIZE;
	int inputlen = from.length();

	for(int i = 0 ; i < inputlen; i+= chunksize)
	{
		auto resultsize = RSA_public_encrypt(std::min(chunksize, inputlen - i), (uint8_t*) &from[i],  &block[0], (RSA*) rsa, RSA_PKCS1_PADDING);
		result.append((char*)block.data(), resultsize);
	}
	return result;
}

inline std::string RSA_private_decrypt(RSA * rsa, const std::string & from)
{
	std::string result;
	const int keysize = RSA_size(rsa);
	std::vector<unsigned char> block(keysize);

	for(int i = 0 ; i < from.length(); i+= keysize)
	{
		auto resultsize = RSA_private_decrypt(std::min<int>(keysize, from.length() - i), (uint8_t*) &from[i],  &block[0], rsa, RSA_PKCS1_PADDING);
		result.append((char*)block.data(), resultsize);
	}
	return result;
}

inline std::string RSA_private_encrypt(RSA * rsa, const std::string & from)
{
	std::string result;
	const int keysize = RSA_size(rsa);
	std::vector<unsigned char> block(keysize);
	const int chunksize = keysize  - RSA_PKCS1_PADDING_SIZE;
	int inputlen = from.length();

	for(int i = 0 ; i < from.length(); i+= chunksize)
	{
		int flen = std::min<int>(chunksize, inputlen - i);

		std::fill(block.begin(),block.end(), 0);

		auto resultsize = RSA_private_encrypt(
			flen,
			(uint8_t*) &from[i],
			&block[0],
			rsa,
			RSA_PKCS1_PADDING
		);
		result.append((char*)block.data(), resultsize);
	}
	return result;
}

inline std::string RSA_public_decrypt(RSA * rsa, const std::string & from)
{
	std::string result;
	const int keysize = RSA_size(rsa);
	std::vector<unsigned char> block(keysize);

	int inputlen = from.length();

	for(int i = 0 ; i < from.length(); i+= keysize)
	{
		int flen = std::min(keysize, inputlen - i);

		auto resultsize = RSA_public_decrypt(
			flen,
			(uint8_t*) &from[i],
			&block[0],
			rsa,
			RSA_PKCS1_PADDING
		);
		result.append((char*)block.data(), resultsize);
	}
	return result;
}
