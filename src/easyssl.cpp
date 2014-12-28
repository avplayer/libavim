#include <string.h>
#include <algorithm>
#include <openssl/pem.h>
#include "avproto/easyssl.hpp"

std::string RSA_public_encrypt(RSA* rsa, const std::string& from)
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

std::string RSA_private_decrypt(RSA* rsa, const std::string& from)
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

std::string RSA_private_encrypt(RSA* rsa, const std::string& from)
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

std::string RSA_public_decrypt(RSA* rsa, const std::string& from)
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

std::shared_ptr<RSA> load_RSA_from_file(std::string filename, std::function<std::string()> password_cb)
{
	std::shared_ptr<BIO> bio {BIO_new_file(filename.c_str(), "r") , BIO_free};

	auto _c_rsa_key = PEM_read_bio_RSAPrivateKey(bio.get(), nullptr, [](char * buf, int size, int rwflag, void * _password_cb)->int
	{
		// 打开窗口, 提升用户输入密码
		auto password_cb = *reinterpret_cast<std::function<std::string()>*>(_password_cb);
		if (password_cb)
		{
			std::string pass = password_cb();
			strncpy(buf, pass.data(), size);
			return pass.length();
		}
		return  -1;
	}, (void*) &password_cb);

	return std::shared_ptr<RSA>(_c_rsa_key, RSA_free);
}

std::shared_ptr<X509> load_X509_from_file(std::string filename, std::function<std::string()> password_cb)
{
	std::shared_ptr<BIO> bio {BIO_new_file(filename.c_str(), "r") , BIO_free};

	auto _c_rsa_key = PEM_read_bio_X509(bio.get(), nullptr, [](char * buf, int size, int rwflag, void * _password_cb)->int
	{
		// 打开窗口, 提升用户输入密码
		auto password_cb = *reinterpret_cast<std::function<std::string()>*>(_password_cb);
		if (password_cb)
		{
			std::string pass = password_cb();
			strncpy(buf, pass.data(), size);
			return pass.length();
		}
		return  -1;
	}, (void*) &password_cb);

	return std::shared_ptr<X509>(_c_rsa_key, X509_free);
}
