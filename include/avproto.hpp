
#pragma once

#include <string>
#include <boost/scoped_ptr.hpp>

#include "avif.hpp"

namespace detail {
class avkernel_impl;
}

enum av_route_op{
	AVROUTE_ADD,
	AVROUTE_MOD,
	AVROUTE_DEL
};

// 从 private 可以里 dump 出 public key
static inline RSA * RSA_DumpPublicKey(RSA * pkey)
{
	RSA * pubkey = RSA_new();

	pubkey->e = BN_dup(pkey->e);
	pubkey->n = BN_dup(pkey->n);

	return pubkey;
}

class avkernel : boost::noncopyable
{
	boost::asio::io_service & io_service;
	boost::shared_ptr<detail::avkernel_impl> _impl;

	// ifname -> avif 的映射关系
public:

	typedef boost::function<void(boost::system::error_code)> SendReadyHandler;

	avkernel(boost::asio::io_service &);

	bool add_interface(avif interface);

	// 添加一项路由
	bool add_route(std::string targetAddress, std::string gateway, std::string ifname, int metric);

	int sendto(std::string target, std::string data);
};


/*
 * 启动 av 协议核心，一旦调用，那么 av 核心就启动起来了，等待 av 协议的处理
 *
 */
extern "C" void av_start();

// 添加 avif 接口，用于 av_route 操作
avif * av_if_handover(avif avinterface);

/*
 * 配置 av 协议地址，类似 ifconfig 的作用。
 *
 * 传递一个 av客户端密钥和证书
 *
 * 所谓私钥啊，就是一个 RSA private key
 * 证书就是一个 RSA pubkey 和一个 avplayer.org 这个  ROOT CA 的签名
 */
bool av_config(std::string pkey, std::string  cert);

// 配置av路由表 允许使用 * 这样的地址设定默认路由
bool av_route(av_route_op op /*add mod del*/, std::string addr, std::string gateway, std::string interfacename);

// 发送数据， av层会自动调用 RSA private key 加密数据
bool av_sendto(std::string dest_address, std::string message);

// 接收数据
bool av_recvfrom(std::string dest_address, std::string message);
