
#pragma once

#include "avif.hpp"


// 这个是 TCP 协议的接口
struct avtcpif
{
public:
	avtcpif(boost::shared_ptr<boost::asio::ip::tcp::socket>, std::string local_addr, RSA * _key);

	// TCP接口，有 master/slave 模式之分 服务器使用 master 模式，客户端则是 slave 模式
	// 区别只是登录时候的握手不一样，所以就在 handshake 这里直接设定就可以了
	bool async_master_handshake(bool as_master, boost::asio::yield_context yield_context);

	// 同步模式
	bool slave_handshake(bool as_master);

	std::string remote_addr();

public: // 下面是实现 avif 接口
	std::string get_ifname()
	{
		return ifname;
	}

	proto::base::avAddress * if_address()
	{
		return m_local_addr;
	}

	RSA * get_rsa_key()
	{
		return _rsa;
	}

	// TODO 从 TCP 连接上读取一个 avPacket
	proto::base::avPacket * async_read_packet(boost::asio::yield_context yield_context)
	{

	}

	// TODO 从 TCP 连接上写入一个 avPacket
    bool async_write_packet(proto::base::avPacket*, boost::asio::yield_context yield_context)
	{

	}

	~avtcpif()
	{
		// remove_from_av();
	}

	// 分配一个 if 接口名字
	static std::string allocate_ifname();

private:
	std::string ifname;
	RSA * _rsa;
	proto::base::avAddress * m_local_addr, * m_remote_addr;
	std::string m_local_addr_str, m_remote_addr_str;
	boost::shared_ptr<boost::asio::ip::tcp::socket> m_sock;

	boost::asio::streambuf m_recv_buf;
};

