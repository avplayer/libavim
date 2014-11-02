
#pragma once

#include <boost/format.hpp>

#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>


// 一个接口类， av核心用这个类来对外数据沟通，类似 linux 内核里的 sbk_buf
// TODO, 使用 type-erasure 重新设计
struct avif
{
	virtual std::string get_ifname() = 0;

};


// 这个是 TCP 协议的接口
// TODO, 使用 type-erasure 重新设计
// TODO 暂时使用继承模式
struct avtcpif : public avif
{
	static int ifcount;

	avtcpif(boost::shared_ptr<boost::asio::ip::tcp::socket> client_sock, std::string local_addr, std::string remote_addr)
	{
		m_client_sock = client_sock;
		ifname = boost::str(boost::format("tcp_%d") % ifcount);
	}

	virtual std::string get_ifname()
	{
		return ifname;
	}


	bool async_send( boost::asio::yield_context);
	bool recvfrom( boost::asio::yield_context );

private:
	std::string ifname;
	boost::shared_ptr<boost::asio::ip::tcp::socket> m_client_sock;
};
