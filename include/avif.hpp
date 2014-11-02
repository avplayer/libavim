
#pragma once

#include <boost/format.hpp>
#include <boost/function.hpp>
#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>

#include "protocol/avim-base.pb.h"

// FIXME 这些接口对象需要重新设计

// 一个接口类， av核心用这个类来对外数据沟通，类似 linux 内核里的 sbk_buf
// TODO, 使用 type-erasure 重新设计
struct avif
{
	virtual std::string get_ifname()= 0 ;
	template<class Handler>
	void set_remove_from_av(Handler handler){
		_remove_from_av = handler;
	};


	virtual avim::proto::base::avPacket * async_read_packet(boost::asio::yield_context yield_context) = 0;

	virtual avim::proto::base::avPacket * async_write_packet(boost::asio::yield_context yield_context) = 0;

protected:
	void remove_from_av()
	{
		if(_remove_from_av)
			_remove_from_av(get_ifname());
		_remove_from_av.clear();
	}

private:

	boost::function<void(std::string)>  _remove_from_av;
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

	// TODO 从 TCP 连接上读取一个 avPacket
	virtual avim::proto::base::avPacket * async_read_packet(boost::asio::yield_context yield_context)
	{

	}

	// TODO 从 TCP 连接上写入一个 avPacket
    virtual avim::proto::base::avPacket* async_write_packet(boost::asio::yield_context yield_context)
	{

	}

	bool async_send( boost::asio::yield_context);
	bool recvfrom( boost::asio::yield_context );

	virtual ~avtcpif()
	{
		remove_from_av();
	}

private:
	std::string ifname;
	boost::shared_ptr<boost::asio::ip::tcp::socket> m_client_sock;
};
