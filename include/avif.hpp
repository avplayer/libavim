
#pragma once

#include <boost/format.hpp>
#include <boost/function.hpp>
#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>

#include "protocol/avim-base.pb.h"

#include <openssl/rsa.h>

namespace detail {

	struct avif_implement_interface{
		virtual std::string get_ifname() = 0 ;

		virtual RSA * get_rsa_key() = 0;

		// 读取 av数据包
		virtual avim::proto::base::avPacket * async_read_packet(boost::asio::yield_context yield_context) = 0;

		// 发送 av数据包
		virtual bool async_write_packet(avim::proto::base::avPacket*, boost::asio::yield_context yield_context) = 0;
	};

	template<class RealImpl>
	struct avif_implement_wrapper : public avif_implement_interface
	{
		std::string get_ifname()
		{
			return _impl->get_ifname();
		};

		RSA * get_rsa_key()
		{
			return _impl->get_rsa_key();
		}

		// 读取 av数据包
		avim::proto::base::avPacket * async_read_packet(boost::asio::yield_context yield_context)
		{
			return _impl->async_read_packet(yield_context);
		}

		// 发送 av数据包
		bool async_write_packet(avim::proto::base::avPacket* pkt, boost::asio::yield_context yield_context)
		{
			return _impl->async_write_packet(pkt, yield_context);
		}

		avif_implement_wrapper(boost::shared_ptr<RealImpl> other)
		{
			_impl = other;
		}

	private:
		boost::shared_ptr<RealImpl> _impl;
	};

}

// 一个接口类， av核心用这个类来对外数据沟通，类似 linux 内核里的 sbk_buf
struct avif
{
	std::string get_ifname()
	{
		return _impl->get_ifname();
	};

	RSA * get_rsa_key()
	{
		return _impl->get_rsa_key();
	}

	// 读取 av数据包
	avim::proto::base::avPacket * async_read_packet(boost::asio::yield_context yield_context)
	{
		return _impl->async_read_packet(yield_context);
	}

	// 发送 av数据包
    bool async_write_packet(avim::proto::base::avPacket* pkt, boost::asio::yield_context yield_context)
	{
		return _impl->async_write_packet(pkt, yield_context);
	}

	template<class AV_IF_IMPL>
	avif(boost::shared_ptr<AV_IF_IMPL> impl)
	{
		_impl.reset( new detail::avif_implement_wrapper<AV_IF_IMPL>(impl) );
	}

private:
	boost::shared_ptr<detail::avif_implement_interface> _impl;
};


// 这个是 TCP 协议的接口
// TODO, 使用 type-erasure 重新设计
// TODO 暂时使用继承模式
struct avtcpif
{
	avtcpif(boost::shared_ptr<boost::asio::ip::tcp::socket> client_sock, std::string local_addr, std::string remote_addr);

	std::string get_ifname()
	{
		return ifname;
	}

	RSA * get_rsa_key()
	{
		return _rsa;
	}

	// TODO 从 TCP 连接上读取一个 avPacket
	avim::proto::base::avPacket * async_read_packet(boost::asio::yield_context yield_context)
	{

	}

	// TODO 从 TCP 连接上写入一个 avPacket
    bool async_write_packet(avim::proto::base::avPacket*, boost::asio::yield_context yield_context)
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
	boost::shared_ptr<boost::asio::ip::tcp::socket> m_client_sock;
};
