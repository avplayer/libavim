
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
		virtual proto::base::avAddress * if_address() = 0;

		virtual RSA * get_rsa_key() = 0;

		// 读取 av数据包
		virtual proto::base::avPacket * async_read_packet(boost::asio::yield_context yield_context) = 0;

		// 发送 av数据包
		virtual bool async_write_packet(proto::base::avPacket*, boost::asio::yield_context yield_context) = 0;
	};

	template<class RealImpl>
	struct avif_implement_wrapper : public avif_implement_interface
	{
		std::string get_ifname()
		{
			return _impl->get_ifname();
		};

		proto::base::avAddress * if_address()
		{
			return _impl->if_address();
		}


		RSA * get_rsa_key()
		{
			return _impl->get_rsa_key();
		}

		// 读取 av数据包
		proto::base::avPacket * async_read_packet(boost::asio::yield_context yield_context)
		{
			return _impl->async_read_packet(yield_context);
		}

		// 发送 av数据包
		bool async_write_packet(proto::base::avPacket* pkt, boost::asio::yield_context yield_context)
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

	proto::base::avAddress * if_address()
	{
		return _impl->if_address();
	}

	RSA * get_rsa_key()
	{
		return _impl->get_rsa_key();
	}

	// 读取 av数据包
	proto::base::avPacket * async_read_packet(boost::asio::yield_context yield_context)
	{
		return _impl->async_read_packet(yield_context);
	}

	// 发送 av数据包
	bool async_write_packet(proto::base::avPacket* pkt, boost::asio::yield_context yield_context)
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

// TODO 实现它！
static inline proto::base::avAddress av_address_from_string(std::string av_address)
{

}

// TODO 实现它
static inline std::string av_address_to_string(const proto::base::avAddress & addr)
{
	if(addr.has_resource())
	{
		return boost::str( boost::format("%s@%s/%s") % addr.username() % addr.domain() % addr.resource());
	}
	return boost::str( boost::format("%s@%s") % addr.username() % addr.domain() );
}

