
#include <boost/bind.hpp>
#include <boost/thread.hpp>
#include <boost/atomic.hpp>
#include <boost/asio.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/make_shared.hpp>
#include <boost/regex.hpp>

#include "avif.hpp"
#include "avproto.hpp"
#include "async_coro_queue.hpp"
#include "protocol/avim-base.pb.h"

class avkernel;
namespace detail
{

class avkernel_impl : boost::noncopyable , public boost::enable_shared_from_this<avkernel_impl>
{
	boost::asio::io_service & io_service;
	std::map<std::string, avif> m_avifs;
    typedef std::pair<boost::regex, std::string> RouteItem;
    std::vector<RouteItem> m_routes;

	// 移除接口的时候调用
	void remove_interface(std::string avifname)
	{
		// TODO 移除路由表上使用该接口的所有项目

		// TODO 移除 m_avifs 里相关条目
	}

	bool is_to_me(const proto::base::avAddress & addr)
	{
		// 遍历 interface 做比较
		for( const auto & i : m_avifs)
		{
			if(addr.username() == i.second.if_address()->username() &&
				addr.domain() == i.second.if_address()->domain()
			){
				return true;
			}
		}
		return false;
	}

	void process_recived_packet(boost::shared_ptr<proto::base::avPacket> avPacket, avif avinterface, boost::asio::yield_context yield_context)
	{
		// TODO 执行客户端校验
		if(avPacket->has_publickey())
		{
			// 有 pubkey ， 比较内部数据库里的记录
			// 如果和内部数据库的记录不一致
			// 要使用 avgmp 协议请求一份证书来校验一遍

			// 干这种事情的话，就需要开另外一个协程慢慢干了，呵呵
			// 因此加到 TODO 列表

			RSA * stored_key = find_RSA_pubkey(av_address_to_string(avPacket->src()));
			if( !stored_key )
			{
				// TODO, 执行 证书请求，并在请求通过后，接受该 key 并同时接受该数据包，
			}
		}

		// 查看据地地址，如果是自己，就交给上层

		if( is_to_me(avPacket->dest()) )
		{
			// TODO 挂入本地接收列队，等待上层读取
		}

		// TODO 查找路由表

		// TODO 转发过去

		// TODO 找不到目的地址，就发回一个 目的地址不可达消息

	}

	void interface_writer(avif avinterface, boost::asio::yield_context yield_context)
	{
		boost::system::error_code ec;

		for(; ! (* avinterface.quitting) ;)
		{
			std::pair<proto::base::avPacket*, boost::function<void(boost::system::error_code)>>
				popvalue = avinterface._write_queue->async_pop(yield_context);
			avinterface.async_write_packet(popvalue.first, yield_context[ec]);
			popvalue.second(ec);
		}
	}

	template<class RealHandler>
	void async_interface_write_packet_impl(avif * avinterface, proto::base::avPacket* avPacket, RealHandler handler)
	{
		std::pair<proto::base::avPacket*, boost::function<void(boost::system::error_code)> > value(
			avPacket,
			handler
		);

		avinterface->_write_queue->push(value);
	}

	void async_interface_write_packet(avif * avinterface, proto::base::avPacket* avPacket, boost::asio::yield_context handler)
	{
		using namespace boost::asio;

		boost::asio::detail::async_result_init<
			boost::asio::yield_context, void(boost::system::error_code)> init(
			BOOST_ASIO_MOVE_CAST(boost::asio::yield_context)(handler));

		async_interface_write_packet_impl<
			BOOST_ASIO_HANDLER_TYPE(boost::asio::yield_context, void(boost::system::error_code))
		>(avinterface, avPacket, init.handler);
		return init.result.get();
	}
	// FIXME
	// TODO, 读取这个接口上的数据，然后转发数据！
	// 对每个 interface 执行的线程， 接收数据
	void interface_runner(avif avinterface, boost::asio::yield_context yield_context)
	{
		boost::system::error_code ec;

		for(; ! (* avinterface.quitting) ;)
		{
			// 读取一个数据包
			boost::shared_ptr<proto::base::avPacket> avpkt;
			avpkt.reset(avinterface.async_read_packet(yield_context[ec]));

			if(avpkt)
			{
				// boost::asio::spawn(io_service, boost::bind(&avkernel_impl::process_recived_packet, shared_from_this(), avpkt, avinterface, _1));
				process_recived_packet(avpkt, avinterface, yield_context);
			}

			// 否则出错，删除该接口！

			// TODO
		}
	}

	void async_sendto_op(std::string target, std::string data, avkernel::SendReadyHandler handler, boost::asio::yield_context yield_context)
	{
		boost::system::error_code ec;
		/*
		*
		* 我来说一下算法, 首先根据路由表选定需要的 interface
		*
		* 接着寻找的加密用的公钥，如果本地的缓存没找到，就要首先发送一个 askpk 消息获取公钥
		*
		* 获取到公钥后，调用 RSA_public_encrypt 加密数据，再用
		* RSA_private_encrypt 加密，构建出 avPacket.
		* 然后再调用 interface->async_write_packet 将数据发送出去
		*/

		avif * interface = select_route(target);
		if( !interface )
		{
			ec = boost::asio::error::network_unreachable;
			// 返回 no route to host 错误
			handler(ec);
			return ;
		}

		RSA * target_pubkey = find_RSA_pubkey(target);

		if( ! target_pubkey )
		{
			// TODO 发送 askpk 消息获取共钥
			// TODO 如果配置了公钥服务器，尝试去公钥服务器获取
		}

		// TODO 构造 avPacket

		proto::base::avPacket avpkt;

		// 第一次加密
		std::string first_pubencode;
		first_pubencode.resize(RSA_size(target_pubkey) + data.length());
		first_pubencode.resize(RSA_public_encrypt(data.length(), (uint8_t*) data.data(),(uint8_t*) &first_pubencode[0], target_pubkey, RSA_PKCS1_OAEP_PADDING));

		// 第二次签名
		std::string second_sign;
		second_sign.resize(RSA_size(interface->get_rsa_key()) + data.length());
		second_sign.resize(RSA_private_encrypt(first_pubencode.length(), (uint8_t*) first_pubencode.data(),(uint8_t*) &second_sign[0], interface->get_rsa_key(), RSA_PKCS1_OAEP_PADDING));

		// 把加密后的数据写入avPacket
		avpkt.set_payload(second_sign);

		// 附上自己的 publickey
		std::string pubkey;
		pubkey.resize(BN_num_bytes(interface->get_rsa_key()->n));

		BN_bn2bin(interface->get_rsa_key()->n,(uint8_t*) &pubkey[0]);

		avpkt.set_publickey(pubkey);
		avpkt.mutable_src()->CopyFrom( av_address_from_string(target) );
		avpkt.mutable_src()->CopyFrom( *interface->if_address() );
		avpkt.set_upperlayerpotocol("avim");

		// TODO 添加其他

		// 添入发送列队
		async_interface_write_packet(interface, &avpkt, yield_context[ec]);

		// 做完成通知
		handler(ec);
	}

	void async_sendto(std::string target, std::string data, avkernel::SendReadyHandler handler)
	{
		boost::asio::spawn(io_service, boost::bind(&avkernel_impl::async_sendto_op, shared_from_this(), target, data, handler, _1 ));
	}

	int sendto(std::string target, std::string data)
	{
		boost::system::error_code ec;
		boost::atomic_bool done;
		done = false;

		async_sendto(target, data, [&ec, &done](const boost::system::error_code & _ec)
			{ ec = _ec; done = true;});

		while( ! done )
		{
			int ret = io_service.run_one();
			BOOST_ASSERT(ret != 0 );
		}
		return ec.value();
	}

	// 从本地数据找 RSA 公钥，找不到就返回 NULL , 让 agmp 协议其作用
	RSA * find_RSA_pubkey(std::string address)
	{
	}

	// TODO
	avif * select_route(std::string address)
	{
        if(m_avifs.empty())
        {
            return nullptr;
        }
        for(const auto& route : m_routes)
        {
            if(boost::regex_match(address, route.first))
            {
                return &m_avifs.at(route.second);
            }
        }
        return &m_avifs.begin()->second;
	}

	// TODO
	bool add_route(std::string targetAddress, std::string gateway, std::string ifname)
	{
		/*
		* 将目标地址添加到路由表  targetAddress 是正则表达式的
		*/
        assert(m_avifs.count(ifname) > 0);
        m_routes.emplace_back(boost::regex(targetAddress), ifname);
	}

public:
	avkernel_impl(boost::asio::io_service & _io_service)
		: io_service(_io_service)
	{
	}

	friend avkernel;
};

}

avkernel::avkernel(boost::asio::io_service & _io_service)
	: io_service(_io_service)
{
	_impl = boost::make_shared<detail::avkernel_impl>(boost::ref(io_service));
}

bool avkernel::add_interface(avif avinterface)
{
	_impl->m_avifs.insert(std::make_pair(avinterface.get_ifname(), avinterface));
	boost::asio::spawn(io_service, boost::bind(&detail::avkernel_impl::interface_runner, _impl, avinterface, _1));
	boost::asio::spawn(io_service, boost::bind(&detail::avkernel_impl::interface_writer, _impl, avinterface, _1));
	return true;
}

bool avkernel::add_route(std::string targetAddress, std::string gateway, std::string ifname)
{
	return _impl->add_route(targetAddress, gateway, ifname);
}

int avkernel::sendto(std::string target, std::string data)
{
	return _impl->sendto(target, data);
}
