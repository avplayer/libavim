
#include <boost/bind.hpp>
#include <boost/thread.hpp>
#include <boost/atomic.hpp>
#include <boost/asio.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/make_shared.hpp>
#include <boost/regex.hpp>

#include <avif.hpp>
#include <avproto.hpp>

class avkernel;
namespace detail
{

class avkernel_impl : boost::noncopyable , public boost::enable_shared_from_this<avkernel_impl>
{
	boost::asio::io_service & io_service;

	// FIXME
	// TODO, 读取这个接口上的数据，然后转发数据！
	// 对每个 interface 执行的线程， 接收数据
	void interface_runner(avif avinterface, boost::asio::yield_context yield_context)
	{
		boost::system::error_code ec;

		for(;;)
		{
			// 读取一个数据包
			proto::base::avPacket * ret  = avinterface.async_read_packet(yield_context[ec]);

			// TODO 执行客户端校验

			// TODO 查找路由表

			// TODO 转发过去

			// TODO 找不到目的地址，就发回一个 目的地址不可达消息
		}

	}

	bool add_route(std::string targetAddress, std::string gateway, std::string ifname)
	{
		// TODO

		/*
		* 将目标地址添加到路由表  targetAddress 是正则表达式的
		*/
		boost::regex regex(targetAddress);
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

		avif interface = selectrouter(target);


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
		second_sign.resize(RSA_size(interface.get_rsa_key()) + data.length());
		second_sign.resize(RSA_private_encrypt(first_pubencode.length(), (uint8_t*) first_pubencode.data(),(uint8_t*) &second_sign[0], interface.get_rsa_key(), RSA_PKCS1_OAEP_PADDING));

		// 把加密后的数据写入avPacket
		avpkt.set_payload(second_sign);

		// 附上自己的 publickey
		std::string pubkey;
		pubkey.resize(BN_num_bytes(interface.get_rsa_key()->n));

		BN_bn2bin(interface.get_rsa_key()->n,(uint8_t*) &pubkey[0]);

		avpkt.set_publickey(pubkey);

		// TODO 添加其他

		interface.async_write_packet(&avpkt, yield_context[ec]);

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

	//
	avif selectrouter(std::string address)
	{
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
	boost::asio::spawn(io_service, boost::bind(&detail::avkernel_impl::interface_runner, _impl, avinterface, _1));
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
