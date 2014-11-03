
#include <boost/bind.hpp>
#include <boost/thread.hpp>
#include <boost/asio.hpp>
#include <boost/regex.hpp>

#include <avif.hpp>
#include <avproto.hpp>

class avkernel;
namespace detail
{

class avkernel_impl : boost::noncopyable
{
	boost::asio::io_service & io_service;

	avkernel_impl(boost::asio::io_service & _io_service)
		: io_service(_io_service)
	{
	}

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

	int sendto(std::string target, std::string data)
	{
		// TODO
		/*
		*
		* 我来说一下算法, 首先根据路由表选定需要的 interface
		*
		* 接着寻找的加密用的公钥，如果本地的缓存没找到，就要首先发送一个 askpk 消息获取公钥
		*
		* 获取到公钥后，调用 RSA_public_encrypt 加密数据，构建 avPacket.
		* 然后再调用 interface->async_write_packet 将数据发送出去
		*/
	}


	friend avkernel;
};

}

avkernel::avkernel(boost::asio::io_service & _io_service)
	: io_service(_io_service)
{
	_impl.reset(new detail::avkernel_impl(io_service));
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
