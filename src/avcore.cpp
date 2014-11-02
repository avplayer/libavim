
#include <boost/bind.hpp>
#include <boost/thread.hpp>
#include <boost/asio.hpp>

#include <avif.hpp>
#include <avproto.hpp>

static boost::asio::io_service * av_service = NULL;

int avtcpif::ifcount = 0;

// avif 接口列表，通过 avif 名字查找
std::map<std::string, boost::shared_ptr<avif> > avif_list;

std::map<std::string, avif*> route_table;
avif * default_router ;

void av_start(boost::asio::io_service * _av_service)
{
	av_service = _av_service;
}

static void remove_av_interface(std::string ifname)
{
	avif_list.erase(ifname);
}


// FIXME
// TODO, 读取这个接口上的数据，然后转发数据！
static void interface_runner(boost::asio::yield_context yield_context, boost::shared_ptr<avif> avinterface)
{
	boost::system::error_code ec;

	for(;;)
	{
		// 读取一个数据包
		avim::proto::base::avPacket * ret  = avinterface->async_read_packet(yield_context[ec]);

		// TODO 执行客户端校验

		// TODO 查找路由表

		// TODO 转发过去

		// TODO 找不到目的地址，就发回一个 目的地址不可达消息
	}


}

// 向 av协议移交 接口 层！
avif * av_if_handover(boost::shared_ptr<avif> avinterface)
{
	avif_list.insert( std::make_pair(avinterface->get_ifname(), avinterface) );

	avinterface->set_remove_from_av(remove_av_interface);

	// 开启为这个接口建立的循环！
	boost::asio::spawn(*av_service, boost::bind(&interface_runner, _1, avinterface));

	return avinterface.get();
}

// 向路由表添加
bool av_route(av_route_op op /*add mod del*/, std::string addr, std::string gateway, std::string interfacename)
{
	// FIXME 完善路由表信息

	// TODO 删除功能
	if(op == AVROUTE_ADD)
	{
		// 接口不存在
		if( avif_list.find(interfacename) == avif_list.end())
			return false;

		if(addr == "*")
		{
			// 添加默认路由表
			default_router = avif_list.find(interfacename)->second.get();
			return true;
		}

		// 已经存在
		if( route_table.find(addr) != route_table.end())
			return false;

		route_table.insert(std::make_pair(addr, avif_list.find(interfacename)->second.get()));
		return true;
	}
}

// TODO, 实现发送过程，通过查找路由表实现
bool av_sendto(std::string dest_address, std::string message)
{
	return false;
}
