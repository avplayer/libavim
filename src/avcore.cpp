
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

void av_start(boost::asio::io_service * _av_service)
{
	av_service = _av_service;
}

// 向 av协议移交 接口 层！
avif * av_if_handover(boost::shared_ptr<avif> avinterface)
{
	avif_list.insert( std::make_pair(avinterface->get_ifname(), avinterface) );
	return avinterface.get();
}

bool av_route(int op /*add mod del*/, std::string addr, std::string gateway, std::string interfacename)
{

}

