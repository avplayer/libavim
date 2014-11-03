
#include <boost/bind.hpp>
#include <boost/thread.hpp>
#include <boost/asio.hpp>

#include <avif.hpp>
#include <avproto.hpp>

/*
 * 这个文件提供的是 C 接口，如果使用 C++，强烈的建议使用 aiso 和 C++ 接口！也就是直接使用 avkernel 对象！
 *
 */

static boost::asio::io_service * av_service;
static avkernel * avkernel_intance;

static void create_avkernel_instance()
{
	av_service = new boost::asio::io_service;
	avkernel_intance = new avkernel(*av_service);
}

void av_start()
{
	static boost::once_flag onceflag;
	boost::call_once(onceflag, create_avkernel_instance);
}
