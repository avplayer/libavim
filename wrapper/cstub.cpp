
#include "avproto.h"
#include <boost/bind.hpp>
#include <boost/thread.hpp>
#include <boost/asio.hpp>

#include <avproto.hpp>
#include <avproto/easyssl.hpp>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

/*
 * 这个文件提供的是 C 接口，如果使用 C++，强烈的建议使用 aiso 和 C++ 接口！也就是直接使用 avkernel 对象！
 *
 */

static boost::asio::io_service * av_service;
static avkernel * avkernel_intance;
static std::thread * avkernelthread;

static void create_avkernel_instance()
{
	av_service = new boost::asio::io_service;
	avkernel_intance = new avkernel(*av_service);

	avkernelthread = new std::thread(std::bind(&boost::asio::io_service::run, av_service));
}

void av_start()
{
	static boost::once_flag onceflag;
	boost::call_once(onceflag, create_avkernel_instance);
}

void av_stop()
{
	av_service->stop();
	avkernelthread->join();
	delete avkernel_intance;
	delete av_service;
	delete avkernelthread;
}

// FIXME 添加错误处理
int connect_to_avrouter(const char * keyfilename, const char * certfilename, const char * self_addr, const char * host, const char * port)
{
	std::shared_ptr<RSA> rsa_key = load_RSA_from_file(keyfilename);
	std::shared_ptr<X509>x509_cert = load_X509_from_file(certfilename);

	if(!rsa_key)
	{
		std::cerr << "can not open avim.key" << std::endl;
		exit(1);
	}

	if(!x509_cert)
	{
		std::cerr << "can not open avim.crt" << std::endl;
		exit(1);
	}

	// 构造 avtcpif
	// 创建一个 tcp 的 avif 设备，然后添加进去
	std::shared_ptr<avjackif> avinterface(new avjackif(*av_service));

	avinterface->set_pki(rsa_key, x509_cert);

	std::atomic< int > ret;
	ret = -1;
	boost::mutex m;
	boost::condition_variable ready;
	boost::unique_lock<boost::mutex> l(m);
	boost::asio::spawn(*av_service, [&](boost::asio::yield_context yield_context)
	{
		if( avinterface->async_connect(host, port, yield_context))
			if(	avinterface->async_handshake(yield_context))
			{
				if(avkernel_intance->add_interface(avinterface))
				{
					std::string me_addr = av_address_to_string(*avinterface->if_address());
					if (avkernel_intance->add_route(".*@.*", me_addr, avinterface->get_ifname(), 100));
						ret = 0;
				}
			}

		ready.notify_all();
	});
	ready.wait(l);
	return ret;
}

int av_sendto(const char * dest_address, const char * message, int len)
{
	return avkernel_intance->sendto(dest_address, std::string(message, len));
}

int av_recvfrom(char* dest_address, char* message, int* len)
{
	std::string dest, msg;
	auto ret = avkernel_intance->recvfrom(dest, msg);
	strcpy(dest_address, dest.c_str());
	BOOST_ASSERT( *len >= msg.length());
	*len = msg.length();
	memcpy(message, msg.c_str(), msg.length());
	return ret;
}
