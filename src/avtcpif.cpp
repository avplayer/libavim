
#include <boost/bind.hpp>
#include <boost/thread.hpp>
#include <boost/asio.hpp>
#include <boost/atomic.hpp>

#include <avif.hpp>
#include <avproto.hpp>

static  boost::atomic<uint64_t> ifcounts;// = 0ul;

std::string avtcpif::allocate_ifname()
{
	return boost::str( boost::format("avif_tcp%1") % ifcounts ++ );
}

avtcpif::avtcpif(boost::shared_ptr<boost::asio::ip::tcp::socket> client_sock, std::string local_addr, std::string remote_addr)
{
	m_client_sock = client_sock;
	ifname = allocate_ifname();
}

