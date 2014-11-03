
#include <boost/bind.hpp>
#include <boost/thread.hpp>
#include <boost/asio.hpp>
#include <boost/atomic.hpp>

#include <avtcpif.hpp>
#include <avproto.hpp>

static  boost::atomic<uint64_t> ifcounts;// = 0ul;

std::string avtcpif::allocate_ifname()
{
	return boost::str( boost::format("avif_tcp%1") % ifcounts ++ );
}

avtcpif::avtcpif(boost::shared_ptr<boost::asio::ip::tcp::socket> _sock, std::string local_addr, RSA * _key)
{
	m_sock = _sock;
	ifname = allocate_ifname();
}

// TODO
bool avtcpif::async_master_handshake(bool as_master, boost::asio::yield_context yield_context)
{
	boost::system::error_code ec;
	// 接收用户的 av地址
	int len = boost::asio::async_read_until(*m_sock, m_recv_buf, "\r\n", yield_context[ec]);

	if( ec)
		return false;

	std::string useraddr; useraddr.resize(len);

	m_recv_buf.sgetn(&useraddr[0], len);

	// 返回服务器地址
	boost::asio::async_write(*m_sock, boost::asio::buffer(m_local_addr_str), yield_context[ec]);
	if( ec )
		return false;
}

// TODO
bool avtcpif::slave_handshake(bool as_master)
{
	boost::asio::write(*m_sock, boost::asio::buffer(m_local_addr_str));

	std::string serveraddr;

	boost::asio::streambuf buf;

	int len = boost::asio::read_until(*m_sock, buf, "\r\n");
	serveraddr.resize(len);

	buf.sgetn(&serveraddr[0], len);
}


std::string avtcpif::remote_addr()
{
	return m_remote_addr_str;
}

