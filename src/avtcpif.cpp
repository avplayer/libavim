
#include <boost/shared_ptr.hpp>
#include <boost/scoped_ptr.hpp>
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

avtcpif::avtcpif(boost::shared_ptr<boost::asio::ip::tcp::socket> _sock, std::string local_addr, RSA * _key, X509 *)
{
	m_sock = _sock;
	ifname = allocate_ifname();
}

// TODO
bool avtcpif::async_master_handshake(bool as_master, boost::asio::yield_context yield_context)
{
	boost::uint32_t l;
	boost::system::error_code ec;
	// 接收用户的 av地址
	int len = boost::asio::async_read(*m_sock, boost::asio::buffer(&l, sizeof(l)), yield_context[ec]);

	if( len != sizeof(l))
		return false;

	len = boost::asio::async_read(*m_sock, m_recv_buf, boost::asio::transfer_exactly(ntohl(l)), yield_context[ec]);

	std::istream inputstream(&m_recv_buf);

	boost::scoped_ptr<proto::base::avTCPPacket> pkt(new proto::base::avTCPPacket);

	pkt->ParseFromIstream(&inputstream);

	if(pkt->type() != 1)
		return false;

	m_remote_addr = pkt->endpoint_address();

	// TODO 检查证书

	* pkt->mutable_endpoint_address() = m_local_addr;

	pkt->clear_endpoint_cert();

	std::ostream outstream(&m_send_buf);

	pkt->SerializeToOstream(&outstream);

	// 返回服务器地址

	l = htonl(m_send_buf.size());

	boost::asio::async_write(*m_sock, boost::asio::buffer(&l, sizeof(l)), yield_context[ec]);

	boost::asio::async_write(*m_sock, m_send_buf, boost::asio::transfer_all(), yield_context[ec]);

	return !ec;
}

// TODO
bool avtcpif::slave_handshake(bool as_master)
{
	boost::uint32_t l;
	std::ostream outstream(&m_send_buf);
	boost::system::error_code ec;

	boost::scoped_ptr<proto::base::avTCPPacket> pkt(new proto::base::avTCPPacket);
	pkt->set_type(1);

	* pkt->mutable_endpoint_address() = m_local_addr;
	pkt->SerializeToOstream(&outstream);

	// 返回服务器地址

	l = htonl(m_send_buf.size());

	boost::asio::write(*m_sock, boost::asio::buffer(&l, sizeof(l)));

	boost::asio::write(*m_sock, m_send_buf, boost::asio::transfer_all());

	int len = boost::asio::read(*m_sock, boost::asio::buffer(&l, sizeof(l)));

	if( len != sizeof(l))
		return false;

	len = boost::asio::read(*m_sock, m_recv_buf, boost::asio::transfer_exactly(ntohl(l)));

	std::istream inputstream(&m_recv_buf);

	pkt->Clear();
	pkt->ParseFromIstream(&inputstream);

	if(pkt->type() != 1)
		return false;

	m_remote_addr = pkt->endpoint_address();

	// TODO 检查证书

	return true;
}

std::string avtcpif::remote_addr()
{
	return m_remote_addr.username() + "@" + m_remote_addr.domain();
}

