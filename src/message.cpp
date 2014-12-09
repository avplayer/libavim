#include "avproto/message.hpp"

#include "avproto/serialization.hpp"
#include <boost/asio.hpp>

enum message_header_type_indicator {
	// 表明消息加密了, 通常意味着是个 group 消息
	// 加密的消息一定是 group 消息, 而 group 消息不一定加密
	TYPE_ENCRYPTED = 0x01,
	// 表明消息是群消息格式, 需要使用 decode_group_message 解码
	TYPE_GROUP = 0x10,
	// 发送者的地址也包进去, 供校验用, 可选
	TYPE_HAS_SENDER = 0x20,
	// 表明是控制消息, 而非聊天消息
	// 用于和机器人沟通群管理
	TYPE_CONTROL_MESSAGE = 0x40,
};

bool is_control_message(const std::string& payload)
{
	unsigned char type = *((unsigned char*)payload.data());

	return type & TYPE_CONTROL_MESSAGE;
}

bool is_group_message(const std::string& payload)
{
	unsigned char type = *((unsigned char*)payload.data());

	return type & TYPE_GROUP;
}

bool is_plain_message(const std::string& payload)
{
	unsigned char type = *((unsigned char*)payload.data());
	return type == 0;
}

std::uint32_t is_encrypted_message(const std::string& payload)
{
	unsigned char type = *((unsigned char*)payload.data());
	if (type & TYPE_ENCRYPTED)
		return ntohl(*reinterpret_cast<const uint32_t*>(payload.data()+1));
	else
		return 0;
}

std::string group_message_get_sender(const std::string& payload)
{
	unsigned char type = *((unsigned char*)payload.data());

	if (type& TYPE_HAS_SENDER)
	{
		int len = *((unsigned char*)(payload.data()+1));
		return payload.substr(2, len);
	}
	return "";
}

/*
 * 第一个字节告诉你包有没有加密, 是不是群消息, 有没有把发送人的 av 地址重复放进去
 */

im_message decode_im_message(const std::string& payload)
{
	im_message ret;
	ret.is_encrypted_message = false;
	int offset = 1;

	// payload 的第一个字节表示消息是否加密, 有的话, 返回失败, 必须使用对称加密的密钥解开
	unsigned char type = *reinterpret_cast<const unsigned char*>(payload.data());
	ret.is_group_message = type & TYPE_GROUP;

	switch (type & TYPE_ENCRYPTED)
	{
		offset +=4;
		throw im_decode_error(0, "encrypted message");
	}


	if (type & TYPE_HAS_SENDER)
	{
		// 非聊天消息
		offset ++;
		auto name_len = * reinterpret_cast<const unsigned char*>(payload.data()+1);
		ret.sender = payload.substr(offset, name_len);
		offset += name_len;
	}

	ret.is_control_message = false;
	ret.is_message = true;

	if (!ret.impkt.ParseFromString(payload.substr(offset)))
	{
		throw im_decode_error(1, "protobuf decode error");
	}
	return ret;
}

std::string encode_im_message(const message::message_packet& pkt)
{
	std::string ret;
	ret.push_back((char)0);


	if (!pkt.AppendToString(&ret))
	{
		throw im_decode_error(2, "protobuf decode error");
	}
	return ret;
}

std::string encode_group_message(const std::string& sender, const std::string& encryption_key, uint32_t keyid, const message::message_packet& pkt)
{
	std::string ret;

	unsigned char type = TYPE_GROUP;

	if (!sender.empty())
	{
		type |= TYPE_HAS_SENDER;
	}

	if (!encryption_key.empty())
	{
		type |= TYPE_ENCRYPTED;
	}

	ret.push_back(*reinterpret_cast<char*>(&type));

	if (!encryption_key.empty())
	{
		uint32_t net_byteorder_keyid = htonl(keyid);
		ret.append(reinterpret_cast<const char*>(&net_byteorder_keyid), 4);
	}

	if (!sender.empty())
	{
		unsigned char len = sender.length();
		ret.push_back(*reinterpret_cast<char*>(&len));
		ret.append(sender, 0, sender.length());
	}

	pkt.SerializeToString(&ret);
	return ret;
}

std::shared_ptr<google::protobuf::Message> decode_control_message(const std::string payload, std::string& sender)
{
	BOOST_ASSERT(is_control_message(payload));

	unsigned char type = *(unsigned char*)payload.data();

	size_t offset = 1;

	if (type & TYPE_HAS_SENDER)
	{
		offset ++;
		auto name_len = * reinterpret_cast<const unsigned char*>(payload.data()+1);
		sender = payload.substr(offset, name_len);
		offset += name_len;
	}

	return std::shared_ptr<google::protobuf::Message>(av_proto::decode(payload.substr(offset)));
}


std::string encode_control_message(const std::string& sender, const google::protobuf::Message& msg)
{
	BOOST_ASSERT(sender.length() < 256);

	std::string ret;
	unsigned char type = TYPE_CONTROL_MESSAGE | (sender.empty() ? 0:TYPE_HAS_SENDER);
	ret.append(1, (char) type);

	if (!sender.empty())
	{
		unsigned char len = sender.length();
		ret.push_back(*reinterpret_cast<char*>(&len));
		ret.append(sender, 0, sender.length());
	}
	// append 类型
	ret.append(av_proto::encode(msg));
	return ret;
}

std::string encode_control_message(const google::protobuf::Message& msg)
{
	return encode_control_message(std::string(), msg);
}
