#include "avproto/message.hpp"

#include "avproto/serialization.hpp"
#include <boost/asio.hpp>

enum message_header_type_indicator {
	TPYE_ENCRYPTED = 0x01,
	TPYE_GROUP = 0x10,
	// 发送者的地址也包进去, 供校验用, 可选
	TPYE_HAS_SENDER = 0x20,
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

	return type & TPYE_GROUP;
}

bool is_plain_message(const std::string& payload)
{
	unsigned char type = *((unsigned char*)payload.data());
	return type == 0;
}

std::uint32_t is_encrypted_message(const std::string& payload)
{
	unsigned char type = *((unsigned char*)payload.data());
	if (type & TPYE_ENCRYPTED)
		return ntohl(*reinterpret_cast<const uint32_t*>(payload.data()+1));
	else
		return 0;
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
	unsigned char type = *((unsigned char*)payload.data());

	switch (type & TPYE_ENCRYPTED)
	{
		offset +=4;
		throw im_decode_error(0, "encrypted message");
	}

	if (type & 0xF0)
	{
		// 非聊天消息
	}

	ret.is_control_message = false;
	ret.is_message = true;

	if (!ret.impkt.ParseFromArray(payload.data()+offset, payload.length()-1))
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

std::string encode_group_message(const std::string& sender, const std::string& encryption_key, const message::message_packet& pkt)
{
	std::string ret;

	unsigned char type = TPYE_GROUP;

	if (!sender.empty())
	{
		type |= TPYE_HAS_SENDER;
	}

	if (!encryption_key.empty())
	{
		type |= TPYE_ENCRYPTED;
	}

	ret.push_back(*reinterpret_cast<char*>(&type));

	if (!sender.empty())
	{
		unsigned char len = sender.length();
		ret.push_back(*reinterpret_cast<char*>(&len));
		ret.append(sender, 0, sender.length());
	}

	pkt.SerializeToString(&ret);
	return ret;
}

std::shared_ptr<google::protobuf::Message> decode_control_message(const std::string payload)
{
	BOOST_ASSERT(is_group_message(payload));
	unsigned char type = *(unsigned char*)payload.data();

	BOOST_ASSERT((type&TPYE_HAS_SENDER) == 0);

	return std::shared_ptr<google::protobuf::Message>(av_proto::decode(payload.substr(1)));
}

std::string encode_control_message(const std::string& sender, const google::protobuf::Message& msg)
{
	BOOST_ASSERT(sender.length() < 256);

	std::string ret;
	unsigned char type = TYPE_CONTROL_MESSAGE | (sender.empty() ? 0:TPYE_HAS_SENDER);
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
