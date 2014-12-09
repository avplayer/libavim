#pragma once
/*
 * 这个文件决定了 avpakcet->payload 里面的数据的解释格式
 */
#include <string>
#include <cstdint>
#include <exception>
#include <memory>
#include "im.pb.h"

struct im_decode_error : std::runtime_error
{
    explicit im_decode_error(int t, const std::string& __arg)
		: std::runtime_error(__arg), error_code(t){}

	int error_code;
};

struct im_message{
	bool is_encrypted_message;
	bool is_group_message;

	std::string sender;
	message::message_packet impkt;
};


// 检测是否经过了对称密钥的加密, 并返回加密key的 ID
// 返回 0 表示木加密

std::uint32_t is_encrypted_message(const std::string& payload);

// 看消息发送方是不是很自觉的把 sender 填入,否则不予转发.
std::string group_message_get_sender(const std::string& payload);

// 如果是控制消息, 请在 payload[1] 这个位置到最后取出 substr 直接调用 av_proto::decode()
bool is_control_message(const std::string& payload);

im_message decode_im_message(const std::string& payload);
std::string encode_im_message(const message::message_packet&);


// 解码用的 key 是个 base64 编码的字符串. 加密类型和加密密钥都在里面. 这个 key 字符串由管理员在你进群的时候发送过来
im_message decode_im_message(const std::string& encryption_key, const std::string& payload);

// 序列化群消息以便 avkernel.send 使用
// 如果群管理员决定不加密, 那么 encryption_key 为空即可
std::string encode_group_message(const std::string& sender, const std::string& encryption_key, uint32_t keyid, const message::message_packet&);

// 从 payload 里解码出非 im_message 消息.
std::shared_ptr<google::protobuf::Message> decode_control_message(const std::string payload, std::string& sender /*out*/);

// 序列化控制消息, 以便 avkernel.send 使用
std::string encode_control_message(const std::string& sender, const google::protobuf::Message&);
// 简化版, 协议里无需带上 sender 的时候使用
std::string encode_control_message(const google::protobuf::Message&);
