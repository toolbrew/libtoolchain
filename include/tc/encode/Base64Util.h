	/**
	 * @file Base64Util.h
	 * @brief Declaration of tc::encode::Base64Util
	 * @author Jack (jakcron)
	 * @version 0.1
	 * @date 2024/09/29
	 **/
#pragma once
#include <tc/types.h>
#include <tc/ByteData.h>

namespace tc { namespace encode {

	/**
	 * @class Base64Util
	 * @brief A collection of utilities to encode/decode binary data/strings to base64 and vice-versa.
	 **/
class Base64Util
{
public:
	static std::string encodeDataAsBase64(const byte_t* data, size_t size);
	static std::string encodeDataAsBase64(const tc::ByteData& data);

	static std::string encodeStringAsBase64(const char* data, size_t size);
	static std::string encodeStringAsBase64(const std::string& data);

	static tc::ByteData decodeBase64AsData(const char* data, size_t size);
	static tc::ByteData decodeBase64AsData(const std::string& data);
	
	static std::string decodeBase64AsString(const char* data, size_t size);
	static std::string decodeBase64AsString(const std::string& data);
};

}} // namespace tc::encode
