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
	static tc::ByteData encodeDataAsBase64Data(const byte_t* data, size_t size);
	static tc::ByteData encodeDataAsBase64Data(const tc::ByteData& data);

	static std::string encodeDataAsBase64String(const byte_t* data, size_t size);
	static std::string encodeDataAsBase64String(const tc::ByteData& data);

	static tc::ByteData encodeStringAsBase64Data(const char* data, size_t size);
	static tc::ByteData encodeStringAsBase64Data(const std::string& data);

	static std::string encodeStringAsBase64String(const char* data, size_t size);
	static std::string encodeStringAsBase64String(const std::string& data);

	static tc::ByteData decodeBase64DataAsData(const byte_t* data, size_t size);
	static tc::ByteData decodeBase64DataAsData(const tc::ByteData& data);

	static std::string decodeBase64DataAsString(const byte_t* data, size_t size);
	static std::string decodeBase64DataAsString(const tc::ByteData& data);

	static tc::ByteData decodeBase64StringAsData(const char* data, size_t size);
	static tc::ByteData decodeBase64StringAsData(const std::string& data);
	
	static std::string decodeBase64StringAsString(const char* data, size_t size);
	static std::string decodeBase64StringAsString(const std::string& data);
private:
};

}} // namespace tc::encode
