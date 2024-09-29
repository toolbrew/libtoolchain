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
		/**
		 * @brief Encode byte array as base64 string.
		 * 
		 * @param[in] data Byte array to encode.
		 * @param[in] size Size of byte array @p data.
		 * 
		 * @return Converted byte array as base64 string.
		 * 
		 * @post String returned will be empty if the byte array cannot be encoded.
		 **/
	static std::string encodeDataAsBase64(const byte_t* data, size_t size);

		/**
		 * @brief Encode byte array as base64 string.
		 * 
		 * @param[in] data tc::ByteData containing byte array to encode.
		 * 
		 * @return Converted byte array as base64 string.
		 * 
		 * @post String returned will be empty if the byte array cannot be encoded.
		 **/
	static std::string encodeDataAsBase64(const tc::ByteData& data);

		/**
		 * @brief Encode string as base64 string.
		 * 
		 * @param[in] str String to encode.
		 * @param[in] size Size in bytes of string @p str.
		 * 
		 * @return Converted string as base64 string.
		 * 
		 * @post String returned will be empty if the string cannot be encoded.
		 **/
	static std::string encodeStringAsBase64(const char* str, size_t size);

		/**
		 * @brief Encode string as base64 string.
		 * 
		 * @param[in] str String to encode.
		 * 
		 * @return Converted string as base64 string.
		 * 
		 * @post String returned will be empty if the string cannot be encoded.
		 **/
	static std::string encodeStringAsBase64(const std::string& str);

		/**
		 * @brief Decode base64 string to bytes.
		 * 
		 * @param[in] str Base64 string to decode.
		 * @param[in] size Size of string @p str.
		 * 
		 * @return Converted base64 string as bytes.
		 * 
		 * @post String returned will be empty if the base64 string cannot be decoded.
		 **/
	static tc::ByteData decodeBase64AsData(const char* str, size_t size);

		/**
		 * @brief Decode base64 string to bytes.
		 * 
		 * @param[in] str Base64 string to decode.
		 * 
		 * @return Converted base64 string as bytes.
		 * 
		 * @post String returned will be empty if the base64 string cannot be decoded.
		 **/
	static tc::ByteData decodeBase64AsData(const std::string& str);
	
		/**
		 * @brief Decode base64 string to ASCII string.
		 * @note this is provided for completeness, and only supports ASCII strings
		 * 
		 * @param[in] str Base64 string to decode.
		 * @param[in] size Size of string @p str.
		 * 
		 * @return Converted base64 string as ASCII string.
		 * 
		 * @post String returned will be empty if the base64 string cannot be decoded.
		 **/
	static std::string decodeBase64AsString(const char* str, size_t size);

		/**
		 * @brief Decode base64 string to ASCII string.
		 * @note this is provided for completeness, and only supports ASCII strings
		 * 
		 * @param[in] str Base64 string to decode.
		 * 
		 * @return Converted base64 string as ASCII string.
		 * 
		 * @post String returned will be empty if the base64 string cannot be decoded.
		 **/
	static std::string decodeBase64AsString(const std::string& str);
};

}} // namespace tc::encode
