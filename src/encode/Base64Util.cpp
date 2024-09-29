#include <tc/encode/Base64Util.h>

#include <fmt/core.h>

#include <mbedtls/base64.h>

inline std::string byteDataAsString(const tc::ByteData& data)
{
	if (data.size() == 0)
		return std::string();

	return std::string((char*)data.data(), data.size());
}

tc::ByteData tc::encode::Base64Util::encodeDataAsBase64Data(const byte_t* data, size_t size)
{
	if (data == nullptr && size != 0)
	{
		return tc::ByteData();
	}

	size_t enc_len = 0;

	mbedtls_base64_encode(nullptr, enc_len, &enc_len, data, size);

	tc::ByteData enc_data = tc::ByteData(enc_len);

	int mbedtls_ret = mbedtls_base64_encode(enc_data.data(), enc_data.size(), &enc_len, data, size);
	if (mbedtls_ret != 0)
		return tc::ByteData();

	return enc_data;
}

tc::ByteData tc::encode::Base64Util::encodeDataAsBase64Data(const tc::ByteData& data)
{
	return encodeDataAsBase64Data(data.data(), data.size());
}

std::string tc::encode::Base64Util::encodeDataAsBase64String(const byte_t* data, size_t size)
{
	return byteDataAsString(encodeDataAsBase64Data(data, size));
}
std::string tc::encode::Base64Util::encodeDataAsBase64String(const tc::ByteData& data)
{
	return encodeDataAsBase64String(data.data(), data.size());
}

tc::ByteData tc::encode::Base64Util::encodeStringAsBase64Data(const char* data, size_t size)
{
	return encodeDataAsBase64Data((const byte_t*)data, size);
}
tc::ByteData tc::encode::Base64Util::encodeStringAsBase64Data(const std::string& data)
{
	return encodeStringAsBase64Data(data.c_str(), data.size());
}

std::string tc::encode::Base64Util::encodeStringAsBase64String(const char* data, size_t size)
{
	return byteDataAsString(encodeStringAsBase64Data(data, size));
}
std::string tc::encode::Base64Util::encodeStringAsBase64String(const std::string& data)
{
	return byteDataAsString(encodeStringAsBase64Data(data));
}

tc::ByteData tc::encode::Base64Util::decodeBase64DataAsData(const byte_t* data, size_t size)
{
	if (data == nullptr && size != 0)
	{
		return tc::ByteData();
	}

	size_t dec_len = 0;

	mbedtls_base64_decode(nullptr, dec_len, &dec_len, data, size);

	tc::ByteData dec_data = tc::ByteData(dec_len);

	int mbedtls_ret = mbedtls_base64_decode(dec_data.data(), dec_data.size(), &dec_len, data, size);
	if (mbedtls_ret != 0)
		return tc::ByteData();

	return dec_data;
}
tc::ByteData tc::encode::Base64Util::decodeBase64DataAsData(const tc::ByteData& data)
{
	return decodeBase64DataAsData(data.data(), data.size());
}

std::string tc::encode::Base64Util::decodeBase64DataAsString(const byte_t* data, size_t size)
{
	return byteDataAsString(decodeBase64DataAsData(data, size));
}
std::string tc::encode::Base64Util::decodeBase64DataAsString(const tc::ByteData& data)
{
	return byteDataAsString(decodeBase64DataAsData(data));
}

tc::ByteData tc::encode::Base64Util::decodeBase64StringAsData(const char* data, size_t size)
{
	return decodeBase64DataAsData((const byte_t*)data, size);
}
tc::ByteData tc::encode::Base64Util::decodeBase64StringAsData(const std::string& data)
{
	return decodeBase64DataAsData((const byte_t*)data.c_str(), data.size());
}
	
std::string tc::encode::Base64Util::decodeBase64StringAsString(const char* data, size_t size)
{
	return byteDataAsString(decodeBase64DataAsData((const byte_t*)data, size));
}
std::string tc::encode::Base64Util::decodeBase64StringAsString(const std::string& data)
{
	return byteDataAsString(decodeBase64DataAsData((const byte_t*)data.c_str(), data.size()));
}