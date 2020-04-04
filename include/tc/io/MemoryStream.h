	/**
	 * @file MemoryStream.h
	 * @brief Declaration of tc::io::MemoryStream
	 * @author Jack (jakcron)
	 * @version	0.1
	 * @date 2020/02/16
	 **/
#pragma once
#include <tc/io/IStream.h>
#include <tc/ByteData.h>

#include <tc/ArgumentNullException.h>
#include <tc/ArgumentOutOfRangeException.h>

#ifdef _WIN32
#include <Windows.h>
#else
#include <cstdio>
#endif

namespace tc { namespace io {

	/**
	 * @class MemoryStream
	 * @brief A block of run-time memory wrapped as an IStream object. 
	 **/
class MemoryStream : public tc::io::IStream
{
public:
		/** 
		 * @brief Default constuctor
		 **/
	MemoryStream();

		/**
		 * @brief Create MemoryStream
		 * 
		 * @param[in] length Length of the stream in bytes.
		 **/
	MemoryStream(size_t length);

		/** 
		 * @brief Create MemoryStream from a tc::ByteData object.
		 * 
		 * @param[in] byte_data The base data to create the MemoryStream from.
		 **/
	MemoryStream(const tc::ByteData& byte_data);

		/** 
		 * @brief Create MemoryStream from a memory pointer.
		 * 
		 * @param[in] data Pointer to memory which will populate this MemoryStream.
		 * @param[in] len Length of data to copy int this MemoryStream.
		 **/
	MemoryStream(const byte_t* data, size_t len);

	bool canRead() const;
	bool canWrite() const;
	bool canSeek() const;

		/**
		 * @brief Gets the length in bytes of the stream.
		 **/
	int64_t length();

		/** 
		 * @brief Gets the position within the current stream.
		 **/
	int64_t position();

		/**
		 * @brief Reads a sequence of bytes from the current stream and advances the position within the stream by the number of bytes read.
		 * 
		 * @param[out] buffer An array of bytes. When this method returns, the buffer contains the specified byte array with the values between 0 and (@p count - 1) replaced by the bytes read from the current source.
		 * @param[in] count The maximum number of bytes to be read from the current stream.
		 * 
		 * @return The total number of bytes read into the buffer. This can be less than the number of bytes requested if that many bytes are not currently available, or zero (0) if the end of the stream has been reached.
		 * 
		 * @throw tc::ArgumentNullException @p buffer is @a nullptr.
		 **/
	size_t read(byte_t* buffer, size_t count);

		/**
		 * @brief Writes a sequence of bytes to the current stream and advances the current position within this stream by the number of bytes written.
		 * 
		 * @param[in] buffer An array of bytes. This method copies count bytes from buffer to the current stream.
		 * @param[in] count The number of bytes to be written to the current stream.
		 * 
		 * @throw tc::ArgumentNullException @p buffer is @a nullptr.
		 * @throw tc::ArgumentOutOfRangeException @p count is too large.
		 **/
	void write(const byte_t* buffer, size_t count);

		/**
		 * @brief Sets the position within the current stream.
		 * 
		 * @param[in] offset A byte offset relative to the origin parameter.
		 * @param[in] origin A value of type @ref tc::io::SeekOrigin indicating the reference point used to obtain the new position.
		 * 
		 * @return The new position within the current stream.
		 * 
		 * @throw tc::ArgumentOutOfRangeException @p offset and @p origin indicate an invalid stream position.
		 * @throw tc::ArgumentOutOfRangeException @p origin contains an invalid value.
		 **/
	int64_t seek(int64_t offset, SeekOrigin origin);


		/**
		 * @brief Sets the length of the current stream.
		 * 
		 * @param[in] length The desired length of the current stream in bytes.
		 * 
		 * @post If the new length is smaller than the current length, the data will be truncated.
		 * 
		 * @throw tc::ArgumentOutOfRangeException @p length exceeds the maximum possible value for a MemoryStream.
		 * @throw tc::ArgumentOutOfRangeException @p length is negative.
		 **/
	void setLength(int64_t length);

		/**
		 * @brief This does nothing for tc::io::MemoryStream
		 **/
	void flush();

		/**
		 * @brief Release internal memory. This will make this stream length 0.
		 **/
	void dispose();
private:
	static const std::string kClassName;

	tc::ByteData mData;
	std::shared_ptr<int64_t> mPosition;
};

}} // namespace tc::io