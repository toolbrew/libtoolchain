	/**
	 * @file SubSink.h
	 * @brief Declaration of tc::io::SubSink
	 * @author Jack (jakcron)
	 * @version 0.1
	 * @date 2020/02/08
	 **/
#pragma once
#include <tc/io/ISink.h>

#include <tc/ArgumentNullException.h>
#include <tc/ArgumentOutOfRangeException.h>
#include <tc/OutOfMemoryException.h>
#include <tc/ObjectDisposedException.h>

namespace tc { namespace io {

	/**
	 * @class SubSink
	 * @brief A ISink that exposes a subset of a base ISink.
	 **/
class SubSink : tc::io::ISink
{
public:
		/**
		 * @brief Default constructor
		 * @post This will create an unusable SubSink, it will have to be assigned from a valid SubSink object to be usable.
		 **/ 
	SubSink();

		/** 
		 * @brief Create SubSink
		 * 
		 * @param[in] sink The base ISink object which this sub sink will derive from.
		 * @param[in] offset The zero-based byte offset in sink at which to begin the sub sink.
		 * @param[in] length Length of the sub sink.
		 * 
		 * @pre The sub sink must be a subset of the base sink.
		 * 
		 * @throw tc::ArgumentNullException @p sink is a @p nullptr.
		 * @throw tc::ArgumentOutOfRangeException @p offset or @p length is negative or otherwise invalid given the length of the base sink.
		 **/
	SubSink(const std::shared_ptr<tc::io::ISink>& sink, int64_t offset, int64_t length);

		/// Gets the length of the sink.
	int64_t length();

		/**
		 * @brief Sets the length of the sink.
		 * 
		 * @param[in] length The desired length of the sink in bytes.
		 * 
		 * @throw tc::ObjectDisposedException The base sink was not initialised.
		 **/
	void setLength(int64_t length);

		/**
		 * @brief Push data to the sink.
		 * 
		 * @param[in] data Data to be pushed to the sink.
		 * @param[in] offset Zero-based offset in sink to push data.
		 * 
		 * @throw tc::ObjectDisposedException The base sink was not initialised.
		 * @throw tc::ArgumentOutOfRangeException @p data was too large to be pushed to the sink.
		 **/
	void pushData(const tc::ByteData& data, int64_t offset);
private:
	static const std::string kClassName;

	std::shared_ptr<tc::io::ISink> mBaseSink;
	int64_t mBaseSinkOffset;

	int64_t mSubSinkLength;
};

}} // namespace tc::io