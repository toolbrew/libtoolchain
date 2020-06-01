	/**
	 * @file HmacImpl.h
	 * @brief Declaration of tc::crypto::detail::HmacImpl
	 * @author Jack (jakcron)
	 * @version 0.1
	 * @date 2020/05/28
	 **/
#pragma once

#include <tc/ByteData.h>

namespace tc { namespace crypto { namespace detail {

template <typename HashFunction>
class HmacImpl
{
public:
	static const size_t kMacSize = HashFunction::kHashSize;
	static const size_t kBlockSize = HashFunction::kBlockSize;

	HmacImpl() :
		mHashFunction(),
		mState(State::None)
	{
	}
	~HmacImpl()
	{
		std::memset(mKeyDigest.data(), 0, mKeyDigest.size());
		std::memset(mMac.data(), 0, mMac.size());
		mState = State::None;
	}

	void initialize(const byte_t* key, size_t key_size)
	{
		std::memset(mKeyDigest.data(), 0x00, mKeyDigest.size());

		if (key_size > kBlockSize)
		{
			mHashFunction.initialize();
			mHashFunction.update(key, key_size);
			mHashFunction.getHash(mKeyDigest.data());
		}
		else
		{
			std::memcpy(mKeyDigest.data(), key, key_size);
		}

		for (uint32_t i = 0 ; i < kBlockSize / sizeof(uint32_t); i++)
		{
			((uint32_t*)mKeyDigest.data())[i] ^= uint32_t(0x36363636);
		}

		mHashFunction.initialize();
		mHashFunction.update(mKeyDigest.data(), mKeyDigest.size());

		mState = State::Initialized;
	}

	void update(const byte_t* data, size_t data_size)
	{
		mHashFunction.update(data, data_size);
	}

	void getMac(byte_t* mac)
	{
		if (mState == State::Initialized)
		{
			mHashFunction.getHash(mMac.data());

			for (uint32_t i = 0 ; i < kBlockSize / sizeof(uint32_t); i++)
			{
				((uint32_t*)mKeyDigest.data())[i] ^= uint32_t(0x6A6A6A6A);
			}

			mHashFunction.initialize();
			mHashFunction.update(mKeyDigest.data(), mKeyDigest.size());
			mHashFunction.update(mMac.data(), mMac.size());
			mHashFunction.getHash(mMac.data());

			mState = State::Done;
		}

		std::memcpy(mac, mMac.data(), mMac.size());
	}
private:
	enum class State
	{
		None,
		Initialized,
		Done
	};

	HashFunction					mHashFunction;
	std::array<byte_t, kBlockSize>	mKeyDigest;
	std::array<byte_t, kMacSize>	mMac;
	State 							mState;
};

}}} // namespace tc::crypto::detail