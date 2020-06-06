#include <tc/crypto/Sha1Generator.h>

const std::array<byte_t, tc::crypto::Sha1Generator::kAsn1OidDataSize> tc::crypto::Sha1Generator::kAsn1OidData = {0x2b, 0x0e, 0x03, 0x02, 0x1a};

void tc::crypto::GenerateSha1Hash(byte_t* hash, const byte_t* data, size_t data_size)
{
	tc::crypto::Sha1Generator impl;
	impl.initialize();
	impl.update(data, data_size);
	impl.getHash(hash);
}