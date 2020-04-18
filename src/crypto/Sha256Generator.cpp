#include <tc/crypto/Sha256Generator.h>

#ifndef TC_CRYPTO_SHA256GENERATOR_NO_IMPL
void tc::crypto::GenerateSha256Hash(byte_t* hash, const byte_t* data, size_t data_size)
{
	Sha256Generator hashGenerator;

	hashGenerator.Initialize();
	hashGenerator.Update(data, data_size);
	hashGenerator.GetHash(hash);
}
#endif