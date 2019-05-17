	/**
	 * @file SandboxedIFile.h
	 * @brief Declaration of tc::fs::SandboxedIFile
	 * @author Jack (jakcron)
	 * @version 0.1
	 * @date 2018/12/18
	 */
#pragma once
#include <tc/fs/IFile.h>
#include <tc/SharedPtr.h>

namespace tc { namespace fs {

	/**
	 * @class SandboxedIFile
	 * @brief A wrapper around an existing IFile object that exposes a carve out (user specified offset & size) of the IFile object.
	 */
class SandboxedIFile : public IFile
{
public:
		/** 
		 * @brief Default constuctor
		 * @param[in] file_ptr Pointer to IFile object to be sandboxed
		 * @param[in] file_base_offset Offset in the base file that serves as offset 0 in the sandbox file
		 * @param[in] virtual_size Artificial size of the sandbox file
		 * 
		 * @pre The carve out presented by the sandbox should exist in the base file.
		 */
	SandboxedIFile(const tc::SharedPtr<tc::fs::IFile>& file_ptr, uint64_t file_base_offset, uint64_t virtual_size);

	uint64_t size();
	void seek(uint64_t offset);
	uint64_t pos();
	void read(byte_t* data, size_t len);
	void write(const byte_t* data, size_t len);

private:
	const std::string kClassName = "tc::fs::SandboxedIFile";

	tc::SharedPtr<tc::fs::IFile> mFile;
	uint64_t mFileBaseOffset;
	uint64_t mVirtualSize;

	uint64_t mVirtualOffset;
};

}} // namespace tc::fs