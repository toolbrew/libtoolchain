	/**
	 * @file LocalStorage.h
	 * @brief Declaration of tc::io::LocalStorage
	 * @author Jack (jakcron)
	 * @version 0.5
	 * @date 2019/06/18
	 **/
#pragma once
#include <tc/io/IStorage.h>

#include <tc/io/IOException.h>
#include <tc/io/DirectoryNotFoundException.h>
#include <tc/io/FileNotFoundException.h>
#include <tc/io/PathTooLongException.h>
#include <tc/UnauthorisedAccessException.h>

#ifdef _WIN32
	#include <windows.h>
#endif

namespace tc { namespace io {

	/**
	 * @class LocalStorage
	 * @brief An IStorage wrapper around the existing OS FileSystem API.
	 **/
class LocalStorage : public IStorage
{
public:
		/// Default Constructor
	LocalStorage();

		/// Open Local Storage
	void openStorage();

	virtual tc::ResourceStatus state();
	virtual void dispose();
	virtual void createFile(const tc::io::Path& path);

		/** 
		 * @brief Remove a file
		 * @param[in] path A relative or absolute path for the file that the current @ref IStorage object will remove.
		 * 
		 * @throw tc::UnauthorisedAccessException @p path specified a read-only file. -or- @p path is a directory. -or- The caller does not have the required permission.
		 * @throw tc::io::IOException File is in use The specified file is in use. -or- An I/O error has occured.
		 * @throw tc::io::PathTooLongException The specified path, file name, or both exceed the system-defined maximum length.
		 * @throw tc::io::DirectoryNotFoundException A component of the path prefix is not a directory.
		 * @throw tc::io::FileNotFoundException The specifed file does not exist.
		 **/
	virtual void removeFile(const tc::io::Path& path);

		/** 
		 * @brief Open a file
		 * @param[in] path A relative or absolute path for the file that the current @ref IStorage object will open an @ref IStream for.
		 * @param[in] mode One of the enumeration values that determines how to open or create the file.
		 * @param[in] access One of the enumeration values that determines how the file can be accessed by the @ref IStream object. This also determines the values returned by the @ref IStream::canRead and @ref IStream::canWrite methods of the IStream object. @ref IStream::canSeek is true if path specifies a disk file.
		 * @param[out] stream Pointer to IStream object to be instantiated
		 **/
	virtual void openFile(const tc::io::Path& path, tc::io::FileMode mode, tc::io::FileAccess access, std::shared_ptr<tc::io::IStream>& stream);
	
		/** 
		 * @brief Create a new directory
		 * @param[in] path Path to directory
		 * 
		 * @post If the directory already exists, this does nothing if the directory cannot be created (invalid path, or access rights)
		 * 
		 * @throw tc::UnauthorisedAccessException Write permission is denied for a parent direcory. -or- Parent directory resides in a read-only file system. -or- The caller does not have the required permission.
		 * @throw tc::io::IOException An I/O error has occured.
		 * @throw tc::io::PathTooLongException The specified path, directory name, or both exceed the system-defined maximum length.
		 * @throw tc::io::DirectoryNotFoundException A component of the path prefix is not a directory or does not exist.
		 **/
	virtual void createDirectory(const tc::io::Path& path);

		/** 
		 * @brief Remove a directory
		 * @param[in] path Path to directory
		 **/
	virtual void removeDirectory(const tc::io::Path& path);

		/** 
		 * @brief Get the full path of the working directory
		 * @param[out] path Path object to populate
		 **/
	virtual void getWorkingDirectory(tc::io::Path& path);

		/** 
		 * @brief Change the working directory
		 * @param[in] path Path to directory
		 **/
	virtual void setWorkingDirectory(const tc::io::Path& path);

		/** 
		 * @brief Get directory listing a directory
		 * @param[in] path Path to directory
		 * @param[out] info sDirectoryListing object to populate
		 **/
	virtual void getDirectoryListing(const tc::io::Path& path, tc::io::sDirectoryListing& info);
private:
	static const std::string kClassName;

	tc::ResourceStatus mState;
};

}} // namespace tc::io