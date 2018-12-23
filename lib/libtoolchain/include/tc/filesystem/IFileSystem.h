/**
 * \class IFileSystem
 *
 * \ingroup LibToolChain
 *
 * \brief An interface for implementing a basic FileSystem handler.
 *
 * Defines expected functionality including:
 * - File access (open,delete)
 * - Directory traversal (get current directory, change current directory)
 * - Directory management (create,remove)
 * - Directory listing
 * 
 * IFileSystem uses the tc::filesystem::Path class to represent a path, not as a literal string.
 * It is up to the implementation of IFileSystem to validate and process the tc::filesystem::Path objects.
 * 
 * \author Jack (jakcron)
 * \version 0.2
 * \date 2018/12/23
 *
 * Contact: jakcron.dev@gmail.com
 *
 */
#pragma once
#include <tc/types.h>
#include <tc/filesystem/IFile.h>
#include <tc/filesystem/DirectoryInfo.h>

namespace tc
{
namespace filesystem
{
	/** FileAccessMode
	 *  This enum is used with openFile() to determine the access mode
	 */
	enum FileAccessMode
	{
		FAM_READ, /**< Access file with READ-ONLY permissions */
		FAM_EDIT, /**< Access file with READ-WRITE permissions */
		FAM_CREATE /**< Create a new file or overwrite an existing file (READ-WRITE permissions) */
	};

	class IFileSystem
	{
	public:
		virtual ~IFileSystem() = default;

		/** \brief Open a file
		 *  \param path const tc::filesystem::Path& Path to file
		 *  \param mode tc::filesystem::FileAccessMode 
		 *  \return tc::filesystem::IFile* pointer to IFile object
		 * 
		 *  If the file cannot be accessed (invalid path, or access rights) an exception will be thrown
		 *  It is up to the implementation to enforce FileAccessMode
		 */
		virtual tc::filesystem::IFile* openFile(const tc::filesystem::Path& path, tc::filesystem::FileAccessMode mode) = 0;

		/** \brief Delete a file
		 *  \param path const tc::filesystem::Path& Path to file
		 * 
		 *  If the file cannot be removed (invalid path, or access rights) an exception will be thrown
		 */
		virtual void deleteFile(const tc::filesystem::Path& path) = 0;

		/** \brief Get the full path of the current directory
		 *  \param path tc::filesystem::Path& Path object to be populated with current directory path
		 */
		virtual void getCurrentDirectory(tc::filesystem::Path& path) = 0;

		/** \brief Change the current directory
		 *  \param path const tc::filesystem::Path& Path to directory
		 */
		virtual void setCurrentDirectory(const tc::filesystem::Path& path) = 0;
		
		/** \brief Create a new directory
		 *  \param path const tc::filesystem::Path& Path to directory
		 * 
		 * 	If the directory already exists, this does nothing
		 *  If the directory cannot be created (invalid path, or access rights) an exception will be thrown
		 */
		virtual void createDirectory(const tc::filesystem::Path& path) = 0;

		/** \brief Remove a directory
		 *  \param path const tc::filesystem::Path& Path to directory
		 * 
		 *  If the directory cannot be removed (invalid path, or access rights) an exception will be thrown
		 */
		virtual void removeDirectory(const tc::filesystem::Path& path) = 0;

		/** \brief Populate a DirectoryInfo object for a specified path
		 *  \param path const tc::filesystem::Path& Path to directory
		 *  \param info tc::filesystem::DirectoryInfo& reference to DirectoryInfo object to be populated
		 * 
		 *  If the directory cannot be accessed (invalid path, or access rights) an exception will be thrown
		 */
		virtual void getDirectoryInfo(const tc::filesystem::Path& path, tc::filesystem::DirectoryInfo& info) = 0;
	};
}
}