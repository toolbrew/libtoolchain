/**
 * \class LocalFileSystem
 *
 * \ingroup LibToolChain
 *
 * \brief A wrapper around the existing OS FileSystem API.
 *
 * Implements expected functionality including:
 * - File access (open,remove)
 * - Directory travesal (get current directory, change current directory)
 * - Directory management (create,remove)
 * - Directory listing
 * 
 * 
 * \note All strings are UTF-8
 * \author Jack (jakcron)
 * \version 0.2
 * \date 2018/12/23
 *
 * Contact: jakcron.dev@gmail.com
 *
 */
#pragma once
#include <tc/filesystem/IFileSystem.h>
#ifdef _WIN32
#include <Windows.h>
#else
#include <cstdio>
#endif

namespace tc
{
namespace filesystem
{
	class LocalFileSystem : public IFileSystem
	{
	public:
#ifdef _WIN32
		typedef HANDLE fs_handle_t;
#else
		typedef int fs_handle_t;
#endif
		/** \brief Default Constructor
		 */
		LocalFileSystem();


		/** \brief Open a file
		 *  \param path const tc::filesystem::Path& Path to file
		 *  \param mode tc::filesystem::FileAccessMode 
		 *  \return tc::filesystem::IFile* pointer to IFile object
		 * 
		 *  IFile object will auto-close the file when destructor is called (when deleted)
		 * 
		 *  If the file cannot be accessed (invalid path, or access rights) an exception will be thrown
		 */
		IFile* openFile(const tc::filesystem::Path& path, tc::filesystem::FileAccessMode mode);

		/** \brief Delete a file
		 *  \param path const tc::filesystem::Path& Path to file
		 * 
		 *  If the file cannot be removed (invalid path, or access rights) an exception will be thrown
		 */
		void deleteFile(const tc::filesystem::Path& path);

		/** \brief Get the full path of the current directory
		 *  \param path tc::filesystem::Path& Path object to be populated with current directory path
		 */
		void getCurrentDirectory(tc::filesystem::Path& path);

		/** \brief Change the current directory
		 *  \param path const tc::filesystem::Path& Path to directory
		 */
		void setCurrentDirectory(const tc::filesystem::Path& path);
		
		/** \brief Create a new directory
		 *  \param path const tc::filesystem::Path& Path to directory
		 * 
		 * 	If the directory already exists, this does nothing
		 *  If the directory cannot be created (invalid path, or access rights) an exception will be thrown
		 */
		void createDirectory(const tc::filesystem::Path& path);

		/** \brief Remove a directory
		 *  \param path const tc::filesystem::Path& Path to directory
		 * 
		 *  If the directory cannot be removed (invalid path, or access rights) an exception will be thrown
		 */
		void removeDirectory(const tc::filesystem::Path& path);

		/** \brief Populate a DirectoryInfo object for a specified path
		 *  \param path const tc::filesystem::Path& Path to directory
		 *  \param info tc::filesystem::DirectoryInfo& reference to DirectoryInfo object to be populated
		 * 
		 *  If the directory cannot be accessed (invalid path, or access rights) an exception will be thrown
		 */
		void getDirectoryInfo(const tc::filesystem::Path& path, tc::filesystem::DirectoryInfo& info);

	private:
		const std::string kClassName = "tc::filesystem::LocalFileSystem";
#ifdef _WIN32
		DWORD getOpenModeFlag(tc::filesystem::FileAccessMode mode) const;
		DWORD getShareModeFlag(tc::filesystem::FileAccessMode mode) const;
		DWORD getCreationModeFlag(tc::filesystem::FileAccessMode mode) const;

		void pathToWindowsUtf16(const tc::filesystem::Path& path, std::u16string& out);
#else
		int getOpenModeFlag(tc::filesystem::FileAccessMode mode) const;

		void pathToUnixUtf8(const tc::filesystem::Path& path, std::string& out);
#endif
	};
}
}