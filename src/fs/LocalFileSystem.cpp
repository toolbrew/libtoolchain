#include <tc/fs/LocalFileSystem.h>
#include "LocalFile.h"
#include <tc/Exception.h>
#include <tc/string.h>
#include <tc/SharedPtr.h>

#ifdef _WIN32
#include <direct.h>
#include <cstdlib>
#else
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#endif

#include <iostream>

tc::fs::LocalFileSystem::LocalFileSystem()
{
}

tc::fs::IFile* tc::fs::LocalFileSystem::openFile(const tc::fs::Path& path, FileAccessMode mode)
{
	tc::fs::IFile* ifile_ptr = nullptr;

#ifdef _WIN32
	// convert Path to unicode string
	std::u16string unicode_path;
	pathToWindowsUTF16(path, unicode_path);

	// open file
	fs_handle_t file_handle = CreateFileW((LPCWSTR)unicode_path.c_str(),
							  getOpenModeFlag(mode),
							  getShareModeFlag(mode),
							  0,
							  getCreationModeFlag(mode),
							  FILE_ATTRIBUTE_NORMAL,
							  NULL);
		
	// check file handle
	if (file_handle == INVALID_HANDLE_VALUE)
	{
		throw tc::Exception(kClassName, "Failed to open file (" + std::to_string(GetLastError()) + ")");
	}

	ifile_ptr = new LocalFile(mode, file_handle);
#else
	// convert Path to unicode string
	std::string unicode_path;
	pathToUnixUTF8(path, unicode_path);

	fs_handle_t file_handle = open(unicode_path.c_str(), getOpenModeFlag(mode), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	if (file_handle == -1)
	{
		throw tc::Exception(kClassName, "Failed to open file (" + std::string(strerror(errno)) + ")");
	}

	ifile_ptr = new LocalFile(mode, file_handle);
#endif

	return ifile_ptr;
}

void tc::fs::LocalFileSystem::deleteFile(const tc::fs::Path& path)
{
#ifdef _WIN32
	// convert Path to unicode string
	std::u16string unicode_path;
	pathToWindowsUTF16(path, unicode_path);

	// delete file
	if (DeleteFileW((LPCWSTR)unicode_path.c_str()) == false)
	{
		throw tc::Exception(kClassName, "Failed to delete file (" + std::to_string(GetLastError()) + ")");
	}	
#else
	// convert Path to unicode string
	std::string unicode_path;
	pathToUnixUTF8(path, unicode_path);

	if (unlink(unicode_path.c_str()) == -1)
	{
		throw tc::Exception(kClassName, "Failed to delete file (" + std::string(strerror(errno)) + ")");
	}	
#endif
}

void tc::fs::LocalFileSystem::getCurrentDirectory(tc::fs::Path& path)
{
#ifdef _WIN32
	tc::SharedPtr<char16_t> raw_char16_path = new char16_t[MAX_PATH];

	// get current directory
	if (GetCurrentDirectoryW(MAX_PATH, (LPWSTR)(raw_char16_path.get())) == false)
	{
		throw tc::Exception(kClassName, "Failed to get current directory (" + std::to_string(GetLastError()) + ")");
	}

	path = Path(raw_char16_path.get());
#else
	setCurrentDirectory(Path("."));

	tc::SharedPtr<char> raw_current_working_directory = new char[PATH_MAX];

	if (getcwd(raw_current_working_directory.get(), PATH_MAX) == nullptr)
	{
		throw tc::Exception(kClassName, "Failed to get current working directory (getcwd)" + std::string(strerror(errno)) + ")");
	}

	path = Path(raw_current_working_directory.get());
#endif
}

void tc::fs::LocalFileSystem::setCurrentDirectory(const tc::fs::Path& path)
{
#ifdef _WIN32
	// convert Path to unicode string
	std::u16string unicode_path;
	pathToWindowsUTF16(path, unicode_path);

	// delete file
	if (SetCurrentDirectoryW((LPCWSTR)unicode_path.c_str()) == false)
	{
		throw tc::Exception(kClassName, "Failed to set current directory (" + std::to_string(GetLastError()) + ")");
	}
#else
	// convert Path to unicode string
	std::string unicode_path;
	pathToUnixUTF8(path, unicode_path);

	// get full path to directory
	if (chdir(unicode_path.c_str()) != 0)
	{
		throw tc::Exception(kClassName, "Failed to get directory info (chdir)(" + std::string(strerror(errno)) + ")");
	}
#endif
}

void tc::fs::LocalFileSystem::createDirectory(const tc::fs::Path& path)
{
#ifdef _WIN32
	// convert Path to unicode string
	std::u16string unicode_path;
	pathToWindowsUTF16(path, unicode_path);

	// create directory
	if (CreateDirectoryW((LPCWSTR)unicode_path.c_str(), nullptr) == false && GetLastError() != ERROR_ALREADY_EXISTS)
	{
		throw tc::Exception(kClassName, "Failed to create directory (" + std::to_string(GetLastError()) + ")");
	}
#else
	// convert Path to unicode string
	std::string unicode_path;
	pathToUnixUTF8(path, unicode_path);

	if (mkdir(unicode_path.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) == -1 && errno != EEXIST)
	{
		throw tc::Exception(kClassName, "Failed to create directory (" + std::string(strerror(errno)) + ")");
	}
#endif
}

void tc::fs::LocalFileSystem::deleteDirectory(const tc::fs::Path& path)
{
#ifdef _WIN32
	// convert Path to unicode string
	std::u16string unicode_path;
	pathToWindowsUTF16(path, unicode_path);

	if (RemoveDirectoryW((wchar_t*)unicode_path.c_str()) == false)
	{
		throw tc::Exception(kClassName, "Failed to remove directory (" + std::to_string(GetLastError()) + ")");
	}
#else
	// convert Path to unicode string
	std::string unicode_path;
	pathToUnixUTF8(path, unicode_path);

	if (rmdir(unicode_path.c_str()) == -1)
	{
		throw tc::Exception(kClassName, "Failed to remove directory (" + std::string(strerror(errno)) + ")");
	}	
#endif
}

void tc::fs::LocalFileSystem::getDirectoryListing(const tc::fs::Path& path, DirectoryInfo& info)
{
	std::vector<std::string> child_dir_name_list;
	std::vector<std::string> child_file_name_list;
	Path current_directory_path;
#ifdef _WIN32
	Path wildcard_path = path + tc::fs::Path("*");

	// convert Path to unicode string
	std::u16string unicode_path;
	pathToWindowsUTF16(wildcard_path, unicode_path);

	HANDLE dir_handle = INVALID_HANDLE_VALUE;
	WIN32_FIND_DATAW dir_entry;



	dir_handle = FindFirstFileW((LPCWSTR)unicode_path.c_str(), &dir_entry);
	if (dir_handle == INVALID_HANDLE_VALUE) 
	{
		throw tc::Exception(kClassName, "Failed to open directory (" + std::to_string(GetLastError()) + ")");
	}

	do {
		std::string utf8_name;
		tc::string::transcodeUTF16ToUTF8((char16_t*)dir_entry.cFileName, utf8_name);

		if (dir_entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) 
		{
			child_dir_name_list.push_back(utf8_name);
		}
		else 
		{
			child_file_name_list.push_back(utf8_name);
		}
	} while (FindNextFileW(dir_handle, &dir_entry) != 0);

	if (GetLastError() != ERROR_NO_MORE_FILES) 
	{
		FindClose(dir_handle);
		throw tc::Exception(kClassName, "Failed to open directory (" + std::to_string(GetLastError()) + ")");
	}

	FindClose(dir_handle);
	

	// save current dir for later
	Path prev_current_dir;
	getCurrentDirectory(prev_current_dir);

	// change the directory
	setCurrentDirectory(path);

	// save the path
	getCurrentDirectory(current_directory_path);

	// restore current directory
	setCurrentDirectory(prev_current_dir);
#else
	std::string unicode_path;
	DIR *dp;

	// convert Path to unicode string
	pathToUnixUTF8(path, unicode_path);
	
	// open directory
	dp = opendir(unicode_path.c_str());
	if (dp == nullptr)
	{
		throw tc::Exception(kClassName, "Failed to get directory info (opendir)(" + std::string(strerror(errno)) + ")");
	}

	// get file and directory names
	child_dir_name_list.clear();
	child_file_name_list.clear();
	
	// since errno can be set by external sources it will be cleared, since the conditions for checking errno being set aren't specific to failure
	errno = 0;
	for (struct dirent *ep = readdir(dp); ep != nullptr && errno == 0; ep = readdir(dp))
	{
		if (ep->d_type == DT_DIR)
		{
			child_dir_name_list.push_back(std::string(ep->d_name));
		}
		else if (ep->d_type == DT_REG)
		{
			child_file_name_list.push_back(std::string(ep->d_name));
		}
	}

	// throw an error if necessary 
	if (errno != 0)
	{
		throw tc::Exception(kClassName, "Failed to get directory info (readdir)(" + std::string(strerror(errno)) + ")");
	}
	

	// close dp
	closedir(dp);

	// save current dir for later
	Path prev_current_dir;
	getCurrentDirectory(prev_current_dir);

	// change the directory
	setCurrentDirectory(path);

	// save the path
	getCurrentDirectory(current_directory_path);

	// restore current directory
	setCurrentDirectory(prev_current_dir);
#endif
	info.setPath(current_directory_path);
	info.setDirectoryList(child_dir_name_list);
	info.setFileList(child_file_name_list);
}

#ifdef _WIN32
DWORD tc::fs::LocalFileSystem::getOpenModeFlag(FileAccessMode mode) const
{
	DWORD flag = 0;
	switch (mode)
	{
		case (FAM_READ):
			flag = GENERIC_READ;
			break;
		case (FAM_EDIT):
			flag = GENERIC_READ | GENERIC_WRITE;
			break;
		case (FAM_CREATE):
			flag = GENERIC_WRITE;
			break;
		default:
			throw tc::Exception(kClassName, "Unknown open mode");
	}
	return flag;
}
DWORD tc::fs::LocalFileSystem::getShareModeFlag(FileAccessMode mode) const
{
	DWORD flag = 0;
	switch (mode)
	{
		case (FAM_READ):
			flag = FILE_SHARE_READ;
			break;
		case (FAM_EDIT):
			flag = FILE_SHARE_READ;
			break;
		case (FAM_CREATE):
			flag = 0;
			break;
		default:
			throw tc::Exception(kClassName, "Unknown open mode");
	}
	return flag;
}
DWORD tc::fs::LocalFileSystem::getCreationModeFlag(FileAccessMode mode) const
{
	DWORD flag = 0;
	switch (mode)
	{
		case (FAM_READ):
			flag = OPEN_EXISTING;
			break;
		case (FAM_EDIT):
			flag = OPEN_EXISTING;
			break;
		case (FAM_CREATE):
			flag = CREATE_ALWAYS;
			break;
		default:
			throw tc::Exception(kClassName, "Unknown open mode");
	}
	return flag;
}

void tc::fs::LocalFileSystem::pathToWindowsUTF16(const tc::fs::Path& path, std::u16string& out)
{
	std::u16string utf16_element;

	out.clear();
	for (size_t i = 0; i < path.getPathElementList().size(); i++)
	{
		tc::string::transcodeUTF8ToUTF16(path.getPathElementList()[i], utf16_element);
		out += utf16_element;
		if (i+1 < path.getPathElementList().size())
			out += std::u16string(u"\\");
		if (utf16_element == std::u16string(u"") && i == 0)
			out += std::u16string(u"\\");
	}
}
#else
int tc::fs::LocalFileSystem::getOpenModeFlag(FileAccessMode mode) const
{
	int flag = 0;
	switch (mode)
	{
		case (FAM_READ):
			flag = O_RDONLY;
			break;
		case (FAM_EDIT):
			flag = O_RDWR;
			break;
		case (FAM_CREATE):
			flag = O_CREAT | O_TRUNC | O_WRONLY;
			break;
		default:
			throw tc::Exception(kClassName, "Unknown open mode");
	}
	return flag;
}

void tc::fs::LocalFileSystem::pathToUnixUTF8(const tc::fs::Path& path, std::string& out)
{
	out.clear();
	for (size_t i = 0; i < path.getPathElementList().size(); i++)
	{
		const std::string& element = path.getPathElementList()[i];
		out += element;
		if (i+1 < path.getPathElementList().size())
			out += "/";
		else if (element == "" && i == 0)
			out += "/";
	}
}
#endif