#include <tc/Exception.h>
#include <iostream>

#include "fs_SandboxedFileSystem_TestClass.h"

const std::string fs_SandboxedFileSystem_TestClass::DummyFileSystemBase::kClassName = "DummyFileSystemBase";

void fs_SandboxedFileSystem_TestClass::runAllTests(void)
{
	std::cout << "[tc::fs::SandboxedFileSystem] START" << std::endl;
	testSandboxRootPath();
	testCreateFile();
	testOpenFile();
	testRemoveFile();
	testCreateDirectory();
	testRemoveDirectory();
	testGetDirectoryListing();
	testNavigateUpSandboxEscape();
	testOpenFileOutsideSandbox();
	std::cout << "[tc::fs::SandboxedFileSystem] END" << std::endl;
}

void fs_SandboxedFileSystem_TestClass::testSandboxRootPath()
{
	std::cout << "[tc::fs::SandboxedFileSystem] testSandboxRootPath : " << std::flush;
	try
	{
		class DummyFileSystem : public DummyFileSystemBase
		{
		public:
			DummyFileSystem()
			{
			}

			virtual tc::fs::IFileSystem* copyInstance() const
			{
				return new DummyFileSystem(*this);
			}

			virtual tc::fs::IFileSystem* moveInstance()
			{
				return new DummyFileSystem(std::move(*this));
			}
		};

		DummyFileSystem fs;

		// define directory names
		tc::fs::Path dummyfs_curdir = tc::fs::Path("/home/jakcron/source/LibToolChain");
		tc::fs::Path testdir_path = tc::fs::Path("testdir");
		tc::fs::Path sandbox_relative_root = testdir_path + tc::fs::Path("sandbox");

		// test sandbox creation & test real sandbox root path
		try
		{
			// get sandbox filesystem
			tc::fs::SandboxedFileSystem sb_fs(fs, dummyfs_curdir + sandbox_relative_root);

			// save sandbox real path
			tc::fs::Path sandbox_real_root;
			sb_fs.setWorkingDirectory(tc::fs::Path("/"));
			fs.getWorkingDirectory(sandbox_real_root);

			// check the sandbox is generating the correct path
			if (sandbox_real_root != dummyfs_curdir + sandbox_relative_root)
			{
				throw tc::Exception("Sandbox root directory did not have expected absolute real path");
			}

			std::cout << "PASS" << std::endl;
		}
		catch (const tc::Exception& e)
		{
			std::cout << "FAIL (" << e.error() << ")" << std::endl;
		}

	
	}
	catch (const std::exception& e)
	{
		std::cout << "UNHANDLED EXCEPTION (" << e.what() << ")" << std::endl;
	}
}

void fs_SandboxedFileSystem_TestClass::testCreateFile()
{
	std::cout << "[tc::fs::SandboxedFileSystem] testCreateFile : " << std::flush;
	try
	{
		class DummyFileSystem : public DummyFileSystemBase
		{
		public:
			DummyFileSystem()
			{
			}

			void createFile(const tc::fs::Path& path)
			{
				tc::fs::Path cur_dir;
				getWorkingDirectory(cur_dir);
				if (path != cur_dir + tc::fs::Path("a_dir/testfile"))
				{
					throw tc::Exception("DummyFileSystem", "file had incorrect path");
				}
			}

			virtual tc::fs::IFileSystem* copyInstance() const
			{
				return new DummyFileSystem(*this);
			}

			virtual tc::fs::IFileSystem* moveInstance()
			{
				return new DummyFileSystem(std::move(*this));
			}
		};

		DummyFileSystem fs;

		// define directory names
		tc::fs::Path dummyfs_curdir = tc::fs::Path("/home/jakcron/source/LibToolChain");
		tc::fs::Path testdir_path = tc::fs::Path("testdir");

		// test sandbox creation & test real sandbox root path
		try
		{
			// get sandbox filesystem
			tc::fs::SandboxedFileSystem sb_fs(fs, dummyfs_curdir + testdir_path);

			// attempt to create file
			sb_fs.createFile(tc::fs::Path("/a_dir/testfile"));
			
			std::cout << "PASS" << std::endl;
		}
		catch (const tc::Exception& e)
		{
			std::cout << "FAIL (" << e.error() << ")" << std::endl;
		}
	}
	catch (const std::exception& e)
	{
		std::cout << "UNHANDLED EXCEPTION (" << e.what() << ")" << std::endl;
	}
}

void fs_SandboxedFileSystem_TestClass::testOpenFile()
{
	std::cout << "[tc::fs::SandboxedFileSystem] testOpenFile : " << std::flush;
	try
	{
		class DummyFileSystem : public DummyFileSystemBase
		{
		public:
			DummyFileSystem()
			{
			}

			void openFile(const tc::fs::Path& path, tc::fs::FileAccessMode mode, tc::fs::GenericFileObject& file)
			{
				tc::fs::Path cur_dir;
				getWorkingDirectory(cur_dir);
				if (mode != tc::fs::FILEACCESS_READ)
				{
					throw tc::Exception("DummyFileSystem", "file had incorrect access permissions");
				}
				if (path != cur_dir + tc::fs::Path("a_dir/testfile"))
				{
					throw tc::Exception("DummyFileSystem", "file had incorrect path");
				}
			}

			virtual tc::fs::IFileSystem* copyInstance() const
			{
				return new DummyFileSystem(*this);
			}

			virtual tc::fs::IFileSystem* moveInstance()
			{
				return new DummyFileSystem(std::move(*this));
			}
		};

		DummyFileSystem fs;

		// define directory names
		tc::fs::Path dummyfs_curdir = tc::fs::Path("/home/jakcron/source/LibToolChain");
		tc::fs::Path testdir_path = tc::fs::Path("testdir");

		// test sandbox creation & test real sandbox root path
		try
		{
			// get sandbox filesystem
			tc::fs::SandboxedFileSystem sb_fs(fs, dummyfs_curdir + testdir_path);

			// attempt to open file
			tc::fs::GenericFileObject file;
			sb_fs.openFile(tc::fs::Path("/a_dir/testfile"), tc::fs::FILEACCESS_READ, file);
			
			std::cout << "PASS" << std::endl;
		}
		catch (const tc::Exception& e)
		{
			std::cout << "FAIL (" << e.error() << ")" << std::endl;
		}
	}
	catch (const std::exception& e)
	{
		std::cout << "UNHANDLED EXCEPTION (" << e.what() << ")" << std::endl;
	}
}

void fs_SandboxedFileSystem_TestClass::testRemoveFile()
{
	std::cout << "[tc::fs::SandboxedFileSystem] testRemoveFile : " << std::flush;
	try
	{
		class DummyFileSystem : public DummyFileSystemBase
		{
		public:
			DummyFileSystem()
			{
			}

			void removeFile(const tc::fs::Path& path)
			{
				tc::fs::Path cur_dir;
				getWorkingDirectory(cur_dir);
				if (path != cur_dir + tc::fs::Path("a_dir/testfile"))
				{
					throw tc::Exception("DummyFileSystem", "file had incorrect path");
				}
			}

			virtual tc::fs::IFileSystem* copyInstance() const
			{
				return new DummyFileSystem(*this);
			}

			virtual tc::fs::IFileSystem* moveInstance()
			{
				return new DummyFileSystem(std::move(*this));
			}
		};
	
		DummyFileSystem fs;

		// define directory names
		tc::fs::Path dummyfs_curdir = tc::fs::Path("/home/jakcron/source/LibToolChain");
		tc::fs::Path testdir_path = tc::fs::Path("testdir");

		// test sandbox creation & test real sandbox root path
		try
		{
			// get sandbox filesystem
			tc::fs::SandboxedFileSystem sb_fs(fs, dummyfs_curdir + testdir_path);

			// attempt to delete file
			sb_fs.removeFile(tc::fs::Path("/a_dir/testfile"));

			std::cout << "PASS" << std::endl;
		}
		catch (const tc::Exception& e)
		{
			std::cout << "FAIL (" << e.error() << ")" << std::endl;
		}
	}
	catch (const std::exception& e)
	{
		std::cout << "UNHANDLED EXCEPTION (" << e.what() << ")" << std::endl;
	}
}


void fs_SandboxedFileSystem_TestClass::testCreateDirectory()
{
	std::cout << "[tc::fs::SandboxedFileSystem] testCreateDirectory : " << std::flush;
	try
	{
		class DummyFileSystem : public DummyFileSystemBase
		{
		public:
			DummyFileSystem()
			{
			}

			void createDirectory(const tc::fs::Path& path)
			{
				tc::fs::Path cur_dir;
				getWorkingDirectory(cur_dir);
				if (path != cur_dir + tc::fs::Path("a_dir/testdir/hey"))
				{
					throw tc::Exception("DummyFileSystem", "dir had incorrect path");
				}
			}

			virtual tc::fs::IFileSystem* copyInstance() const
			{
				return new DummyFileSystem(*this);
			}

			virtual tc::fs::IFileSystem* moveInstance()
			{
				return new DummyFileSystem(std::move(*this));
			}
		};

		DummyFileSystem fs;

		// define directory names
		tc::fs::Path dummyfs_curdir = tc::fs::Path("/home/jakcron/source/LibToolChain");
		tc::fs::Path testdir_path = tc::fs::Path("testdir");

		// test sandbox creation & test real sandbox root path
		try
		{
			// get sandbox filesystem
			tc::fs::SandboxedFileSystem sb_fs(fs, dummyfs_curdir + testdir_path);

			// attempt to create directory
			sb_fs.createDirectory(tc::fs::Path("/a_dir/testdir/hey"));

			std::cout << "PASS" << std::endl;
		}
		catch (const tc::Exception& e)
		{
			std::cout << "FAIL (" << e.error() << ")" << std::endl;
		}
	}
	catch (const std::exception& e)
	{
		std::cout << "UNHANDLED EXCEPTION (" << e.what() << ")" << std::endl;
	}
}

void fs_SandboxedFileSystem_TestClass::testRemoveDirectory()
{
	std::cout << "[tc::fs::SandboxedFileSystem] testRemoveDirectory : " << std::flush;
	try
	{
		class DummyFileSystem : public DummyFileSystemBase
		{
		public:
			DummyFileSystem()
			{
			}

			void removeDirectory(const tc::fs::Path& path)
			{
				tc::fs::Path cur_dir;
				getWorkingDirectory(cur_dir);
				if (path != cur_dir + tc::fs::Path("a_dir/testdir/hey"))
				{
					throw tc::Exception("DummyFileSystem", "dir had incorrect path");
				}
			}

			virtual tc::fs::IFileSystem* copyInstance() const
			{
				return new DummyFileSystem(*this);
			}

			virtual tc::fs::IFileSystem* moveInstance()
			{
				return new DummyFileSystem(std::move(*this));
			}			
		};

		DummyFileSystem fs;

		// define directory names
		tc::fs::Path dummyfs_curdir = tc::fs::Path("/home/jakcron/source/LibToolChain");
		tc::fs::Path testdir_path = tc::fs::Path("testdir");

		// test sandbox creation & test real sandbox root path
		try
		{
			// get sandbox filesystem
			tc::fs::SandboxedFileSystem sb_fs(fs, dummyfs_curdir + testdir_path);

			// attempt to remove directory
			sb_fs.removeDirectory(tc::fs::Path("/a_dir/testdir/hey"));

			std::cout << "PASS" << std::endl;
		}
		catch (const tc::Exception& e)
		{
			std::cout << "FAIL (" << e.error() << ")" << std::endl;
		}
	}
	catch (const std::exception& e)
	{
		std::cout << "UNHANDLED EXCEPTION (" << e.what() << ")" << std::endl;
	}
}

void fs_SandboxedFileSystem_TestClass::testGetDirectoryListing()
{
	std::cout << "[tc::fs::SandboxedFileSystem] testGetDirectoryListing : " << std::flush;
	try
	{
		class DummyFileSystem : public DummyFileSystemBase
		{
		public:
			DummyFileSystem()
			{
			}

			void getDirectoryListing(const tc::fs::Path& path, tc::fs::sDirectoryListing& dir_info)
			{
				tc::fs::Path cur_dir;
				getWorkingDirectory(cur_dir);
				if (path != cur_dir + tc::fs::Path("a_dir/testdir/hey"))
				{
					throw tc::Exception("DummyFileSystem", "dir had incorrect path");
				}

				dir_info.abs_path = path;
				dir_info.dir_list = std::vector<std::string>({ "dir0", "dir1", "dir2" });
				dir_info.file_list = std::vector<std::string>({ "file0", "file1" });
			}

			virtual tc::fs::IFileSystem* copyInstance() const
			{
				return new DummyFileSystem(*this);
			}

			virtual tc::fs::IFileSystem* moveInstance()
			{
				return new DummyFileSystem(std::move(*this));
			}
		};

		DummyFileSystem fs;

		// define directory names
		tc::fs::Path dummyfs_curdir = tc::fs::Path("/home/jakcron/source/LibToolChain");
		tc::fs::Path testdir_path = tc::fs::Path("testdir");

		// test sandbox creation & test real sandbox root path
		try
		{
			// get sandbox filesystem
			tc::fs::SandboxedFileSystem sb_fs(fs, dummyfs_curdir + testdir_path);

			// save sandbox dir info
			tc::fs::sDirectoryListing sb_dir_info;
			sb_fs.getDirectoryListing(tc::fs::Path("/a_dir/testdir/hey"), sb_dir_info);

			// save real dir info
			tc::fs::sDirectoryListing real_dir_info;
			fs.getDirectoryListing(dummyfs_curdir + tc::fs::Path("testdir/a_dir/testdir/hey"), real_dir_info);

			if (sb_dir_info.file_list != real_dir_info.file_list)
			{
				throw tc::Exception("DummyFileSystem", "File list was not as expected");
			}

			if (sb_dir_info.dir_list != real_dir_info.dir_list)
			{
				throw tc::Exception("DummyFileSystem", "Directory list was not as expected");
			}

			tc::fs::Path fixed_sandbox_path;
			for (tc::fs::Path::const_iterator itr = sb_dir_info.abs_path.begin(); itr != sb_dir_info.abs_path.end(); itr++)
			{
				if (*itr == "" && itr == sb_dir_info.abs_path.begin())
				{
					continue;
				}

				fixed_sandbox_path.push_back(*itr);
			}

			if ((dummyfs_curdir + testdir_path + fixed_sandbox_path) != real_dir_info.abs_path)
			{
				throw tc::Exception("DummyFileSystem", "Directory path was not as expected");
			}

			std::cout << "PASS" << std::endl;
		}
		catch (const tc::Exception& e)
		{
			std::cout << "FAIL (" << e.error() << ")" << std::endl;
		}
	}
	catch (const std::exception& e)
	{
		std::cout << "UNHANDLED EXCEPTION (" << e.what() << ")" << std::endl;
	}
}


void fs_SandboxedFileSystem_TestClass::testNavigateUpSandboxEscape()
{
	std::cout << "[tc::fs::SandboxedFileSystem] testNavigateUpSandboxEscape : " << std::flush;
	try
	{
		class DummyFileSystem : public DummyFileSystemBase
		{
		public:
			DummyFileSystem() :
				mLastUsedPath(new tc::fs::Path())
			{
			}

			void getDirectoryListing(const tc::fs::Path& path, tc::fs::sDirectoryListing& dir_info)
			{			
				dir_info.abs_path = path;
				*mLastUsedPath = path;
			}

			const tc::fs::Path& getLastUsedPath()
			{
				return *mLastUsedPath;
			}

			virtual tc::fs::IFileSystem* copyInstance() const
			{
				return new DummyFileSystem(*this);
			}

			virtual tc::fs::IFileSystem* moveInstance()
			{
				return new DummyFileSystem(std::move(*this));
			}
		private:
			tc::SharedPtr<tc::fs::Path> mLastUsedPath;
		};

		DummyFileSystem fs;

		// save the current directory
		tc::fs::Path dummyfs_curdir = tc::fs::Path("/home/jakcron/source/LibToolChain");

		// define directory names
		tc::fs::Path testdir_path = tc::fs::Path("testdir");
		tc::fs::Path sandbox_relative_root = testdir_path + tc::fs::Path("sandbox");

		// test navigating outside of sandbox with ".." navigation
		try
		{
			// get sandbox filesystem
			tc::fs::SandboxedFileSystem sb_fs(fs, dummyfs_curdir + sandbox_relative_root);

			// get info about current directory
			tc::fs::sDirectoryListing dir_info;
			sb_fs.getDirectoryListing(tc::fs::Path("./../../../../../../../../../../../../../..///./././"), dir_info);
			
			if (dir_info.abs_path != tc::fs::Path("/"))
			{
				throw tc::Exception("Sandbox directory path not as expected");
			}

			if (fs.getLastUsedPath() != dummyfs_curdir + sandbox_relative_root)
			{
				throw tc::Exception("Real directory path not as expected");
			}

			std::cout << "PASS" << std::endl;
		}
		catch (const tc::Exception& e)
		{
			std::cout << "FAIL (" << e.error() << ")" << std::endl;
		}
	}
	catch (const std::exception& e)
	{
		std::cout << "UNHANDLED EXCEPTION (" << e.what() << ")" << std::endl;
	}
}

void fs_SandboxedFileSystem_TestClass::testOpenFileOutsideSandbox()
{
	std::cout << "[tc::fs::SandboxedFileSystem] testOpenFileOutsideSandbox : " << std::flush;
	try
	{
		class DummyFileSystem : public DummyFileSystemBase
		{
		public:
			DummyFileSystem()
			{
			}

			void openFile(const tc::fs::Path& path, tc::fs::FileAccessMode mode, tc::fs::GenericFileObject& file)
			{
				tc::fs::Path mCurDir;
				getWorkingDirectory(mCurDir);
				if (mode != tc::fs::FILEACCESS_READ)
				{
					throw tc::Exception("DummyFileSystem", "file had incorrect access mode");
				}
				if (path == tc::fs::Path("/home/jakcron/source/LibToolChain/testdir/inaccessible_file0"))
				{
					throw tc::Exception("DummyFileSystem", "escaped sandbox");
				}
				if (path != tc::fs::Path("/home/jakcron/source/LibToolChain/testdir/sandbox/inaccessible_file0"))
				{
					throw tc::Exception("DummyFileSystem", "sandbox path was not as expected");
				}
			}

			virtual tc::fs::IFileSystem* copyInstance() const
			{
				return new DummyFileSystem(*this);
			}

			virtual tc::fs::IFileSystem* moveInstance()
			{
				return new DummyFileSystem(std::move(*this));
			}
		};

		DummyFileSystem fs;

		// save the current directory
		tc::fs::Path dummyfs_curdir = tc::fs::Path("/home/jakcron/source/LibToolChain");

		// define directory names
		tc::fs::Path testdir_path = tc::fs::Path("testdir");
		tc::fs::Path sandbox_relative_root = testdir_path + tc::fs::Path("sandbox");

		// test accessing file outside of sandbox
		try {
			// get sandbox filesystem
			tc::fs::SandboxedFileSystem sb_fs(fs, dummyfs_curdir + sandbox_relative_root);
			  
			// try to open the file just outside the sandbox
			sb_fs.setWorkingDirectory(tc::fs::Path("/"));
			tc::fs::GenericFileObject inaccessible_file;
			sb_fs.openFile(tc::fs::Path("../inaccessible_file0"), tc::fs::FILEACCESS_READ, inaccessible_file);

			std::cout << "PASS" << std::endl;
		}
		catch (const tc::Exception& e)
		{
			std::cout << "FAIL (" << e.error() << ")" << std::endl;
		}
	}
	catch (const std::exception& e)
	{
		std::cout << "UNHANDLED EXCEPTION (" << e.what() << ")" << std::endl;
	}
}