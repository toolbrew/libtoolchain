#include "io_SubFileSystem_TestClass.h"
#include "FileSystemTestUtil.h"
#include "StreamTestUtil.h"

#include <fmt/format.h>

//---------------------------------------------------------

io_SubFileSystem_TestClass::io_SubFileSystem_TestClass() :
	mTestTag("tc::io::SubFileSystem"),
	mTestResults()
{
}

void io_SubFileSystem_TestClass::runAllTests(void)
{
	testBaseFileSystemRetainsWorkingDirectory();
	testGetSetWorkingDirectory();
	testCreateFile();
	testOpenFile();
	testRemoveFile();
	testCreateDirectory();
	testCreateDirectoryPath();
	testRemoveDirectory();
	testGetDirectoryListing();
	testNavigateUpSubFileSystemEscape();
	testOpenFileOutsideSubFileSystem();
}

const std::string& io_SubFileSystem_TestClass::getTestTag() const
{
	return mTestTag;
}

const std::vector<ITestClass::TestResult>& io_SubFileSystem_TestClass::getTestResults() const
{
	return mTestResults;
}

//---------------------------------------------------------

void io_SubFileSystem_TestClass::testBaseFileSystemRetainsWorkingDirectory()
{
	TestResult test;
	test.test_name = "testBaseFileSystemRetainsWorkingDirectory";
	test.result = "NOT RUN";
	test.comments = "";
	
	try
	{
		class DummyFileSystem : public FileSystemTestUtil::DummyFileSystemBase
		{
		public:
			DummyFileSystem()
			{
			}
		};
		
		// define sub filesystem base path
		tc::io::Path subfilesystem_base_path = tc::io::Path("/home/jakcron/source/LibToolChain/testdir");

		// define base filesystem
		DummyFileSystem filesystem = DummyFileSystem();

		// test sub filesystem creation & test base working directory is maintained after SubFileSystem constructor
		try
		{
			// save a copy of the base filesystem working directory
			tc::io::Path base_initial_working_dir_path;
			filesystem.getWorkingDirectory(base_initial_working_dir_path);

			// create sub filesystem
			tc::io::SubFileSystem sub_filesystem(std::make_shared<DummyFileSystem>(filesystem), subfilesystem_base_path);

			// check the sub filesystem preserved the base filesystem working directory after the constructor
			tc::io::Path base_current_working_dir_path;
			filesystem.getWorkingDirectory(base_current_working_dir_path);
			if (base_initial_working_dir_path != base_current_working_dir_path)
			{
				throw tc::TestException("SubFileSystem constructor did not preserve the base file system working directory.");
			}

			// record result
			test.result = "PASS";
			test.comments = "";
		}
		catch (const tc::TestException& e)
		{
			// record result
			test.result = "FAIL";
			test.comments = e.what();
		}
	}
	catch (const std::exception& e)
	{
		// record result
		test.result = "UNHANDLED EXCEPTION";
		test.comments = e.what();
	}

	// add result to list
	mTestResults.push_back(std::move(test));
}

void io_SubFileSystem_TestClass::testGetSetWorkingDirectory()
{
	TestResult test;
	test.test_name = "testGetSetWorkingDirectory";
	test.result = "NOT RUN";
	test.comments = "";
	
	try
	{
		class DummyFileSystem : public FileSystemTestUtil::DummyFileSystemBase
		{
		public:
			DummyFileSystem()
			{
			}
		};
		
		// define sub filesystem base path
		tc::io::Path subfilesystem_base_path = tc::io::Path("/home/jakcron/source/LibToolChain/testdir");

		// define base filesystem
		DummyFileSystem filesystem = DummyFileSystem();

		// test sub filesystem creation & test base working directory is maintained after SubFileSystem constructor
		try
		{
			// save a copy of the base filesystem working directory
			tc::io::Path base_initial_working_dir_path;
			filesystem.getWorkingDirectory(base_initial_working_dir_path);

			// create sub filesystem
			tc::io::SubFileSystem sub_filesystem(std::make_shared<DummyFileSystem>(filesystem), subfilesystem_base_path);

			// check the sub filesystem preserved the base filesystem working directory after get/set the working directory

			// test 1a) is the initial working directory for sub filesystem root?
			{
				tc::io::Path sub_current_working_dir_path;
				sub_filesystem.getWorkingDirectory(sub_current_working_dir_path);
				if (sub_current_working_dir_path != tc::io::Path("/"))
				{
					throw tc::TestException("SubFileSystem initial working directory was not root.");
				}
			}
			

			// test 1b) is the base filesystem working directory unchanged after using SubFileSystem::getWorkingDirectory()?
			{
				tc::io::Path base_current_working_dir_path;
				filesystem.getWorkingDirectory(base_current_working_dir_path);
				if (base_initial_working_dir_path != base_current_working_dir_path)
				{
					throw tc::TestException("SubFileSystem getWorkingDirectory did not preserve the base file system working directory.");
				}
			}

			// test 2a) can the sub filesystem change its working directory?
			tc::io::Path sub_test_path = tc::io::Path("/a/path/to/change/to");
			{
				sub_filesystem.setWorkingDirectory(sub_test_path);

				tc::io::Path sub_current_working_dir_path;
				sub_filesystem.getWorkingDirectory(sub_current_working_dir_path);

				if (sub_current_working_dir_path != sub_test_path)
				{
					throw tc::TestException("SubFileSystem setWorkingDirectory() failed to set working directory as getWorkingDirectory() returned unexpected path.");
				}
			}

			// test 2b) is the base filesystem working directory unchanged after using SubFileSystem::setWorkingDirectory()?
			{
				tc::io::Path base_current_working_dir_path;
				filesystem.getWorkingDirectory(base_current_working_dir_path);
				if (base_initial_working_dir_path != base_current_working_dir_path)
				{
					throw tc::TestException("SubFileSystem getWorkingDirectory did not preserve the base file system working directory.");
				}
			}

			// record result
			test.result = "PASS";
			test.comments = "";
		}
		catch (const tc::TestException& e)
		{
			// record result
			test.result = "FAIL";
			test.comments = e.what();
		}
	}
	catch (const std::exception& e)
	{
		// record result
		test.result = "UNHANDLED EXCEPTION";
		test.comments = e.what();
	}

	// add result to list
	mTestResults.push_back(std::move(test));
}

void io_SubFileSystem_TestClass::testCreateFile()
{
	TestResult test;
	test.test_name = "testCreateFile";
	test.result = "NOT RUN";
	test.comments = "";
	
	try
	{
		class DummyFileSystem : public FileSystemTestUtil::DummyFileSystemBase
		{
		public:
			DummyFileSystem(const tc::io::Path& expected_subfs_base) :
				mExpectedSubfsBasePath(expected_subfs_base)
			{
				getWorkingDirectory(mInitialWorkingDirectoryPath);
			}

			void createFile(const tc::io::Path& path)
			{
				// validate base working directory was preserved
				tc::io::Path cur_dir;
				getWorkingDirectory(cur_dir);

				if (cur_dir != mInitialWorkingDirectoryPath)
				{
					throw tc::TestException("DummyFileSystem: Working directory was not preserved by SubFileSystem.");
				}

				// check input was correct
				if (path != mExpectedSubfsBasePath + tc::io::Path("a_dir/testfile"))
				{
					throw tc::TestException("DummyFileSystem: file had incorrect path");
				}
			}
		private:
			tc::io::Path mInitialWorkingDirectoryPath;
			tc::io::Path mExpectedSubfsBasePath;
		};

		// define sub filesystem base path
		tc::io::Path subfilesystem_base_path = tc::io::Path("/home/jakcron/source/LibToolChain/testdir");

		// define base filesystem
		DummyFileSystem filesystem = DummyFileSystem(subfilesystem_base_path);

		// test sub filesystem creation & test translation of input to base filesystem
		try
		{
			// create sub filesystem
			tc::io::SubFileSystem sub_filesystem(std::make_shared<DummyFileSystem>(filesystem), subfilesystem_base_path);

			// attempt to create file
			sub_filesystem.createFile(tc::io::Path("/a_dir/testfile"));
			
			// record result
			test.result = "PASS";
			test.comments = "";
		}
		catch (const tc::TestException& e)
		{
			// record result
			test.result = "FAIL";
			test.comments = e.what();
		}
	}
	catch (const std::exception& e)
	{
		// record result
		test.result = "UNHANDLED EXCEPTION";
		test.comments = e.what();
	}

	// add result to list
	mTestResults.push_back(std::move(test));
}

void io_SubFileSystem_TestClass::testOpenFile()
{
	TestResult test;
	test.test_name = "testOpenFile";
	test.result = "NOT RUN";
	test.comments = "";
	
	try
	{
		class DummyFileSystem : public FileSystemTestUtil::DummyFileSystemBase
		{
		public:
			DummyFileSystem(const tc::io::Path& expected_subfs_base) :
				mExpectedSubfsBasePath(expected_subfs_base)
			{
				getWorkingDirectory(mInitialWorkingDirectoryPath);
			}

			void openFile(const tc::io::Path& path, tc::io::FileMode mode, tc::io::FileAccess access, std::shared_ptr<tc::io::IStream>& stream)
			{
				// validate base working directory was preserved
				tc::io::Path cur_dir;
				getWorkingDirectory(cur_dir);

				if (cur_dir != mInitialWorkingDirectoryPath)
				{
					throw tc::TestException("DummyFileSystem: Working directory was not preserved by SubFileSystem.");
				}
				
				// check input was correct
				if (mode != tc::io::FileMode::Open || access != tc::io::FileAccess::Read)
				{
					throw tc::TestException("DummyFileSystem: file had incorrect access permissions");
				}
				if (path != mExpectedSubfsBasePath + tc::io::Path("a_dir/testfile"))
				{
					throw tc::TestException("DummyFileSystem: file had incorrect path");
				}

				// popualate file stream pointer
				stream = std::make_shared<StreamTestUtil::DummyStreamBase>(StreamTestUtil::DummyStreamBase(0xdeadbeef));
			}
		private:
			tc::io::Path mInitialWorkingDirectoryPath;
			tc::io::Path mExpectedSubfsBasePath;
		};

		// define sub filesystem base path
		tc::io::Path subfilesystem_base_path = tc::io::Path("/home/jakcron/source/LibToolChain/testdir");

		// define base filesystem
		DummyFileSystem filesystem = DummyFileSystem(subfilesystem_base_path);

		// test sub filesystem creation & test translation of input/output to/from base filesystem
		try
		{
			// create sub filesystem
			tc::io::SubFileSystem sub_filesystem(std::make_shared<DummyFileSystem>(filesystem), subfilesystem_base_path);

			// attempt to open file
			std::shared_ptr<tc::io::IStream> file;
			sub_filesystem.openFile(tc::io::Path("/a_dir/testfile"), tc::io::FileMode::Open, tc::io::FileAccess::Read, file);

			// check file was opened and correct
			if (file == nullptr)
			{
				throw tc::TestException("openFile() did not populate stream pointer");
			}
			if (file->length() != 0xdeadbeef)
			{
				throw tc::TestException("openFile() did not populate stream pointer correctly");
			}
			
			// record result
			test.result = "PASS";
			test.comments = "";
		}
		catch (const tc::TestException& e)
		{
			// record result
			test.result = "FAIL";
			test.comments = e.what();
		}
	}
	catch (const std::exception& e)
	{
		// record result
		test.result = "UNHANDLED EXCEPTION";
		test.comments = e.what();
	}

	// add result to list
	mTestResults.push_back(std::move(test));
}

void io_SubFileSystem_TestClass::testRemoveFile()
{
	TestResult test;
	test.test_name = "testRemoveFile";
	test.result = "NOT RUN";
	test.comments = "";
	
	try
	{
		class DummyFileSystem : public FileSystemTestUtil::DummyFileSystemBase
		{
		public:
			DummyFileSystem(const tc::io::Path& expected_subfs_base) :
				mExpectedSubfsBasePath(expected_subfs_base)
			{
				getWorkingDirectory(mInitialWorkingDirectoryPath);
			}

			void removeFile(const tc::io::Path& path)
			{
				// validate base working directory was preserved
				tc::io::Path cur_dir;
				getWorkingDirectory(cur_dir);

				if (cur_dir != mInitialWorkingDirectoryPath)
				{
					throw tc::TestException("DummyFileSystem: Working directory was not preserved by SubFileSystem.");
				}

				// check input was correct
				if (path != mExpectedSubfsBasePath + tc::io::Path("a_dir/testfile"))
				{
					throw tc::TestException("DummyFileSystem: file had incorrect path");
				}
			}
		private:
			tc::io::Path mInitialWorkingDirectoryPath;
			tc::io::Path mExpectedSubfsBasePath;
		};
	
		// define sub filesystem base path
		tc::io::Path subfilesystem_base_path = tc::io::Path("/home/jakcron/source/LibToolChain/testdir");

		// define base filesystem
		DummyFileSystem filesystem = DummyFileSystem(subfilesystem_base_path);

		// test sub filesystem creation & test translation of input to base filesystem
		try
		{
			// create sub filesystem
			tc::io::SubFileSystem sub_filesystem(std::make_shared<DummyFileSystem>(filesystem), subfilesystem_base_path);

			// attempt to delete file
			sub_filesystem.removeFile(tc::io::Path("/a_dir/testfile"));

			// record result
			test.result = "PASS";
			test.comments = "";
		}
		catch (const tc::TestException& e)
		{
			// record result
			test.result = "FAIL";
			test.comments = e.what();
		}
	}
	catch (const std::exception& e)
	{
		// record result
		test.result = "UNHANDLED EXCEPTION";
		test.comments = e.what();
	}

	// add result to list
	mTestResults.push_back(std::move(test));
}

void io_SubFileSystem_TestClass::testCreateDirectory()
{
	TestResult test;
	test.test_name = "testCreateDirectory";
	test.result = "NOT RUN";
	test.comments = "";
	
	try
	{
		class DummyFileSystem : public FileSystemTestUtil::DummyFileSystemBase
		{
		public:
			DummyFileSystem(const tc::io::Path& expected_subfs_base) :
				mExpectedSubfsBasePath(expected_subfs_base)
			{
				getWorkingDirectory(mInitialWorkingDirectoryPath);
			}

			void createDirectory(const tc::io::Path& path)
			{
				// validate base working directory was preserved
				tc::io::Path cur_dir;
				getWorkingDirectory(cur_dir);

				if (cur_dir != mInitialWorkingDirectoryPath)
				{
					throw tc::TestException("DummyFileSystem: Working directory was not preserved by SubFileSystem.");
				}

				// check input was correct
				if (path != mExpectedSubfsBasePath + tc::io::Path("a_dir/testdir/hey"))
				{
					throw tc::TestException("DummyFileSystem: dir had incorrect path");
				}
			}
		private:
			tc::io::Path mInitialWorkingDirectoryPath;
			tc::io::Path mExpectedSubfsBasePath;
		};
	
		// define sub filesystem base path
		tc::io::Path subfilesystem_base_path = tc::io::Path("/home/jakcron/source/LibToolChain/testdir");

		// define base filesystem
		DummyFileSystem filesystem = DummyFileSystem(subfilesystem_base_path);

		// test sub filesystem creation & test translation of input to base filesystem
		try
		{
			// create sub filesystem
			tc::io::SubFileSystem sub_filesystem(std::make_shared<DummyFileSystem>(filesystem), subfilesystem_base_path);

			// attempt to create directory
			sub_filesystem.createDirectory(tc::io::Path("/a_dir/testdir/hey"));

			// record result
			test.result = "PASS";
			test.comments = "";
		}
		catch (const tc::TestException& e)
		{
			// record result
			test.result = "FAIL";
			test.comments = e.what();
		}
	}
	catch (const std::exception& e)
	{
		// record result
		test.result = "UNHANDLED EXCEPTION";
		test.comments = e.what();
	}

	// add result to list
	mTestResults.push_back(std::move(test));
}

void io_SubFileSystem_TestClass::testCreateDirectoryPath()
{
	TestResult test;
	test.test_name = "testCreateDirectoryPath";
	test.result = "NOT RUN";
	test.comments = "";
	
	try
	{
		class DummyFileSystem : public FileSystemTestUtil::DummyFileSystemBase
		{
		public:
			DummyFileSystem(const tc::io::Path& expected_subfs_base) :
				mExpectedSubfsBasePath(expected_subfs_base)
			{
				getWorkingDirectory(mInitialWorkingDirectoryPath);
			}

			void createDirectoryPath(const tc::io::Path& path)
			{
				// validate base working directory was preserved
				tc::io::Path cur_dir;
				getWorkingDirectory(cur_dir);

				if (cur_dir != mInitialWorkingDirectoryPath)
				{
					throw tc::TestException("DummyFileSystem: Working directory was not preserved by SubFileSystem.");
				}

				// check input was correct
				if (path != mExpectedSubfsBasePath + tc::io::Path("a_dir/testdir/hey"))
				{
					throw tc::TestException("DummyFileSystem: dir had incorrect path");
				}
			}
		private:
			tc::io::Path mInitialWorkingDirectoryPath;
			tc::io::Path mExpectedSubfsBasePath;
		};
	
		// define sub filesystem base path
		tc::io::Path subfilesystem_base_path = tc::io::Path("/home/jakcron/source/LibToolChain/testdir");

		// define base filesystem
		DummyFileSystem filesystem = DummyFileSystem(subfilesystem_base_path);

		// test sub filesystem creation & test translation of input to base filesystem
		try
		{
			// create sub filesystem
			tc::io::SubFileSystem sub_filesystem(std::make_shared<DummyFileSystem>(filesystem), subfilesystem_base_path);

			// attempt to create directory
			sub_filesystem.createDirectoryPath(tc::io::Path("/a_dir/testdir/hey"));

			// record result
			test.result = "PASS";
			test.comments = "";
		}
		catch (const tc::TestException& e)
		{
			// record result
			test.result = "FAIL";
			test.comments = e.what();
		}
	}
	catch (const std::exception& e)
	{
		// record result
		test.result = "UNHANDLED EXCEPTION";
		test.comments = e.what();
	}

	// add result to list
	mTestResults.push_back(std::move(test));
}

void io_SubFileSystem_TestClass::testRemoveDirectory()
{
	TestResult test;
	test.test_name = "testRemoveDirectory";
	test.result = "NOT RUN";
	test.comments = "";
	
	try
	{
		class DummyFileSystem : public FileSystemTestUtil::DummyFileSystemBase
		{
		public:
			DummyFileSystem(const tc::io::Path& expected_subfs_base) :
				mExpectedSubfsBasePath(expected_subfs_base)
			{
				getWorkingDirectory(mInitialWorkingDirectoryPath);
			}

			void removeDirectory(const tc::io::Path& path)
			{
				// validate base working directory was preserved
				tc::io::Path cur_dir;
				getWorkingDirectory(cur_dir);

				if (cur_dir != mInitialWorkingDirectoryPath)
				{
					throw tc::TestException("DummyFileSystem: Working directory was not preserved by SubFileSystem.");
				}

				// check input was correct
				if (path != mExpectedSubfsBasePath + tc::io::Path("a_dir/testdir/hey"))
				{
					throw tc::TestException("DummyFileSystem: dir had incorrect path");
				}
			}
		private:
			tc::io::Path mInitialWorkingDirectoryPath;
			tc::io::Path mExpectedSubfsBasePath;
		};
	
		// define sub filesystem base path
		tc::io::Path subfilesystem_base_path = tc::io::Path("/home/jakcron/source/LibToolChain/testdir");

		// define base filesystem
		DummyFileSystem filesystem = DummyFileSystem(subfilesystem_base_path);

		// test sub filesystem creation & test translation of input to base filesystem
		try
		{
			// create sub filesystem
			tc::io::SubFileSystem sub_filesystem(std::make_shared<DummyFileSystem>(filesystem), subfilesystem_base_path);

			// attempt to remove directory
			sub_filesystem.removeDirectory(tc::io::Path("/a_dir/testdir/hey"));

			// record result
			test.result = "PASS";
			test.comments = "";
		}
		catch (const tc::TestException& e)
		{
			// record result
			test.result = "FAIL";
			test.comments = e.what();
		}
	}
	catch (const std::exception& e)
	{
		// record result
		test.result = "UNHANDLED EXCEPTION";
		test.comments = e.what();
	}

	// add result to list
	mTestResults.push_back(std::move(test));
}

void io_SubFileSystem_TestClass::testGetCanonicalPath()
{
	TestResult test;
	test.test_name = "testGetCanonicalPath";
	test.result = "NOT RUN";
	test.comments = "";
	
	try
	{
		class DummyFileSystem : public FileSystemTestUtil::DummyFileSystemBase
		{
		public:
			DummyFileSystem(const tc::io::Path& expected_subfs_base) :
				mExpectedSubfsBasePath(expected_subfs_base)
			{
				getWorkingDirectory(mInitialWorkingDirectoryPath);
			}

			void getCanonicalPath(const tc::io::Path& path, tc::io::Path& canon_path)
			{
				// validate base working directory was preserved
				tc::io::Path cur_dir;
				getWorkingDirectory(cur_dir);

				if (cur_dir != mInitialWorkingDirectoryPath)
				{
					throw tc::TestException("DummyFileSystem: Working directory was not preserved by SubFileSystem.");
				}

				// check input was correct
				if (path != mExpectedSubfsBasePath + tc::io::Path("a_dir/testdir/hey"))
				{
					throw tc::TestException("DummyFileSystem: dir had incorrect path");
				}

				canon_path = mExpectedSubfsBasePath + tc::io::Path("a_dir/canondir/hey");
			}
		private:
			tc::io::Path mInitialWorkingDirectoryPath;
			tc::io::Path mExpectedSubfsBasePath;
		};
	
		// define sub filesystem base path
		tc::io::Path subfilesystem_base_path = tc::io::Path("/home/jakcron/source/LibToolChain/testdir");

		// define base filesystem
		DummyFileSystem filesystem = DummyFileSystem(subfilesystem_base_path);

		// test sub filesystem creation & test translation of input to base filesystem
		try
		{
			// create sub filesystem
			tc::io::SubFileSystem sub_filesystem(std::make_shared<DummyFileSystem>(filesystem), subfilesystem_base_path);

			// get canon path
			tc::io::Path canonised_path;
			sub_filesystem.getCanonicalPath(tc::io::Path("/a_dir/testdir/hey"), canonised_path);

			// to be clear, this is not an example of how getCanonicalPath() should be treating paths, but rather the passthrough behaviour of SubFileSystem
			tc::io::Path expected_canonised_path = tc::io::Path("/a_dir/canondir/hey");
			if (canonised_path != expected_canonised_path)
			{
				throw tc::TestException(fmt::format("SubFileSystem: Sub canon path was not as expected (returned: \"{:s}\", expected: \"{:s}\"", canonised_path.to_string(), expected_canonised_path.to_string()));
			}

			// record result
			test.result = "PASS";
			test.comments = "";
		}
		catch (const tc::TestException& e)
		{
			// record result
			test.result = "FAIL";
			test.comments = e.what();
		}
	}
	catch (const std::exception& e)
	{
		// record result
		test.result = "UNHANDLED EXCEPTION";
		test.comments = e.what();
	}

	// add result to list
	mTestResults.push_back(std::move(test));
}

void io_SubFileSystem_TestClass::testGetDirectoryListing()
{
	TestResult test;
	test.test_name = "testGetDirectoryListing";
	test.result = "NOT RUN";
	test.comments = "";
	
	try
	{
		class DummyFileSystem : public FileSystemTestUtil::DummyFileSystemBase
		{
		public:
			DummyFileSystem(const tc::io::Path& expected_subfs_base) :
				mExpectedSubfsBasePath(expected_subfs_base)
			{
				getWorkingDirectory(mInitialWorkingDirectoryPath);
			}

			void getDirectoryListing(const tc::io::Path& path, tc::io::sDirectoryListing& dir_info)
			{
				// validate base working directory was preserved
				tc::io::Path cur_dir;
				getWorkingDirectory(cur_dir);

				if (cur_dir != mInitialWorkingDirectoryPath)
				{
					throw tc::TestException("DummyFileSystem: Working directory was not preserved by SubFileSystem.");
				}

				// check input was correct
				if (path != mExpectedSubfsBasePath + tc::io::Path("a_dir/testdir/hey"))
				{
					throw tc::TestException("DummyFileSystem: dir had incorrect path");
				}

				dir_info.abs_path = path;
				dir_info.dir_list = std::vector<std::string>({ "dir0", "dir1", "dir2" });
				dir_info.file_list = std::vector<std::string>({ "file0", "file1" });
			}
		private:
			tc::io::Path mInitialWorkingDirectoryPath;
			tc::io::Path mExpectedSubfsBasePath;
		};
	
		// define sub filesystem base path
		tc::io::Path subfilesystem_base_path = tc::io::Path("/home/jakcron/source/LibToolChain/testdir");

		// define base filesystem
		DummyFileSystem filesystem = DummyFileSystem(subfilesystem_base_path);

		// test sub filesystem creation & test translation of input to base filesystem
		try
		{
			// create sub filesystem
			tc::io::SubFileSystem sub_filesystem(std::make_shared<DummyFileSystem>(filesystem), subfilesystem_base_path);

			// save sub filesystem dir info
			tc::io::sDirectoryListing sb_dir_info;
			sub_filesystem.getDirectoryListing(tc::io::Path("/a_dir/testdir/hey"), sb_dir_info);

			// save real dir info
			tc::io::sDirectoryListing real_dir_info;
			filesystem.getDirectoryListing(subfilesystem_base_path + tc::io::Path("a_dir/testdir/hey"), real_dir_info);

			if (sb_dir_info.file_list != real_dir_info.file_list)
			{
				throw tc::TestException("DummyFileSystem: File list was not as expected");
			}

			if (sb_dir_info.dir_list != real_dir_info.dir_list)
			{
				throw tc::TestException("DummyFileSystem: Directory list was not as expected");
			}

			tc::io::Path fixed_sub_filesystem_path;
			for (tc::io::Path::const_iterator itr = sb_dir_info.abs_path.begin(); itr != sb_dir_info.abs_path.end(); itr++)
			{
				if (*itr == "" && itr == sb_dir_info.abs_path.begin())
				{
					continue;
				}

				fixed_sub_filesystem_path.push_back(*itr);
			}

			if ((subfilesystem_base_path + fixed_sub_filesystem_path) != real_dir_info.abs_path)
			{
				throw tc::TestException("DummyFileSystem: Directory absolute path was not as expected");
			}

			// record result
			test.result = "PASS";
			test.comments = "";
		}
		catch (const tc::TestException& e)
		{
			// record result
			test.result = "FAIL";
			test.comments = e.what();
		}
	}
	catch (const std::exception& e)
	{
		// record result
		test.result = "UNHANDLED EXCEPTION";
		test.comments = e.what();
	}

	// add result to list
	mTestResults.push_back(std::move(test));
}

void io_SubFileSystem_TestClass::testNavigateUpSubFileSystemEscape()
{
	TestResult test;
	test.test_name = "testNavigateUpSubFileSystemEscape";
	test.result = "NOT RUN";
	test.comments = "";
	
	try
	{
		class DummyFileSystem : public FileSystemTestUtil::DummyFileSystemBase
		{
		public:
			DummyFileSystem() :
				mLastUsedPath(new tc::io::Path())
			{
			}

			void getDirectoryListing(const tc::io::Path& path, tc::io::sDirectoryListing& dir_info)
			{			
				dir_info.abs_path = path;
				*mLastUsedPath = path;
			}

			const tc::io::Path& getLastUsedPath()
			{
				return *mLastUsedPath;
			}
		private:
			std::shared_ptr<tc::io::Path> mLastUsedPath;
		};

		DummyFileSystem filesystem;

		// save the current directory
		tc::io::Path dummyio_curdir = tc::io::Path("/home/jakcron/source/LibToolChain");

		// define directory names
		tc::io::Path testdir_path = tc::io::Path("testdir");
		tc::io::Path sub_filesystem_relative_root = testdir_path + tc::io::Path("subfilesystem");

		// test navigating outside of sub filesystem with ".." navigation
		try
		{
			// get sub filesystem
			tc::io::SubFileSystem sub_filesystem(std::make_shared<DummyFileSystem>(filesystem), dummyio_curdir + sub_filesystem_relative_root);

			// get info about current directory
			tc::io::sDirectoryListing dir_info;
			sub_filesystem.getDirectoryListing(tc::io::Path("./../../../../../../../../../../../../../..///./././"), dir_info);
			
			if (dir_info.abs_path != tc::io::Path("/"))
			{
				throw tc::TestException("SubFileSystem directory path not as expected");
			}

			if (filesystem.getLastUsedPath() != dummyio_curdir + sub_filesystem_relative_root)
			{
				throw tc::TestException("Real directory path not as expected");
			}

			// record result
			test.result = "PASS";
			test.comments = "";
		}
		catch (const tc::TestException& e)
		{
			// record result
			test.result = "FAIL";
			test.comments = e.what();
		}
	}
	catch (const std::exception& e)
	{
		// record result
		test.result = "UNHANDLED EXCEPTION";
		test.comments = e.what();
	}

	// add result to list
	mTestResults.push_back(std::move(test));
}

void io_SubFileSystem_TestClass::testOpenFileOutsideSubFileSystem()
{
	TestResult test;
	test.test_name = "testOpenFileOutsideSubFileSystem";
	test.result = "NOT RUN";
	test.comments = "";
	
	try
	{
		class DummyFileSystem : public FileSystemTestUtil::DummyFileSystemBase
		{
		public:
			DummyFileSystem()
			{
			}

			void openFile(const tc::io::Path& path, tc::io::FileMode mode, tc::io::FileAccess access, std::shared_ptr<tc::io::IStream>& stream)
			{
				tc::io::Path mCurDir;
				getWorkingDirectory(mCurDir);
				if (mode != tc::io::FileMode::Open || access != tc::io::FileAccess::Read)
				{
					throw tc::TestException("DummyFileSystem: file had incorrect access mode");
				}
				if (path == tc::io::Path("/home/jakcron/source/LibToolChain/testdir/inaccessible_file0"))
				{
					throw tc::TestException("DummyFileSystem: escaped sub filesystem");
				}
				if (path != tc::io::Path("/home/jakcron/source/LibToolChain/testdir/subfilesystem/inaccessible_file0"))
				{
					throw tc::TestException("DummyFileSystem: sub filesystem path was not as expected");
				}
			}
		};

		DummyFileSystem filesystem;

		// save the current directory
		tc::io::Path dummyio_curdir = tc::io::Path("/home/jakcron/source/LibToolChain");

		// define directory names
		tc::io::Path testdir_path = tc::io::Path("testdir");
		tc::io::Path sub_filesystem_relative_root = testdir_path + tc::io::Path("subfilesystem");

		// test accessing file outside of sub filesystem
		try {
			// create sub filesystem
			tc::io::SubFileSystem sub_filesystem(std::make_shared<DummyFileSystem>(filesystem), dummyio_curdir + sub_filesystem_relative_root);
			  
			// try to open the file just outside the sub filesystem
			sub_filesystem.setWorkingDirectory(tc::io::Path("/"));
			std::shared_ptr<tc::io::IStream> inaccessible_file;
			sub_filesystem.openFile(tc::io::Path("../inaccessible_file0"), tc::io::FileMode::Open, tc::io::FileAccess::Read, inaccessible_file);

			// record result
			test.result = "PASS";
			test.comments = "";
		}
		catch (const tc::TestException& e)
		{
			// record result
			test.result = "FAIL";
			test.comments = e.what();
		}
	}
	catch (const std::exception& e)
	{
		// record result
		test.result = "UNHANDLED EXCEPTION";
		test.comments = e.what();
	}

	// add result to list
	mTestResults.push_back(std::move(test));
}