#include "encode_Base64Util_TestClass.h"

#include <fmt/format.h>

//---------------------------------------------------------

encode_Base64Util_TestClass::encode_Base64Util_TestClass() :
	mTestTag("tc::encode::Base64Util"),
	mTestResults()
{
}

void encode_Base64Util_TestClass::runAllTests(void)
{
	testEncodeDataAsBase64();
	testEncodeStringAsBase64();
	testDecodeBase64AsData();
	testDecodeBase64AsString();
}

const std::string& encode_Base64Util_TestClass::getTestTag() const
{
	return mTestTag;
}

const std::vector<ITestClass::TestResult>& encode_Base64Util_TestClass::getTestResults() const
{
	return mTestResults;
}

//---------------------------------------------------------

void encode_Base64Util_TestClass::testEncodeDataAsBase64()
{
	TestResult test;
	test.test_name = "testEncodeDataAsBase64";
	test.result = "NOT RUN";
	test.comments = "";

	try
	{
		struct TestCase
		{
			std::string test_name;
			std::string in_string;
			tc::ByteData in_data;
			std::string out_base64;
		};

		// create happy path tests
		std::vector<TestCase> tests = 
		{
			{ "empty data", std::string(), tc::ByteData(), std::string()},
			{ "single space", " ", tc::cli::FormatUtil::hexStringToBytes("20"), "IA=="},
			{ "ascii string", "The quick brown fox jumps over the lazy dog.", tc::cli::FormatUtil::hexStringToBytes("54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e"), "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4="},
			{ "512 bytes binary data", std::string(), tc::cli::FormatUtil::hexStringToBytes("85d278fb18be42a62a56b495d4ab56a803fad5a1c66153b0c8a8628c3222fe55c500fa9721d5bfebff31ec59dcf810ac4bd0d2939ae045e7fcc34a432b45aca93e2a7a35b8208e75e1477d02bfd2175ae4a2d68dbf1a882249ca3f2b36586db700fb47e954f9233c9a2227e850957bbb1f3da6e9b4693d38e09434a691451b897c8b1fbbd5de4921e1f84fc136dd1b9297ad5e065556cd2ce52ec6eed8133d83bfc4e54c7d715de5e2b7eed9898b9b5eebbd5d07ae22f83d87218f7fe7355b5b6379e4a3eb27d48a9e042aa637063aac9a0b7bc104758bee61321183c0bb1ffb8ceb8c3d0cbbd5a55fe7809df89bf0883d8d7c762673fbfc5fceb6b14b4b1a828da5059cb090a2286ae7efc64b09e033d70cb6a528c54cea3d90f35b8fdfd73a1e85604c827cf5719b488e37b8cda2e2baba5cec43b1d031e7e4a47f3baedb00c037779a6f0e9fab5c9c3c84236458378847acd174083570c628074417ebba551853299eea400dfa95a8aff5f1fd9c314225365023ee31a03930c0029d57feb81417d57f9f45f225faa3790c0b239891c82151a7449507cab70376975ba9f2e68f5e37544f848faf875b9e24dccb9c556aae2a57a7f369581d50dfdf06fdff27fd2107db080c4d9e1c100427a1493ddb5e80e43f943bbbad9113448b658a5a5cdefd70e57d0b28e2bd942a978179eb88d6661b30f2b5b346fff1d0a5c9b93d2d"), "hdJ4+xi+QqYqVrSV1KtWqAP61aHGYVOwyKhijDIi/lXFAPqXIdW/6/8x7Fnc+BCsS9DSk5rgRef8w0pDK0WsqT4qejW4II514Ud9Ar/SF1rkotaNvxqIIknKPys2WG23APtH6VT5IzyaIifoUJV7ux89pum0aT044JQ0ppFFG4l8ix+71d5JIeH4T8E23RuSl61eBlVWzSzlLsbu2BM9g7/E5Ux9cV3l4rfu2YmLm17rvV0HriL4PYchj3/nNVtbY3nko+sn1IqeBCqmNwY6rJoLe8EEdYvuYTIRg8C7H/uM64w9DLvVpV/ngJ34m/CIPY18diZz+/xfzraxS0sago2lBZywkKIoaufvxksJ4DPXDLalKMVM6j2Q81uP39c6HoVgTIJ89XGbSI43uM2i4rq6XOxDsdAx5+Skfzuu2wDAN3eabw6fq1ycPIQjZFg3iEes0XQINXDGKAdEF+u6VRhTKZ7qQA36laiv9fH9nDFCJTZQI+4xoDkwwAKdV/64FBfVf59F8iX6o3kMCyOYkcghUadElQfKtwN2l1up8uaPXjdUT4SPr4dbniTcy5xVaq4qV6fzaVgdUN/fBv3/J/0hB9sIDE2eHBAEJ6FJPdtegOQ/lDu7rZETRItlilpc3v1w5X0LKOK9lCqXgXnriNZmGzDytbNG//HQpcm5PS0="},
		};

		// run error path tests
		{
			std::string out = tc::encode::Base64Util::encodeDataAsBase64(nullptr, 0xdeadbeef);

			if (out != "")
			{
				throw tc::TestException(fmt::format("encodeDataAsBase64() did not return an empty string for invalid input: data=nullptr, size=0xdeadbeef"));
			}
		}

		// run happy path tests
		for (auto test = tests.begin(); test != tests.end(); test++)
		{
			std::string out_1 = tc::encode::Base64Util::encodeDataAsBase64(test->in_data);
			std::string out_2 = tc::encode::Base64Util::encodeDataAsBase64(test->in_data.data(), test->in_data.size());

			if (out_1 != test->out_base64)
			{
				throw tc::TestException(fmt::format("Test({:s}) to convert data({:s}) to base64, returned \"{:s}\" (should be: \"{:s}\")", test->test_name, tc::cli::FormatUtil::formatBytesAsString(test->in_data, false, ""), out_1, test->out_base64));
			}

			if (out_2 != test->out_base64)
			{
				throw tc::TestException(fmt::format("Test({:s}) to convert data({:s}), size({:d}) to base64, returned \"{:s}\" (should be: \"{:s}\")", test->test_name, tc::cli::FormatUtil::formatBytesAsString(test->in_data.data(), test->in_data.size(), false, ""), test->in_data.size(), out_2, test->out_base64));
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
	catch (const std::exception& e)
	{
		// record result
		test.result = "UNHANDLED EXCEPTION";
		test.comments = e.what();
	}

	// add result to list
	mTestResults.push_back(std::move(test));
}

void encode_Base64Util_TestClass::testEncodeStringAsBase64()
{
	TestResult test;
	test.test_name = "testEncodeStringAsBase64";
	test.result = "NOT RUN";
	test.comments = "";

	try
	{
		struct TestCase
		{
			std::string test_name;
			std::string in_string;
			tc::ByteData in_data;
			std::string out_base64;
		};

		// create happy path tests
		std::vector<TestCase> tests = 
		{
			{ "empty data", std::string(), tc::ByteData(), std::string()},
			{ "single space", " ", tc::cli::FormatUtil::hexStringToBytes("20"), "IA=="},
			{ "ascii string", "The quick brown fox jumps over the lazy dog.", tc::cli::FormatUtil::hexStringToBytes("54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e"), "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4="},
			// skip binary test as not a string
			//{ "512 bytes binary data", std::string(), tc::cli::FormatUtil::hexStringToBytes("85d278fb18be42a62a56b495d4ab56a803fad5a1c66153b0c8a8628c3222fe55c500fa9721d5bfebff31ec59dcf810ac4bd0d2939ae045e7fcc34a432b45aca93e2a7a35b8208e75e1477d02bfd2175ae4a2d68dbf1a882249ca3f2b36586db700fb47e954f9233c9a2227e850957bbb1f3da6e9b4693d38e09434a691451b897c8b1fbbd5de4921e1f84fc136dd1b9297ad5e065556cd2ce52ec6eed8133d83bfc4e54c7d715de5e2b7eed9898b9b5eebbd5d07ae22f83d87218f7fe7355b5b6379e4a3eb27d48a9e042aa637063aac9a0b7bc104758bee61321183c0bb1ffb8ceb8c3d0cbbd5a55fe7809df89bf0883d8d7c762673fbfc5fceb6b14b4b1a828da5059cb090a2286ae7efc64b09e033d70cb6a528c54cea3d90f35b8fdfd73a1e85604c827cf5719b488e37b8cda2e2baba5cec43b1d031e7e4a47f3baedb00c037779a6f0e9fab5c9c3c84236458378847acd174083570c628074417ebba551853299eea400dfa95a8aff5f1fd9c314225365023ee31a03930c0029d57feb81417d57f9f45f225faa3790c0b239891c82151a7449507cab70376975ba9f2e68f5e37544f848faf875b9e24dccb9c556aae2a57a7f369581d50dfdf06fdff27fd2107db080c4d9e1c100427a1493ddb5e80e43f943bbbad9113448b658a5a5cdefd70e57d0b28e2bd942a978179eb88d6661b30f2b5b346fff1d0a5c9b93d2d"), "hdJ4+xi+QqYqVrSV1KtWqAP61aHGYVOwyKhijDIi/lXFAPqXIdW/6/8x7Fnc+BCsS9DSk5rgRef8w0pDK0WsqT4qejW4II514Ud9Ar/SF1rkotaNvxqIIknKPys2WG23APtH6VT5IzyaIifoUJV7ux89pum0aT044JQ0ppFFG4l8ix+71d5JIeH4T8E23RuSl61eBlVWzSzlLsbu2BM9g7/E5Ux9cV3l4rfu2YmLm17rvV0HriL4PYchj3/nNVtbY3nko+sn1IqeBCqmNwY6rJoLe8EEdYvuYTIRg8C7H/uM64w9DLvVpV/ngJ34m/CIPY18diZz+/xfzraxS0sago2lBZywkKIoaufvxksJ4DPXDLalKMVM6j2Q81uP39c6HoVgTIJ89XGbSI43uM2i4rq6XOxDsdAx5+Skfzuu2wDAN3eabw6fq1ycPIQjZFg3iEes0XQINXDGKAdEF+u6VRhTKZ7qQA36laiv9fH9nDFCJTZQI+4xoDkwwAKdV/64FBfVf59F8iX6o3kMCyOYkcghUadElQfKtwN2l1up8uaPXjdUT4SPr4dbniTcy5xVaq4qV6fzaVgdUN/fBv3/J/0hB9sIDE2eHBAEJ6FJPdtegOQ/lDu7rZETRItlilpc3v1w5X0LKOK9lCqXgXnriNZmGzDytbNG//HQpcm5PS0="},
		};

		// run error path tests
		{
			std::string out = tc::encode::Base64Util::encodeStringAsBase64(nullptr, 0xdeadbeef);

			if (out != "")
			{
				throw tc::TestException(fmt::format("encodeStringAsBase64() did not return an empty string for invalid input: str=nullptr, size=0xdeadbeef"));
			}
		}

		// run happy path tests
		for (auto test = tests.begin(); test != tests.end(); test++)
		{
			std::string out_1 = tc::encode::Base64Util::encodeStringAsBase64(test->in_string);
			std::string out_2 = tc::encode::Base64Util::encodeStringAsBase64(test->in_string.c_str(), test->in_string.size());

			if (out_1 != test->out_base64)
			{
				throw tc::TestException(fmt::format("Test({:s}) to convert str({:s}) to base64, returned \"{:s}\" (should be: \"{:s}\")", test->test_name, test->in_string, out_1, test->out_base64));
			}

			if (out_2 != test->out_base64)
			{
				throw tc::TestException(fmt::format("Test({:s}) to convert str({:s}), size({:d}) to base64, returned \"{:s}\" (should be: \"{:s}\")", test->test_name, test->in_string.c_str(), test->in_string.size(), test->in_data.size(), out_2, test->out_base64));
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
	catch (const std::exception& e)
	{
		// record result
		test.result = "UNHANDLED EXCEPTION";
		test.comments = e.what();
	}

	// add result to list
	mTestResults.push_back(std::move(test));
}

void encode_Base64Util_TestClass::testDecodeBase64AsData()
{
	TestResult test;
	test.test_name = "testDecodeBase64AsData";
	test.result = "NOT RUN";
	test.comments = "";

	try
	{
		struct TestCase
		{
			std::string test_name;
			std::string in_string;
			tc::ByteData in_data;
			std::string out_base64;
		};

		// create happy path tests
		std::vector<TestCase> tests = 
		{
			{ "empty data", std::string(), tc::ByteData(), std::string()},
			{ "single space", " ", tc::cli::FormatUtil::hexStringToBytes("20"), "IA=="},
			{ "ascii string", "The quick brown fox jumps over the lazy dog.", tc::cli::FormatUtil::hexStringToBytes("54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e"), "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4="},
			{ "512 bytes binary data", std::string(), tc::cli::FormatUtil::hexStringToBytes("85d278fb18be42a62a56b495d4ab56a803fad5a1c66153b0c8a8628c3222fe55c500fa9721d5bfebff31ec59dcf810ac4bd0d2939ae045e7fcc34a432b45aca93e2a7a35b8208e75e1477d02bfd2175ae4a2d68dbf1a882249ca3f2b36586db700fb47e954f9233c9a2227e850957bbb1f3da6e9b4693d38e09434a691451b897c8b1fbbd5de4921e1f84fc136dd1b9297ad5e065556cd2ce52ec6eed8133d83bfc4e54c7d715de5e2b7eed9898b9b5eebbd5d07ae22f83d87218f7fe7355b5b6379e4a3eb27d48a9e042aa637063aac9a0b7bc104758bee61321183c0bb1ffb8ceb8c3d0cbbd5a55fe7809df89bf0883d8d7c762673fbfc5fceb6b14b4b1a828da5059cb090a2286ae7efc64b09e033d70cb6a528c54cea3d90f35b8fdfd73a1e85604c827cf5719b488e37b8cda2e2baba5cec43b1d031e7e4a47f3baedb00c037779a6f0e9fab5c9c3c84236458378847acd174083570c628074417ebba551853299eea400dfa95a8aff5f1fd9c314225365023ee31a03930c0029d57feb81417d57f9f45f225faa3790c0b239891c82151a7449507cab70376975ba9f2e68f5e37544f848faf875b9e24dccb9c556aae2a57a7f369581d50dfdf06fdff27fd2107db080c4d9e1c100427a1493ddb5e80e43f943bbbad9113448b658a5a5cdefd70e57d0b28e2bd942a978179eb88d6661b30f2b5b346fff1d0a5c9b93d2d"), "hdJ4+xi+QqYqVrSV1KtWqAP61aHGYVOwyKhijDIi/lXFAPqXIdW/6/8x7Fnc+BCsS9DSk5rgRef8w0pDK0WsqT4qejW4II514Ud9Ar/SF1rkotaNvxqIIknKPys2WG23APtH6VT5IzyaIifoUJV7ux89pum0aT044JQ0ppFFG4l8ix+71d5JIeH4T8E23RuSl61eBlVWzSzlLsbu2BM9g7/E5Ux9cV3l4rfu2YmLm17rvV0HriL4PYchj3/nNVtbY3nko+sn1IqeBCqmNwY6rJoLe8EEdYvuYTIRg8C7H/uM64w9DLvVpV/ngJ34m/CIPY18diZz+/xfzraxS0sago2lBZywkKIoaufvxksJ4DPXDLalKMVM6j2Q81uP39c6HoVgTIJ89XGbSI43uM2i4rq6XOxDsdAx5+Skfzuu2wDAN3eabw6fq1ycPIQjZFg3iEes0XQINXDGKAdEF+u6VRhTKZ7qQA36laiv9fH9nDFCJTZQI+4xoDkwwAKdV/64FBfVf59F8iX6o3kMCyOYkcghUadElQfKtwN2l1up8uaPXjdUT4SPr4dbniTcy5xVaq4qV6fzaVgdUN/fBv3/J/0hB9sIDE2eHBAEJ6FJPdtegOQ/lDu7rZETRItlilpc3v1w5X0LKOK9lCqXgXnriNZmGzDytbNG//HQpcm5PS0="},
		};

		// run error path tests
		{
			tc::ByteData out = tc::encode::Base64Util::decodeBase64AsData(nullptr, 0xdeadbeef);

			if (out.data() != nullptr || out.size() != 0)
			{
				throw tc::TestException(fmt::format("decodeBase64AsData() did not return an empty tc::ByteData for invalid input: str=nullptr, size=0xdeadbeef"));
			}
		}
		{
			tc::ByteData out = tc::encode::Base64Util::decodeBase64AsData("not base 64");

			if (out.data() != nullptr || out.size() != 0)
			{
				throw tc::TestException(fmt::format("decodeBase64AsData() did not return an empty tc::ByteData for invalid input: str=\"not base 64\""));
			}
		}

		// run happy path tests
		for (auto test = tests.begin(); test != tests.end(); test++)
		{
			tc::ByteData out_1 = tc::encode::Base64Util::decodeBase64AsData(test->out_base64);
			tc::ByteData out_2 = tc::encode::Base64Util::decodeBase64AsData(test->out_base64.data(), test->out_base64.size());

			// size should match
			if (out_1.size() != test->in_data.size())
			{
				throw tc::TestException(fmt::format("Test({:s}) to convert str({:s}) from base64, size was \"{:d}\" (should be: \"{:d}\")", test->test_name, test->out_base64, out_1.size(), test->in_data.size()));
			}

			// if expected data was nullptr, so should actual
			if (test->in_data.data() == nullptr && out_1.data() != nullptr)
			{
				throw tc::TestException(fmt::format("Test({:s}) to convert str({:s}) from base64, ret.data() should have been null", test->test_name, test->out_base64));
			}

			// if the data was matching and non-zero, they should also match
			if (memcmp(out_2.data(), test->in_data.data(), test->in_data.size()) != 0)
			{
				throw tc::TestException(fmt::format("Test({:s}) to convert str({:s}) from base64, returned \"{:s}\" (should be: \"{:s}\")", test->test_name, test->out_base64, tc::cli::FormatUtil::formatBytesAsString(out_2, false, ""), tc::cli::FormatUtil::formatBytesAsString(test->in_data, false, "")));
			}

			// size should match
			if (out_2.size() != test->in_data.size())
			{
				throw tc::TestException(fmt::format("Test({:s}) to convert str({:s}), size({:d}) from base64, size was \"{:d}\" (should be: \"{:d}\")", test->test_name, test->out_base64.c_str(), test->out_base64.size(), out_2.size(), test->in_data.size()));
			}

			// if expected data was nullptr, so should actual
			if (test->in_data.data() == nullptr && out_2.data() != nullptr)
			{
				throw tc::TestException(fmt::format("Test({:s}) to convert str({:s}), size({:d}) from base64, ret.data() should have been null", test->test_name, test->out_base64.c_str(), test->out_base64.size()));
			}

			// if the data was matching and non-zero, they should also match
			if (memcmp(out_2.data(), test->in_data.data(), test->in_data.size()) != 0)
			{
				throw tc::TestException(fmt::format("Test({:s}) to convert str({:s}), size({:d}) from base64, returned \"{:s}\" (should be: \"{:s}\")", test->test_name, test->out_base64.c_str(), test->out_base64.size(), tc::cli::FormatUtil::formatBytesAsString(out_1, false, ""), tc::cli::FormatUtil::formatBytesAsString(test->in_data, false, "")));
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
	catch (const std::exception& e)
	{
		// record result
		test.result = "UNHANDLED EXCEPTION";
		test.comments = e.what();
	}

	// add result to list
	mTestResults.push_back(std::move(test));
}

void encode_Base64Util_TestClass::testDecodeBase64AsString()
{
	TestResult test;
	test.test_name = "testDecodeBase64AsString";
	test.result = "NOT RUN";
	test.comments = "";

	try
	{
		struct TestCase
		{
			std::string test_name;
			std::string in_string;
			tc::ByteData in_data;
			std::string out_base64;
		};

		// create happy path tests
		std::vector<TestCase> tests = 
		{
			{ "empty data", std::string(), tc::ByteData(), std::string()},
			{ "single space", " ", tc::cli::FormatUtil::hexStringToBytes("20"), "IA=="},
			{ "ascii string", "The quick brown fox jumps over the lazy dog.", tc::cli::FormatUtil::hexStringToBytes("54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e"), "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4="},
			// skip binary test as not a string
			//{ "512 bytes binary data", std::string(), tc::cli::FormatUtil::hexStringToBytes("85d278fb18be42a62a56b495d4ab56a803fad5a1c66153b0c8a8628c3222fe55c500fa9721d5bfebff31ec59dcf810ac4bd0d2939ae045e7fcc34a432b45aca93e2a7a35b8208e75e1477d02bfd2175ae4a2d68dbf1a882249ca3f2b36586db700fb47e954f9233c9a2227e850957bbb1f3da6e9b4693d38e09434a691451b897c8b1fbbd5de4921e1f84fc136dd1b9297ad5e065556cd2ce52ec6eed8133d83bfc4e54c7d715de5e2b7eed9898b9b5eebbd5d07ae22f83d87218f7fe7355b5b6379e4a3eb27d48a9e042aa637063aac9a0b7bc104758bee61321183c0bb1ffb8ceb8c3d0cbbd5a55fe7809df89bf0883d8d7c762673fbfc5fceb6b14b4b1a828da5059cb090a2286ae7efc64b09e033d70cb6a528c54cea3d90f35b8fdfd73a1e85604c827cf5719b488e37b8cda2e2baba5cec43b1d031e7e4a47f3baedb00c037779a6f0e9fab5c9c3c84236458378847acd174083570c628074417ebba551853299eea400dfa95a8aff5f1fd9c314225365023ee31a03930c0029d57feb81417d57f9f45f225faa3790c0b239891c82151a7449507cab70376975ba9f2e68f5e37544f848faf875b9e24dccb9c556aae2a57a7f369581d50dfdf06fdff27fd2107db080c4d9e1c100427a1493ddb5e80e43f943bbbad9113448b658a5a5cdefd70e57d0b28e2bd942a978179eb88d6661b30f2b5b346fff1d0a5c9b93d2d"), "hdJ4+xi+QqYqVrSV1KtWqAP61aHGYVOwyKhijDIi/lXFAPqXIdW/6/8x7Fnc+BCsS9DSk5rgRef8w0pDK0WsqT4qejW4II514Ud9Ar/SF1rkotaNvxqIIknKPys2WG23APtH6VT5IzyaIifoUJV7ux89pum0aT044JQ0ppFFG4l8ix+71d5JIeH4T8E23RuSl61eBlVWzSzlLsbu2BM9g7/E5Ux9cV3l4rfu2YmLm17rvV0HriL4PYchj3/nNVtbY3nko+sn1IqeBCqmNwY6rJoLe8EEdYvuYTIRg8C7H/uM64w9DLvVpV/ngJ34m/CIPY18diZz+/xfzraxS0sago2lBZywkKIoaufvxksJ4DPXDLalKMVM6j2Q81uP39c6HoVgTIJ89XGbSI43uM2i4rq6XOxDsdAx5+Skfzuu2wDAN3eabw6fq1ycPIQjZFg3iEes0XQINXDGKAdEF+u6VRhTKZ7qQA36laiv9fH9nDFCJTZQI+4xoDkwwAKdV/64FBfVf59F8iX6o3kMCyOYkcghUadElQfKtwN2l1up8uaPXjdUT4SPr4dbniTcy5xVaq4qV6fzaVgdUN/fBv3/J/0hB9sIDE2eHBAEJ6FJPdtegOQ/lDu7rZETRItlilpc3v1w5X0LKOK9lCqXgXnriNZmGzDytbNG//HQpcm5PS0="},
		};

		// run error path tests
		{
			std::string out = tc::encode::Base64Util::decodeBase64AsString(nullptr, 0xdeadbeef);

			if (out != "")
			{
				throw tc::TestException(fmt::format("decodeBase64AsString() did not return an empty string for invalid input: str=nullptr, size=0xdeadbeef"));
			}
		}
		{
			std::string out = tc::encode::Base64Util::decodeBase64AsString("not base 64");

			if (out != "")
			{
				throw tc::TestException(fmt::format("decodeBase64AsString() did not return an empty string for invalid input: str=\"not base 64\""));
			}
		}

		// run happy path tests
		for (auto test = tests.begin(); test != tests.end(); test++)
		{
			std::string out_1 = tc::encode::Base64Util::decodeBase64AsString(test->out_base64);
			std::string out_2 = tc::encode::Base64Util::decodeBase64AsString(test->out_base64.data(), test->out_base64.size());

			if (out_1 != test->in_string)
			{
				throw tc::TestException(fmt::format("Test({:s}) to convert str({:s}) from base64, returned \"{:s}\" (should be: \"{:s}\")", test->test_name, test->out_base64, out_1, test->in_string));
			}

			if (out_2 != test->in_string)
			{
				throw tc::TestException(fmt::format("Test({:s}) to convert str({:s}), size({:d}) from base64, returned \"{:s}\" (should be: \"{:s}\")", test->test_name, test->out_base64.c_str(), test->out_base64.size(), test->in_data.size(), out_2, test->in_string));
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
	catch (const std::exception& e)
	{
		// record result
		test.result = "UNHANDLED EXCEPTION";
		test.comments = e.what();
	}

	// add result to list
	mTestResults.push_back(std::move(test));
}