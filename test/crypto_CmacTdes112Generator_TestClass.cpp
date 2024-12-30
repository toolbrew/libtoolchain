#include "crypto_CmacTdes112Generator_TestClass.h"

#include <fmt/format.h>

#include <tc/crypto/CmacTdes112Generator.h>
#include <tc/cli/FormatUtil.h>
#include <tc/ByteData.h>

//---------------------------------------------------------

crypto_CmacTdes112Generator_TestClass::crypto_CmacTdes112Generator_TestClass() :
	mTestTag("tc::crypto::CmacTdes112Generator"),
	mTestResults()
{
}

void crypto_CmacTdes112Generator_TestClass::runAllTests(void)
{
	test_Constants();
	test_SingleUpdateCall();
	test_MultiUpdateCall();
	test_UtilFunc();

	test_NoInitNoUpdateDoMac();
	test_NoInitDoUpdateDoMac();
	test_InvalidKeyThrowsExceptionClass();
	test_InvalidKeyThrowsExceptionUtilFunc();

	test_CallGetMacRepeatedly();
}

const std::string& crypto_CmacTdes112Generator_TestClass::getTestTag() const
{
	return mTestTag;
}

const std::vector<ITestClass::TestResult>& crypto_CmacTdes112Generator_TestClass::getTestResults() const
{
	return mTestResults;
}

//---------------------------------------------------------

void crypto_CmacTdes112Generator_TestClass::test_Constants()
{
	TestResult test_result;
	test_result.test_name = "test_Constants";
	test_result.result = "NOT RUN";
	test_result.comments = "";

	try
	{
		// check key size
		static const size_t kExpectedKeySize = 16;
		size_t kKeySize = tc::crypto::CmacTdes112Generator::kKeySize;
		if (kKeySize != kExpectedKeySize)
		{				
			throw tc::TestException(fmt::format("kKeySize had value {:d} (expected {:d})", kKeySize, kExpectedKeySize));
		}
		
		// check mac size
		static const size_t kExpectedMacSize = 8;
		size_t kMacSize = tc::crypto::CmacTdes112Generator::kMacSize;
		if (kMacSize != kExpectedMacSize)
		{				
			throw tc::TestException(fmt::format("kMacSize had value {:d} (expected {:d})", kMacSize, kExpectedMacSize));
		}

		// check block size
		static const size_t kExpectedBlockSize = 8;
		size_t kBlockSize = tc::crypto::CmacTdes112Generator::kBlockSize;
		if (kBlockSize != kExpectedBlockSize)
		{				
			throw tc::TestException(fmt::format("kBlockSize had value {:d} (expected {:d})", kBlockSize, kExpectedBlockSize));
		}

		// record result
		test_result.result = "PASS";
		test_result.comments = "";
	}
	catch (const tc::TestException& e)
	{
		// record result
		test_result.result = "FAIL";
		test_result.comments = e.what();
	}
	catch (const std::exception& e)
	{
		// record result
		test_result.result = "UNHANDLED EXCEPTION";
		test_result.comments = e.what();
	}

	// add result to list
	mTestResults.push_back(std::move(test_result));
}

void crypto_CmacTdes112Generator_TestClass::test_SingleUpdateCall()
{
	TestResult test_result;
	test_result.test_name = "test_SingleUpdateCall";
	test_result.result = "NOT RUN";
	test_result.comments = "";

	try
	{
		// create tests
		std::vector<TestCase> test_cases;
		util_Setup_TestCases(test_cases);
		if (test_cases.begin() == test_cases.end())
		{
			throw tc::TestException("No test vectors");
		}

		tc::crypto::CmacTdes112Generator calc;
		tc::ByteData mac = tc::ByteData(tc::crypto::CmacTdes112Generator::kMacSize);

		for (auto test_case = test_cases.begin(); test_case != test_cases.end(); test_case++)
		{
			calc.initialize(test_case->in_key.data(), test_case->in_key.size());
			calc.update(test_case->in_data.data(), test_case->in_data.size());
			memset(mac.data(), 0xff, mac.size());
			calc.getMac(mac.data());
			if (memcmp(mac.data(), test_case->out_mac.data(), mac.size()) != 0)
			{					
				throw tc::TestException(fmt::format("Test \"{:s}\" Failed. Had wrong MAC: {:s} (expected {:s})", test_case->test_name, tc::cli::FormatUtil::formatBytesAsString(mac, true, ""), tc::cli::FormatUtil::formatBytesAsString(test_case->out_mac, true, "")));
			}
		}

		// record result
		test_result.result = "PASS";
		test_result.comments = "";
	}
	catch (const tc::TestException& e)
	{
		// record result
		test_result.result = "FAIL";
		test_result.comments = e.what();
	}
	catch (const std::exception& e)
	{
		// record result
		test_result.result = "UNHANDLED EXCEPTION";
		test_result.comments = e.what();
	}

	// add result to list
	mTestResults.push_back(std::move(test_result));
}

void crypto_CmacTdes112Generator_TestClass::test_MultiUpdateCall()
{
	TestResult test_result;
	test_result.test_name = "test_MultiUpdateCall";
	test_result.result = "NOT RUN";
	test_result.comments = "";

	try
	{
		// create tests
		std::vector<TestCase> test_cases;
		util_Setup_TestCases(test_cases);
		if (test_cases.begin() == test_cases.end())
		{
			throw tc::TestException("No test vectors");
		}

		tc::crypto::CmacTdes112Generator calc;
		tc::ByteData mac = tc::ByteData(tc::crypto::CmacTdes112Generator::kMacSize);

		for (auto test_case = test_cases.begin(); test_case != test_cases.end(); test_case++)
		{
			calc.initialize(test_case->in_key.data(), test_case->in_key.size());

			// pick an offset to split the in_data at
			size_t offset = test_case->in_data.size() / 2;

			// update with first half
			calc.update(test_case->in_data.data(), offset);

			// update with second half
			calc.update(test_case->in_data.data() + offset, test_case->in_data.size() - offset);
			
			memset(mac.data(), 0xff, mac.size());
			calc.getMac(mac.data());
			if (memcmp(mac.data(), test_case->out_mac.data(), mac.size()) != 0)
			{
				throw tc::TestException(fmt::format("Test \"{:s}\" Failed. Had wrong MAC: {:s} (expected {:s})", test_case->test_name, tc::cli::FormatUtil::formatBytesAsString(mac, true, ""), tc::cli::FormatUtil::formatBytesAsString(test_case->out_mac, true, "")));
			}
		}

		// record result
		test_result.result = "PASS";
		test_result.comments = "";
	}
	catch (const tc::TestException& e)
	{
		// record result
		test_result.result = "FAIL";
		test_result.comments = e.what();
	}
	catch (const std::exception& e)
	{
		// record result
		test_result.result = "UNHANDLED EXCEPTION";
		test_result.comments = e.what();
	}

	// add result to list
	mTestResults.push_back(std::move(test_result));
}

void crypto_CmacTdes112Generator_TestClass::test_UtilFunc()
{
	TestResult test_result;
	test_result.test_name = "test_UtilFunc";
	test_result.result = "NOT RUN";
	test_result.comments = "";

	try
	{
		// create tests
		std::vector<TestCase> test_cases;
		util_Setup_TestCases(test_cases);
		if (test_cases.begin() == test_cases.end())
		{
			throw tc::TestException("No test vectors");
		}

		tc::ByteData mac = tc::ByteData(tc::crypto::CmacTdes112Generator::kMacSize);

		for (auto test_case = test_cases.begin(); test_case != test_cases.end(); test_case++)
		{
			memset(mac.data(), 0xff, mac.size());
			tc::crypto::GenerateCmacTdes112Mac(mac.data(), test_case->in_data.data(), test_case->in_data.size(), test_case->in_key.data(), test_case->in_key.size());
			if (memcmp(mac.data(), test_case->out_mac.data(), mac.size()) != 0)
			{
				throw tc::TestException(fmt::format("Test \"{:s}\" Failed. Had wrong MAC: {:s} (expected {:s})", test_case->test_name, tc::cli::FormatUtil::formatBytesAsString(mac, true, ""), tc::cli::FormatUtil::formatBytesAsString(test_case->out_mac, true, "")));
			}
		}

		// record result
		test_result.result = "PASS";
		test_result.comments = "";
	}
	catch (const tc::TestException& e)
	{
		// record result
		test_result.result = "FAIL";
		test_result.comments = e.what();
	}
	catch (const std::exception& e)
	{
		// record result
		test_result.result = "UNHANDLED EXCEPTION";
		test_result.comments = e.what();
	}

	// add result to list
	mTestResults.push_back(std::move(test_result));
}

void crypto_CmacTdes112Generator_TestClass::test_NoInitNoUpdateDoMac()
{
	TestResult test_result;
	test_result.test_name = "test_NoInitNoUpdateDoMac";
	test_result.result = "NOT RUN";
	test_result.comments = "";

	try
	{
		// create tests
		std::vector<TestCase> test_cases;
		util_Setup_TestCases(test_cases);
		if (test_cases.begin() == test_cases.end())
		{
			throw tc::TestException("No test vectors");
		}

		tc::crypto::CmacTdes112Generator calc;
		tc::ByteData mac = tc::ByteData(tc::crypto::CmacTdes112Generator::kMacSize);
		tc::ByteData expected_uninitialized_mac = tc::ByteData(mac.size());
		memset(expected_uninitialized_mac.data(), 0xff, expected_uninitialized_mac.size());

		for (auto test_case = test_cases.begin(); test_case != test_cases.end(); test_case++)
		{
			//calc.initialize(test_case->in_key.data(), test_case->in_key.size());
			//calc.update(test_case->in_data.data(), test_case->in_data.size());
			memcpy(mac.data(), expected_uninitialized_mac.data(), mac.size());
			calc.getMac(mac.data());
			if (memcmp(mac.data(), expected_uninitialized_mac.data(), mac.size()) != 0)
			{
				throw tc::TestException(fmt::format("Test \"{:s}\" Failed. Had wrong MAC: {:s} (expected {:s})", test_case->test_name, tc::cli::FormatUtil::formatBytesAsString(mac, true, ""), tc::cli::FormatUtil::formatBytesAsString(test_case->out_mac, true, "")));
			}
		}

		// record result
		test_result.result = "PASS";
		test_result.comments = "";
	}
	catch (const tc::TestException& e)
	{
		// record result
		test_result.result = "FAIL";
		test_result.comments = e.what();
	}
	catch (const std::exception& e)
	{
		// record result
		test_result.result = "UNHANDLED EXCEPTION";
		test_result.comments = e.what();
	}

	// add result to list
	mTestResults.push_back(std::move(test_result));
}

void crypto_CmacTdes112Generator_TestClass::test_NoInitDoUpdateDoMac()
{
	TestResult test_result;
	test_result.test_name = "test_NoInitDoUpdateDoMac";
	test_result.result = "NOT RUN";
	test_result.comments = "";

	try
	{
		// create tests
		std::vector<TestCase> test_cases;
		util_Setup_TestCases(test_cases);
		if (test_cases.begin() == test_cases.end())
		{
			throw tc::TestException("No test vectors");
		}

		tc::crypto::CmacTdes112Generator calc;
		tc::ByteData mac = tc::ByteData(tc::crypto::CmacTdes112Generator::kMacSize);
		tc::ByteData expected_uninitialized_mac = tc::ByteData(mac.size());
		memset(expected_uninitialized_mac.data(), 0xff, expected_uninitialized_mac.size());

		for (auto test_case = test_cases.begin(); test_case != test_cases.end(); test_case++)
		{
			//calc.initialize(test_case->in_key.data(), test_case->in_key.size());
			calc.update(test_case->in_data.data(), test_case->in_data.size());
			memcpy(mac.data(), expected_uninitialized_mac.data(), mac.size());
			calc.getMac(mac.data());
			if (memcmp(mac.data(), expected_uninitialized_mac.data(), mac.size()) != 0)
			{
				throw tc::TestException(fmt::format("Test \"{:s}\" Failed. Had wrong MAC: {:s} (expected {:s})", test_case->test_name, tc::cli::FormatUtil::formatBytesAsString(mac, true, ""), tc::cli::FormatUtil::formatBytesAsString(test_case->out_mac, true, "")));
			}
		}

		// record result
		test_result.result = "PASS";
		test_result.comments = "";
	}
	catch (const tc::TestException& e)
	{
		// record result
		test_result.result = "FAIL";
		test_result.comments = e.what();
	}
	catch (const std::exception& e)
	{
		// record result
		test_result.result = "UNHANDLED EXCEPTION";
		test_result.comments = e.what();
	}

	// add result to list
	mTestResults.push_back(std::move(test_result));
}

void crypto_CmacTdes112Generator_TestClass::test_InvalidKeyThrowsExceptionClass()
{
	TestResult test_result;
	test_result.test_name = "test_InvalidKeyThrowsExceptionClass";
	test_result.result = "NOT RUN";
	test_result.comments = "";

	try
	{
		// create tests
		std::vector<TestCase> test_cases;
		util_Setup_TestCases(test_cases);
		if (test_cases.begin() == test_cases.end())
		{
			throw tc::TestException("No test vectors");
		}


		tc::crypto::CmacTdes112Generator calc;
		tc::ByteData mac = tc::ByteData(tc::crypto::CmacTdes112Generator::kMacSize);

		// try invalid key - key size == kKeySize-1 expected
		try
		{
			calc.initialize(test_cases[0].in_key.data(), test_cases[0].in_key.size() - 1);
			throw tc::TestException("Failed to throw ArgumentOutOfRangeException where key_size==kKeySize-1");
		}
		catch (const tc::ArgumentOutOfRangeException&) { /* do nothing */ }
		catch (const tc::Exception&)
		{
			throw tc::TestException("Failed to throw correct exception where key_size==kKeySize-1");
		}

		// try invalid key - key size == kKeySize+1 expected
		try
		{
			calc.initialize(test_cases[0].in_key.data(), test_cases[0].in_key.size() + 1);
			throw tc::TestException("Failed to throw ArgumentOutOfRangeException where key_size==kKeySize+1");
		}
		catch (const tc::ArgumentOutOfRangeException&) { /* do nothing */ }
		catch (const tc::Exception&)
		{
			throw tc::TestException("Failed to throw correct exception where key_size==kKeySize+1");
		}

		// try invalid key - key size == 0 expected
		try
		{
			calc.initialize(test_cases[0].in_key.data(), 0);
			throw tc::TestException("Failed to throw ArgumentOutOfRangeException where key_size==0");
		}
		catch (const tc::ArgumentOutOfRangeException&) { /* do nothing */ }
		catch (const tc::Exception&)
		{
			throw tc::TestException("Failed to throw correct exception where key_size==0");
		}

		// try invalid key - key is null
		try
		{
			calc.initialize(nullptr, test_cases[0].in_key.size());
			throw tc::TestException("Failed to throw ArgumentNullException where key==nullptr");
		}
		catch (const tc::ArgumentNullException&) { /* do nothing */ }
		catch (const tc::Exception&)
		{
			throw tc::TestException("Failed to throw correct exception where key==nullptr");
		}

		// record result
		test_result.result = "PASS";
		test_result.comments = "";
	}
	catch (const tc::TestException& e)
	{
		// record result
		test_result.result = "FAIL";
		test_result.comments = e.what();
	}
	catch (const std::exception& e)
	{
		// record result
		test_result.result = "UNHANDLED EXCEPTION";
		test_result.comments = e.what();
	}

	// add result to list
	mTestResults.push_back(std::move(test_result));
}

void crypto_CmacTdes112Generator_TestClass::test_InvalidKeyThrowsExceptionUtilFunc()
{
	TestResult test_result;
	test_result.test_name = "test_InvalidKeyThrowsExceptionUtilFunc";
	test_result.result = "NOT RUN";
	test_result.comments = "";

	try
	{
		// create tests
		std::vector<TestCase> test_cases;
		util_Setup_TestCases(test_cases);
		if (test_cases.begin() == test_cases.end())
		{
			throw tc::TestException("No test vectors");
		}


		tc::ByteData mac = tc::ByteData(tc::crypto::CmacTdes112Generator::kMacSize);

		// try invalid key - key size == kKeySize-1 expected
		try
		{
			tc::crypto::GenerateCmacTdes112Mac(mac.data(), test_cases[0].in_data.data(), test_cases[0].in_data.size(), test_cases[0].in_key.data(), test_cases[0].in_key.size() - 1);
			throw tc::TestException("Failed to throw ArgumentOutOfRangeException where key_size==kKeySize-1");
		}
		catch (const tc::ArgumentOutOfRangeException&) { /* do nothing */ }
		catch (const tc::Exception&)
		{
			throw tc::TestException("Failed to throw correct exception where key_size==kKeySize-1");
		}

		// try invalid key - key size == kKeySize+1 expected
		try
		{
			tc::crypto::GenerateCmacTdes112Mac(mac.data(), test_cases[0].in_data.data(), test_cases[0].in_data.size(), test_cases[0].in_key.data(), test_cases[0].in_key.size() + 1);
			throw tc::TestException("Failed to throw ArgumentOutOfRangeException where key_size==kKeySize+1");
		}
		catch (const tc::ArgumentOutOfRangeException&) { /* do nothing */ }
		catch (const tc::Exception&)
		{
			throw tc::TestException("Failed to throw correct exception where key_size==kKeySize+1");
		}

		// try invalid key - key size == 0 expected
		try
		{
			tc::crypto::GenerateCmacTdes112Mac(mac.data(), test_cases[0].in_data.data(), test_cases[0].in_data.size(), test_cases[0].in_key.data(), 0);
			throw tc::TestException("Failed to throw ArgumentOutOfRangeException where key_size==0");
		}
		catch (const tc::ArgumentOutOfRangeException&) { /* do nothing */ }
		catch (const tc::Exception&)
		{
			throw tc::TestException("Failed to throw correct exception where key_size==0");
		}

		// try invalid key - key is null
		try
		{
			tc::crypto::GenerateCmacTdes112Mac(mac.data(), test_cases[0].in_data.data(), test_cases[0].in_data.size(), nullptr, test_cases[0].in_key.size());
			throw tc::TestException("Failed to throw ArgumentNullException where key==nullptr");
		}
		catch (const tc::ArgumentNullException&) { /* do nothing */ }
		catch (const tc::Exception&)
		{
			throw tc::TestException("Failed to throw correct exception where key==nullptr");
		}

		// record result
		test_result.result = "PASS";
		test_result.comments = "";
	}
	catch (const tc::TestException& e)
	{
		// record result
		test_result.result = "FAIL";
		test_result.comments = e.what();
	}
	catch (const std::exception& e)
	{
		// record result
		test_result.result = "UNHANDLED EXCEPTION";
		test_result.comments = e.what();
	}

	// add result to list
	mTestResults.push_back(std::move(test_result));
}

void crypto_CmacTdes112Generator_TestClass::test_CallGetMacRepeatedly()
{
	TestResult test_result;
	test_result.test_name = "test_CallGetMacRepeatedly";
	test_result.result = "NOT RUN";
	test_result.comments = "";

	try
	{
		// create tests
		std::vector<TestCase> test_cases;
		util_Setup_TestCases(test_cases);
		if (test_cases.begin() == test_cases.end())
		{
			throw tc::TestException("No test vectors");
		}

		tc::crypto::CmacTdes112Generator calc;
		tc::ByteData mac = tc::ByteData(tc::crypto::CmacTdes112Generator::kMacSize);

		for (auto test_case = test_cases.begin(); test_case != test_cases.end(); test_case++)
		{
			calc.initialize(test_case->in_key.data(), test_case->in_key.size());
			calc.update(test_case->in_data.data(), test_case->in_data.size());
			for (size_t i = 0; i < 100; i++)
			{
				// by resetting the mac here we can tell if it is updated each time
				memset(mac.data(), 0xff, mac.size());
				calc.getMac(mac.data());
				if (memcmp(mac.data(), test_case->out_mac.data(), mac.size()) != 0)
				{
					throw tc::TestException(fmt::format("Test \"{:s}\" Failed. Had wrong MAC: {:s} (expected {:s})", test_case->test_name, tc::cli::FormatUtil::formatBytesAsString(mac, true, ""), tc::cli::FormatUtil::formatBytesAsString(test_case->out_mac, true, "")));
				}
			}
		}

		// record result
		test_result.result = "PASS";
		test_result.comments = "";
	}
	catch (const tc::TestException& e)
	{
		// record result
		test_result.result = "FAIL";
		test_result.comments = e.what();
	}
	catch (const std::exception& e)
	{
		// record result
		test_result.result = "UNHANDLED EXCEPTION";
		test_result.comments = e.what();
	}

	// add result to list
	mTestResults.push_back(std::move(test_result));
}

void crypto_CmacTdes112Generator_TestClass::util_Setup_TestCases(std::vector<crypto_CmacTdes112Generator_TestClass::TestCase>& test_cases)
{
	TestCase tmp;

	test_cases.clear();

	// NIST 800-38B
	tmp.test_name = "NIST 800-38B Test 1";
	tmp.in_key = tc::cli::FormatUtil::hexStringToBytes("4cf15134a2850dd58a3d10ba80570d38");
	tmp.in_data = tc::cli::FormatUtil::hexStringToBytes(""); //  Mlen 0  <empty string>
	tmp.out_mac = tc::cli::FormatUtil::hexStringToBytes("bd2ebf9a3ba00361");
	test_cases.push_back(tmp);

	tmp.test_name = "NIST 800-38B Test 2";
	tmp.in_key = tc::cli::FormatUtil::hexStringToBytes("4cf15134a2850dd58a3d10ba80570d38");
	tmp.in_data = tc::cli::FormatUtil::hexStringToBytes("6bc1bee22e409f96"); // Mlen 64-bit
	tmp.out_mac = tc::cli::FormatUtil::hexStringToBytes("4FF2AB813C53CE83"); // test data incorrectly had this as bd2ebf9a3ba00361
	test_cases.push_back(tmp);

	tmp.test_name = "NIST 800-38B Test 3";
	tmp.in_key = tc::cli::FormatUtil::hexStringToBytes("4cf15134a2850dd58a3d10ba80570d38");
	tmp.in_data = tc::cli::FormatUtil::hexStringToBytes("6bc1bee22e409f96e93d7e117393172aae2d8a57"); // Mlen 160-bit
	tmp.out_mac = tc::cli::FormatUtil::hexStringToBytes("62DD1B471902BD4E"); // test data incorrectly had this as 8ea92435b52660e0
	test_cases.push_back(tmp);

	tmp.test_name = "NIST 800-38B Test 4";
	tmp.in_key = tc::cli::FormatUtil::hexStringToBytes("4cf15134a2850dd58a3d10ba80570d38");
	tmp.in_data = tc::cli::FormatUtil::hexStringToBytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"); // Mlen 256-bit
	tmp.out_mac = tc::cli::FormatUtil::hexStringToBytes("31b1e431dabc4eb8"); 
	test_cases.push_back(tmp);
}