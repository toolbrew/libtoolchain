#include "crypto_CmacAes128Generator_TestClass.h"

#include <fmt/format.h>

#include <tc/crypto/CmacAes128Generator.h>
#include <tc/cli/FormatUtil.h>
#include <tc/ByteData.h>

//---------------------------------------------------------

crypto_CmacAes128Generator_TestClass::crypto_CmacAes128Generator_TestClass() :
	mTestTag("tc::crypto::CmacAes128Generator"),
	mTestResults()
{
}

void crypto_CmacAes128Generator_TestClass::runAllTests(void)
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

const std::string& crypto_CmacAes128Generator_TestClass::getTestTag() const
{
	return mTestTag;
}

const std::vector<ITestClass::TestResult>& crypto_CmacAes128Generator_TestClass::getTestResults() const
{
	return mTestResults;
}

//---------------------------------------------------------

void crypto_CmacAes128Generator_TestClass::test_Constants()
{
	TestResult test_result;
	test_result.test_name = "test_Constants";
	test_result.result = "NOT RUN";
	test_result.comments = "";

	try
	{
		// check key size
		static const size_t kExpectedKeySize = 16;
		size_t kKeySize = tc::crypto::CmacAes128Generator::kKeySize;
		if (kKeySize != kExpectedKeySize)
		{				
			throw tc::TestException(fmt::format("kKeySize had value {:d} (expected {:d})", kKeySize, kExpectedKeySize));
		}
		
		// check mac size
		static const size_t kExpectedMacSize = 16;
		if (tc::crypto::CmacAes128Generator::kMacSize != kExpectedMacSize)
		{				
			throw tc::TestException(fmt::format("kMacSize had value {:d} (expected {:d})", tc::crypto::CmacAes128Generator::kMacSize, kExpectedMacSize));
		}

		// check block size
		static const size_t kExpectedBlockSize = 16;
		if (tc::crypto::CmacAes128Generator::kBlockSize != kExpectedBlockSize)
		{				
			throw tc::TestException(fmt::format("kBlockSize had value {:d} (expected {:d})", tc::crypto::CmacAes128Generator::kBlockSize, kExpectedBlockSize));
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

void crypto_CmacAes128Generator_TestClass::test_SingleUpdateCall()
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
		
		tc::crypto::CmacAes128Generator calc;
		tc::ByteData mac = tc::ByteData(tc::crypto::CmacAes128Generator::kMacSize);

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

void crypto_CmacAes128Generator_TestClass::test_MultiUpdateCall()
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
		
		tc::crypto::CmacAes128Generator calc;
		tc::ByteData mac = tc::ByteData(tc::crypto::CmacAes128Generator::kMacSize);

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

void crypto_CmacAes128Generator_TestClass::test_UtilFunc()
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
		
		tc::ByteData mac = tc::ByteData(tc::crypto::CmacAes128Generator::kMacSize);

		for (auto test_case = test_cases.begin(); test_case != test_cases.end(); test_case++)
		{
			memset(mac.data(), 0xff, mac.size());
			tc::crypto::GenerateCmacAes128Mac(mac.data(), test_case->in_data.data(), test_case->in_data.size(), test_case->in_key.data(), test_case->in_key.size());
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

void crypto_CmacAes128Generator_TestClass::test_NoInitNoUpdateDoMac()
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
		
		tc::crypto::CmacAes128Generator calc;
		tc::ByteData mac = tc::ByteData(tc::crypto::CmacAes128Generator::kMacSize);
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

void crypto_CmacAes128Generator_TestClass::test_NoInitDoUpdateDoMac()
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
		
		tc::crypto::CmacAes128Generator calc;
		tc::ByteData mac = tc::ByteData(tc::crypto::CmacAes128Generator::kMacSize);
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

void crypto_CmacAes128Generator_TestClass::test_InvalidKeyThrowsExceptionClass()
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


		tc::crypto::CmacAes128Generator calc;
		tc::ByteData mac = tc::ByteData(tc::crypto::CmacAes128Generator::kMacSize);

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

void crypto_CmacAes128Generator_TestClass::test_InvalidKeyThrowsExceptionUtilFunc()
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


		tc::ByteData mac = tc::ByteData(tc::crypto::CmacAes128Generator::kMacSize);

		// try invalid key - key size == kKeySize-1 expected
		try
		{
			tc::crypto::GenerateCmacAes128Mac(mac.data(), test_cases[0].in_data.data(), test_cases[0].in_data.size(), test_cases[0].in_key.data(), test_cases[0].in_key.size() - 1);
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
			tc::crypto::GenerateCmacAes128Mac(mac.data(), test_cases[0].in_data.data(), test_cases[0].in_data.size(), test_cases[0].in_key.data(), test_cases[0].in_key.size() + 1);
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
			tc::crypto::GenerateCmacAes128Mac(mac.data(), test_cases[0].in_data.data(), test_cases[0].in_data.size(), test_cases[0].in_key.data(), 0);
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
			tc::crypto::GenerateCmacAes128Mac(mac.data(), test_cases[0].in_data.data(), test_cases[0].in_data.size(), nullptr, test_cases[0].in_key.size());
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

void crypto_CmacAes128Generator_TestClass::test_CallGetMacRepeatedly()
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
		
		tc::crypto::CmacAes128Generator calc;
		tc::ByteData mac = tc::ByteData(tc::crypto::CmacAes128Generator::kMacSize);

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

void crypto_CmacAes128Generator_TestClass::util_Setup_TestCases(std::vector<crypto_CmacAes128Generator_TestClass::TestCase>& test_cases)
{
	TestCase tmp;

	test_cases.clear();

	// NIST 800-38B
	tmp.test_name = "NIST 800-38B Test 1";
	tmp.in_key = tc::cli::FormatUtil::hexStringToBytes("2b7e151628aed2a6abf7158809cf4f3c");
	tmp.in_data = tc::cli::FormatUtil::hexStringToBytes(""); //  Mlen 0  <empty string>
	tmp.out_mac = tc::cli::FormatUtil::hexStringToBytes("bb1d6929e95937287fa37d129b756746");
	test_cases.push_back(tmp);

	tmp.test_name = "NIST 800-38B Test 2";
	tmp.in_key = tc::cli::FormatUtil::hexStringToBytes("2b7e151628aed2a6abf7158809cf4f3c");
	tmp.in_data = tc::cli::FormatUtil::hexStringToBytes("6bc1bee22e409f96e93d7e117393172a"); // Mlen 128-bit
	tmp.out_mac = tc::cli::FormatUtil::hexStringToBytes("070a16b46b4d4144f79bdd9dd04a287c");
	test_cases.push_back(tmp);

	tmp.test_name = "NIST 800-38B Test 3";
	tmp.in_key = tc::cli::FormatUtil::hexStringToBytes("2b7e151628aed2a6abf7158809cf4f3c");
	tmp.in_data = tc::cli::FormatUtil::hexStringToBytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411"); // Mlen 320-bit
	tmp.out_mac = tc::cli::FormatUtil::hexStringToBytes("dfa66747de9ae63030ca32611497c827");
	test_cases.push_back(tmp);

	tmp.test_name = "NIST 800-38B Test 4";
	tmp.in_key = tc::cli::FormatUtil::hexStringToBytes("2b7e151628aed2a6abf7158809cf4f3c");
	tmp.in_data = tc::cli::FormatUtil::hexStringToBytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"); // Mlen 512-bit
	tmp.out_mac = tc::cli::FormatUtil::hexStringToBytes("51f0bebf7e3b9d92fc49741779363cfe");
	test_cases.push_back(tmp);

	// sample 128bit BDK
	tmp.test_name = "Test 128bit BDK";
	tmp.in_key = tc::cli::FormatUtil::hexStringToBytes("102030405060708090A0B0C0D0E0F011");
	tmp.in_data = tc::cli::FormatUtil::hexStringToBytes("00000000000000000000000000000000");
	tmp.out_mac = tc::cli::FormatUtil::hexStringToBytes("CEE9F355CF79633777514B192C0317C9");
	test_cases.push_back(tmp);

}