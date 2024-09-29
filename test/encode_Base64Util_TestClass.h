#pragma once
#include "ITestClass.h"
#include <tc.h>

class encode_Base64Util_TestClass : public ITestClass
{
public:
	encode_Base64Util_TestClass();

		// this will run the tests
	void runAllTests();

		// this is the label for this test (for filtering purposes)
	const std::string& getTestTag() const;

		// this is where the test results are written
	const std::vector<ITestClass::TestResult>& getTestResults() const;
private:
	std::string mTestTag;
	std::vector<TestResult> mTestResults;

	/*
	static tc::ByteData encodeDataAsBase64Data(const byte_t* data, size_t size);

	static std::string encodeDataAsBase64String(const byte_t* data, size_t size);

	static tc::ByteData encodeStringAsBase64Data(const char* data, size_t size);

	static std::string encodeStringAsBase64String(const char* data, size_t size);

	static tc::ByteData decodeBase64DataAsData(const byte_t* data, size_t size);

	static std::string decodeBase64DataAsString(const byte_t* data, size_t size);

	static tc::ByteData decodeBase64StringAsData(const char* data, size_t size);
	
	static std::string decodeBase64StringAsString(const char* data, size_t size);
	 */

	void testEncodeDataAsBase64Data();
	void testEncodeDataAsBase64String();
	void testEncodeStringAsBase64Data();
	void testEncodeStringAsBase64String();
	void testDecodeBase64DataAsData();
	void testDecodeBase64DataAsString();
	void testDecodeBase64StringAsData();
	void testDecodeBase64StringAsString();
};