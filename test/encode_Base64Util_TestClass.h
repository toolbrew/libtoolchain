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

	void testEncodeDataAsBase64();
	void testEncodeStringAsBase64();
	void testDecodeBase64AsData();
	void testDecodeBase64AsString();
};