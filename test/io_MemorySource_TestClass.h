#pragma once
#include "ITestClass.h"

class io_MemorySource_TestClass : public ITestClass
{
public:
	io_MemorySource_TestClass();

		// this will run the tests
	void runAllTests();

		// this is the label for this test (for filtering purposes)
	const std::string& getTestTag() const;

		// this is where the test results are written
	const std::vector<ITestClass::TestResult>& getTestResults() const;
private:
	std::string mTestTag;
	std::vector<TestResult> mTestResults;

	void testDefaultConstructor();
	void testInitializeByCopyWithByteData();
	void testInitializeByMoveWithByteData();
	void testInitializeByCopyWithMemoryPointer();
	void testNegativeOffset();
	void testTooLargeOffset();
};
