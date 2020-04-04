#pragma once
#include "ITestClass.h"

#include <tc/io/ISink.h>
#include "SinkTestUtil.h"

class io_SubSink_TestClass : public ITestClass
{
public:
	void runAllTests();
private:
	void testDefaultConstructor();
	void testCreateConstructor();
	void testCreateFromNullBase();
	void testCreateWithNegativeSubSinkOffset();
	void testCreateWithNegativeSubSinkLength();
	void testCreateWithExcessiveSubSink();
	void testSetLengthOnDisposedBase();
	void testPushDataOnDisposedBase();
	void testPushDataOutsideOfBaseRange();

	void pushDataTestHelper(tc::io::ISink& sub_sink, SinkTestUtil::DummySinkTestablePushData& base_sink, int64_t sub_base_offset, int64_t sub_push_offset, tc::ByteData& expected_data);
};
