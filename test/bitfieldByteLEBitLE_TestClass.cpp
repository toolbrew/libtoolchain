#include <tc/Exception.h>
#include <iostream>
#include <sstream>
#include <algorithm>

#include <tc/types.h>

#include "bitfieldByteLEBitLE_TestClass.h"

//---------------------------------------------------------

void bitfieldByteLEBitLE_TestClass::runAllTests(void)
{
	std::cout << "[tc::bitfield<LE,LE>] START" << std::endl;
	test_Size();
	test_TestBit();
	test_SetBit();
	test_ResetBit();
	test_FlipBit();
	std::cout << "[tc::bitfield<LE,LE>] END" << std::endl;
}

//---------------------------------------------------------

void bitfieldByteLEBitLE_TestClass::test_Size()
{
	std::cout << "[tc::bitfield<LE,LE>] test_Size : " << std::flush;
	try
	{
		try 
		{
			std::stringstream ss;

			// check size
			static const size_t kBitFieldSize = sizeof(uint32_t);
			tc::bitfield<kBitFieldSize, true, true> bf;
			if (sizeof(bf) != kBitFieldSize)
			{
				ss << "sizeof(bf) had value " << std::dec << sizeof(bf) << " (expected " << kBitFieldSize << ")";
				throw tc::Exception(ss.str());
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

void bitfieldByteLEBitLE_TestClass::test_TestBit()
{
	std::cout << "[tc::bitfield<LE,LE>] test_TestBit : " << std::flush;
	try
	{
		try 
		{
			std::stringstream ss;

			// check size
			testtype_t bf;
			
			// clear all bits
			*((uint32_t*)&bf) = 0;
			helper_TestBit("All bits clear", bf, {});

			// set all bits
			*((uint32_t*)&bf) = -1;
			helper_TestBit("All bits set", bf, {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31});

			// test endianness calculation
			byte_t* bf_raw = (byte_t*)&bf;

			// set byte0 bit0
			*((uint32_t*)&bf) = 0;
			bf_raw[0] = 0x01;
			helper_TestBit("byte0bit0 test", bf, {0});

			// set byte0 bit7
			*((uint32_t*)&bf) = 0;
			bf_raw[0] = 0x80;
			helper_TestBit("byte0bit7 test", bf, {7});

			// set byte3 bit0
			*((uint32_t*)&bf) = 0;
			bf_raw[3] = 0x01;
			helper_TestBit("byte3bit0 test", bf, {24});

			// set byte3 bit7
			*((uint32_t*)&bf) = 0;
			bf_raw[3] = 0x80;
			helper_TestBit("byte3bit7 test", bf, {31});

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

void bitfieldByteLEBitLE_TestClass::test_SetBit()
{
	std::cout << "[tc::bitfield<LE,LE>] test_SetBit : " << std::flush;
	try
	{
		try 
		{
			std::stringstream ss;

			// check size
			testtype_t bf;
			
			// clear all bits
			*((uint32_t*)&bf) = 0;
			
			for (size_t i = 0; i < bf.bit_size(); i++)
			{
				bf.set(i);
				if (bf.test(i) != true)
				{
					ss << "set() failed to set bit " << std::dec << i << std::endl;
				}
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

void bitfieldByteLEBitLE_TestClass::test_ResetBit()
{
	std::cout << "[tc::bitfield<LE,LE>] test_ResetBit : " << std::flush;
	try
	{
		try 
		{
			std::stringstream ss;

			// check size
			testtype_t bf;
			
			// clear all bits
			*((uint32_t*)&bf) = -1;
			
			for (size_t i = 0; i < bf.bit_size(); i++)
			{
				bf.reset(i);
				if (bf.test(i) != false)
				{
					ss << "reset() failed to clear bit " << std::dec << i << std::endl;
				}
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

void bitfieldByteLEBitLE_TestClass::test_FlipBit()
{
	std::cout << "[tc::bitfield<LE,LE>] test_FlipBit : " << std::flush;
	try
	{
		try 
		{
			std::stringstream ss;

			// check size
			testtype_t bf;
			
			// clear all bits
			*((uint32_t*)&bf) = -1;
			
			for (size_t i = 0; i < bf.bit_size(); i++)
			{
				bf.flip(i);
				if (bf.test(i) != false)
				{
					ss << "reset() failed to flip bit " << std::dec << i << std::endl;
				}
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

void bitfieldByteLEBitLE_TestClass::helper_TestBit(const std::string& test_name, const testtype_t& bitfield, const std::vector<size_t>& expected_set_bits)
{
	std::stringstream ss;
	for (size_t i = 0; i < bitfield.bit_size(); i++)
	{
		bool res = bitfield.test(i);
		bool expected_res = std::find(expected_set_bits.begin(), expected_set_bits.end(), i) != expected_set_bits.end();
		if (res != expected_res)
		{
			if (test_name.empty() == false)
				ss << test_name << " : ";
			ss << "bitfield.test(" << std::dec << i << ") had value " << std::boolalpha << res << " (expected " << std::boolalpha << expected_res << ")";
			throw tc::Exception(ss.str());
		}
	}
}