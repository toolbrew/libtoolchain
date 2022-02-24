
#include <tc/io/Path.h>
#include <tc/string.h>
#include <tc/Exception.h>

#include <fmt/core.h>
#include <sstream>
#include <iostream>

static const char kWindowsPathDelimiter = '\\'; /**< Path delimiter used on Microsoft Windows based systems */
static const char kPosixPathDelimiter = '/'; /**< Path delimiter used on POSIX based systems */
#ifdef _WIN32
static const char kNativePathDelimiter = kWindowsPathDelimiter; /**< Path delimiter for the native environment */
#else
static const char kNativePathDelimiter = kPosixPathDelimiter; /**< Path delimiter for the native environment */
#endif

const std::string tc::io::Path::kClassName = "tc::io::Path";

tc::io::Path::Path()
{}

tc::io::Path::Path(const std::string& path)
{
	initializePath(path);
}

tc::io::Path::Path(const std::u16string& path)
{
	std::string utf8_path;
	string::TranscodeUtil::UTF16ToUTF8(path, utf8_path);
	initializePath(utf8_path);
}

tc::io::Path::Path(const std::u32string& path)
{
	std::string utf8_path;
	string::TranscodeUtil::UTF32ToUTF8(path, utf8_path);
	initializePath(utf8_path);
}

tc::io::Path tc::io::Path::operator+(const Path& other) const
{
	Path new_path = *this;
	new_path.appendPath(other.mUnicodePath);
	return new_path;
}

void tc::io::Path::operator+=(const Path& other)
{
	appendPath(other.mUnicodePath);
}

bool tc::io::Path::operator==(const Path& other) const
{
	return mUnicodePath == other.mUnicodePath;
}

bool tc::io::Path::operator!=(const Path& other) const
{
	return !(this->operator==(other));
}

bool tc::io::Path::operator<(const Path& other) const
{
	int cmp_score = 0;

	auto self_itr = this->begin();
	auto other_itr = other.begin();

	// in this loop for as long as both path has an itr, it'll compare them
	for (; self_itr != this->end() && other_itr != other.end(); self_itr++, other_itr++)
	{
		cmp_score = self_itr->compare(*other_itr);
		if (cmp_score != 0)
			break;
	}

	// if one of the itrs isn't the end, then that one is "larger"
	// it can't be both or the prior loop won't have ended
	if (cmp_score == 0 && (self_itr != this->end() || other_itr != other.end()))
	{
		cmp_score = self_itr == this->end() ? -1 : 1;
	}

	return cmp_score < 0;
}

tc::io::Path::iterator tc::io::Path::begin()
{
	return mUnicodePath.begin();
}

std::string& tc::io::Path::front()
{
	return mUnicodePath.front();
}

const std::string& tc::io::Path::front() const
{
	return mUnicodePath.front();
}

std::string& tc::io::Path::back()
{
	return mUnicodePath.back();
}

const std::string& tc::io::Path::back() const
{
	return mUnicodePath.back();
}

tc::io::Path::const_iterator tc::io::Path::begin() const
{
	return mUnicodePath.begin();
}

tc::io::Path::iterator tc::io::Path::end()
{
	return mUnicodePath.end();
}

tc::io::Path::const_iterator tc::io::Path::end() const
{
	return mUnicodePath.end();
}

void tc::io::Path::pop_front()
{
	mUnicodePath.pop_front();
}

void tc::io::Path::pop_back()
{
	mUnicodePath.pop_back();
}

void tc::io::Path::push_front(const std::string& str)
{
	mUnicodePath.push_front(str);
}

void tc::io::Path::push_back(const std::string& str)
{
	mUnicodePath.push_back(str);
}

void tc::io::Path::clear()
{
	mUnicodePath.clear();
}

size_t tc::io::Path::size() const
{
	return mUnicodePath.size();
}

bool tc::io::Path::empty() const
{
	return mUnicodePath.empty();
}

tc::io::Path tc::io::Path::subpath(size_t pos, size_t len) const
{
	tc::io::Path out_path;

	auto itr = begin();
	size_t index = 0;

	// while the out_path size is less than len and the iterator hasn't ended
	while ( out_path.size() < len && itr != end() )
	{
		// provided the index >= pos save the element
		if (index >= pos)
		{
			out_path.push_back(*itr);
		}

		itr++;
		index++;
	}

	return out_path;
}

tc::io::Path tc::io::Path::subpath(const_iterator begin, const_iterator end) const
{
	tc::io::Path out_path;

	for (auto itr = begin; itr != end && itr != this->end(); itr++)
	{
		out_path.push_back(*itr);
	}

	return out_path;
}

std::string tc::io::Path::to_string(Format format) const
{
	std::string path_str = "";

	std::string path_delimiter_str;
	switch (format)
	{
	case (Path::Format::Native):
		path_delimiter_str = fmt::format("{:c}", kNativePathDelimiter);
		break;
	case (Path::Format::POSIX):
		path_delimiter_str = fmt::format("{:c}", kPosixPathDelimiter);
		break;
	case (Path::Format::Win32):
		path_delimiter_str = fmt::format("{:c}", kWindowsPathDelimiter);
		break;
	default:
		throw tc::ArgumentException(kClassName, "Invalid Format type.");
	}

	// special case where the path has one element and it's empty (posix root path "/")
	if (this->size() == 1 && this->front() == "")
		return path_delimiter_str;

	for (const_iterator itr = this->begin(); itr != this->end(); itr++)
	{
		path_str += *itr;
		if (itr != --(this->end()))
			path_str += path_delimiter_str;
	}

	return path_str;
}

std::u16string tc::io::Path::to_u16string(Format format) const
{
	std::string u8string = to_string(format);
	std::u16string u16string;

	// convert
	string::TranscodeUtil::UTF8ToUTF16(u8string, u16string);

	// return
	return u16string;
}

std::u32string tc::io::Path::to_u32string(Format format) const
{
	std::string u8string = to_string(format);
	std::u32string u32string;

	// convert
	string::TranscodeUtil::UTF8ToUTF32(u8string, u32string);

	// return
	return u32string;
}

tc::io::Path::operator std::string() const
{
	return to_string(Format::Native);
}

tc::io::Path::operator std::u16string() const
{
	return to_u16string(Format::Native);
}

tc::io::Path::operator std::u32string() const
{
	return to_u32string(Format::Native);
}

void tc::io::Path::initializePath(const std::string& src)
{
	size_t windows_slash_count = 0;
	size_t posix_slash_count = 0;
	for (size_t i = 0; i < src.size(); i++)
	{
		if (src[i] == kWindowsPathDelimiter)
			windows_slash_count += 1;
		else if (src[i] == kPosixPathDelimiter)
			posix_slash_count += 1;
	}

	if (windows_slash_count != 0 && posix_slash_count != 0)
	{
		throw tc::Exception(kClassName, "Both Windows and Unix path delimiters are present in path");
	}

	char path_delimiter = kNativePathDelimiter;
	if (windows_slash_count > 0)
		path_delimiter = kWindowsPathDelimiter;
	else if (posix_slash_count > 0)
		path_delimiter = kPosixPathDelimiter;


	std::stringstream src_stream(src);

	std::string element;
	while (std::getline(src_stream, element, path_delimiter))
	{
		mUnicodePath.push_back(element);
	}
}

void tc::io::Path::appendPath(const std::list<std::string>& other)
{
	for (std::list<std::string>::const_iterator itr = other.begin(); itr != other.end(); itr++)
	{
		mUnicodePath.push_back(*itr);
	}
}