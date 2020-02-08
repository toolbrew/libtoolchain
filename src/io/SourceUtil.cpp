#include <tc/io/SourceUtil.h>

size_t tc::io::SourceUtil::getReadableSize(int64_t source_length, int64_t source_offset, size_t read_size)
{
	if (source_length < 0 || source_offset < 0)
		return 0;

	int64_t available_data = (source_offset < source_length) ? (source_length - source_offset) : 0;

	return size_t(std::min<int64_t>(available_data, int64_t(read_size)));
}