	/**
	 * @file		fs.h
	 * @brief       Declaration of the filesystem library
	 */
#pragma once
#include <tc/types.h>
#include <tc/Exception.h>

	/**
	 * @namespace   tc::fs
	 * @brief       Namespace of the filesystem library
	 */
#include <tc/fs/Path.h>

#include <tc/fs/IFileObject.h>
#include <tc/fs/IFileSystem.h>

#include <tc/fs/GenericFileObject.h>
#include <tc/fs/GenericFileSystem.h>

#include <tc/fs/LocalFileSystem.h>

#include <tc/fs/PartitionedFileObject.h>
#include <tc/fs/SandboxedFileSystem.h>