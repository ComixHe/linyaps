// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "file.h"

#include "linglong/utils/error/error.h"

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>

#include <sys/stat.h>

namespace linglong::utils {
linglong::utils::error::Result<std::string> readFile(const std::string &filepath) noexcept
{
    LINGLONG_TRACE("read file %1" + filepath);

    std::error_code ec;
    auto exists = std::filesystem::exists(filepath, ec);
    if (ec) {
        return LINGLONG_ERR("check file", ec);
    }
    if (!exists) {
        return LINGLONG_ERR("file not found");
    }
    std::ifstream in{ filepath };
    if (!in.is_open()) {
        auto msg = std::string("open file:") + std::strerror(errno);
        return LINGLONG_ERR(msg.c_str());
    }
    std::stringstream buffer;
    buffer << in.rdbuf();
    if (in.fail()) {
        auto msg = std::string("read file: ") + std::strerror(errno);
        return LINGLONG_ERR(msg.c_str());
    }
    return buffer.str();
}

linglong::utils::error::Result<void> writeFile(const std::string &filepath,
                                               const std::string &content) noexcept
{
    LINGLONG_TRACE("write file %1" + filepath);

    std::error_code ec;
    auto exists = std::filesystem::exists(filepath, ec);
    if (ec) {
        return LINGLONG_ERR("check file", ec);
    }
    if (exists) {
        std::filesystem::remove(filepath, ec);
        if (ec) {
            return LINGLONG_ERR("remove file", ec);
        }
    }
    std::ofstream out{ filepath };
    if (!out.is_open()) {
        auto msg = std::string("open file:") + std::strerror(errno);
        return LINGLONG_ERR(msg.c_str());
    }
    out << content;
    if (out.fail()) {
        auto msg = std::string("write file: ") + std::strerror(errno);
        return LINGLONG_ERR(msg.c_str());
    }
    return LINGLONG_OK;
}

linglong::utils::error::Result<uintmax_t>
calculateDirectorySize(const std::filesystem::path &dir) noexcept
{
    LINGLONG_TRACE("calculate directory size")

    uintmax_t size{ 0 };
    std::error_code ec;

    auto fsIter = std::filesystem::recursive_directory_iterator{ dir, ec };
    if (ec) {
        return LINGLONG_ERR(std::string{ "failed to calculate directory size: " } + ec.message());
    }

    for (const auto &entry : fsIter) {
        auto path = entry.path().string();
        if (entry.is_symlink(ec)) {
            struct stat64 st{};

            if (::lstat64(path.c_str(), &st) == -1) {
                return LINGLONG_ERR(std::string{ "failed to get symlink size: " }
                                    + ::strerror(errno));
            }

            size += st.st_size;
            continue;
        }

        if (ec) {
            return LINGLONG_ERR("failed to get entry type of " + entry.path().string() + ": "
                                + ec.message());
        }

        if (entry.is_directory(ec)) {
            struct stat64 st{};

            if (::stat64(path.c_str(), &st) == -1) {
                return LINGLONG_ERR(std::string{ "failed to get directory size: " }
                                    + ::strerror(errno));
            }

            size += st.st_size;
            continue;
        }

        if (ec) {
            return LINGLONG_ERR(std::string{ "failed to get entry type of " }
                                + entry.path().string() + ": " + ec.message());
        }

        size += entry.file_size();
    }

    return size;
}
} // namespace linglong::utils
