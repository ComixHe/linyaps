/*
 * SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

#pragma once

#include "linglong/utils/error/details/error_impl.h"

#include <glib.h>
#include <tl/expected.hpp>

#include <memory>
#include <string>
#include <system_error>
#include <utility>

namespace linglong::utils::error {

enum class ErrorCode : int {
    Failed = -1, // 通用失败错误码
    Success = 0, // 成功
    /* 通用错误层 */
    Unknown = 1000,               // 未知错误
    AppNotFoundFromRemote = 1001, // 从远程找不到对应应用
    AppNotFoundFromLocal = 1002,  // 从本地找不到对应应用

    /* 安装 */
    AppInstallFailed = 2001,                // 安装失败
    AppInstallNotFoundFromRemote = 2002,    // 远程不存在对应应用
    AppInstallAlreadyInstalled = 2003,      // 本地已安装相同版本的应用
    AppInstallNeedDowngrade = 2004,         // 安装app需要降级
    AppInstallModuleNoVersion = 2005,       // 安装模块时不允许指定版本
    AppInstallModuleRequireAppFirst = 2006, // 安装模块时需要先安装应用
    AppInstallModuleAlreadyExists = 2007,   // 安装模块时已存在相同版本的模块
    AppInstallArchNotMatch = 2008,          // 安装app的架构不匹配
    AppInstallModuleNotFound = 2009,        // 远程不存在对应模块
    /* 卸载 */
    AppUninstallFailed = 2101,            // 卸载失败
    AppUninstallNotFoundFromLocal = 2102, // 本地不存在对应应用
    AppUninstallAppIsRunning = 2103,      // 卸载的app正在运行
    LayerCompatibilityError = 2104,       // 找不到兼容的layer
    /* 升级 */
    AppUpgradeFailed = 2201,          // 升级失败
    AppUpgradeNotFound = 2202,        // 本地不存在对应应用
    AppUpgradeLatestInstalled = 2203, // 已安装最新版本

    /* 网络 */
    NetworkError = 3001, // 网络错误
};

class Error
{
public:
    Error() = default;

    Error(const Error &) = delete;
    Error(Error &&) = default;
    Error &operator=(const Error &) = delete;
    Error &operator=(Error &&) = default;

    [[nodiscard]] auto code() const { return pImpl->code(); };

    [[nodiscard]] auto message() const { return pImpl->message(); }

    [[nodiscard]] auto release() && { return std::move(pImpl); }

    template <typename T>
    static auto Err(const char *file,
                    int line,
                    const char *function,
                    const std::string &trace_msg,
                    T &&msg,
                    int code = -1) -> Error
    {
        static_assert(std::is_convertible_v<T, std::string>, "msg cannot convert to std::string");
        return Error(std::make_unique<details::ErrorImpl>(file,
                                                          line,
                                                          code,
                                                          function,
                                                          trace_msg,
                                                          std::forward<T>(msg),
                                                          nullptr));
    }

    template <typename T>
    static auto Err(const char *file,
                    int line,
                    const char *function,
                    const std::string &trace_msg,
                    T &&msg,
                    ErrorCode code) -> Error
    {
        static_assert(std::is_convertible_v<T, std::string>, "msg cannot convert to std::string");
        return Err(file, line, function, trace_msg, std::forward<T>(msg), static_cast<int>(code));
    }

    static auto Err(const char *file,
                    int line,
                    const char *function,
                    const std::string &trace_msg,
                    const std::string &msg,
                    const std::exception &err) -> Error
    {
        return Err(file, line, function, trace_msg, msg + ":" + err.what());
    }

    static auto Err(const char *file,
                    int line,
                    const char *function,
                    const std::string &trace_msg,
                    const std::string &msg,
                    std::exception_ptr &&err) -> Error
    {
        std::string what{ msg };

        try {
            std::rethrow_exception(std::move(err));
        } catch (const std::exception &e) {
            what.append(": ").append(e.what());
        } catch (...) {
            what.append(": unknown exception");
        }

        return Err(file, line, function, trace_msg, std::move(what));
    }

    template <typename T>
    static auto Err(const char *file,
                    int line,
                    const char *function,
                    const std::string &trace_msg,
                    T &&msg,
                    GError const *const e) -> Error
    {
        static_assert(std::is_convertible_v<T, std::string>, "msg cannot convert to std::string");
        std::string new_msg{ std::forward<T>(msg) };
        if (e != nullptr) {
            new_msg.append(" error code:" + std::to_string(e->code) + " message:" + e->message);
        }

        return Err(file, line, function, trace_msg, std::move(new_msg));
    }

    template <typename T>
    static auto Err(const char *file,
                    int line,
                    const char *function,
                    const std::string &trace_msg,
                    T &&msg,
                    const std::system_error &e) -> Error
    {
        static_assert(std::is_convertible_v<T, std::string>, "msg cannot convert to std::string");
        std::string new_msg{ std::forward<T>(msg) };
        new_msg.append(": ");
        new_msg.append(e.what());

        return Err(file, line, function, trace_msg, std::move(new_msg), e.code().value());
    }

    template <typename T>
    static auto Err(const char *file,
                    int line,
                    const char *function,
                    const std::string &trace_msg,
                    T &&msg,
                    Error &&cause,
                    int code = -1) -> Error
    {
        static_assert(std::is_convertible_v<T, std::string>, "msg cannot convert to std::string");
        return Error(std::make_unique<details::ErrorImpl>(file,
                                                          line,
                                                          code,
                                                          function,
                                                          trace_msg,
                                                          std::forward<T>(msg),
                                                          std::move(cause).release()));
    }

    template <typename T, typename Value>
    static auto Err(const char *file,
                    int line,
                    const char *function,
                    const std::string &trace_msg,
                    T &&msg,
                    tl::expected<Value, Error> &&cause) -> Error
    {
        static_assert(std::is_convertible_v<T, std::string>, "msg cannot convert to std::string");
        assert(!cause.has_value());

        return Err(file, line, function, trace_msg, std::forward<T>(msg), std::move(cause).error());
    }

    template <typename Value>
    static auto Err(const char *file,
                    int line,
                    const char *function,
                    const std::string &trace_msg,
                    tl::expected<Value, Error> &&cause) -> Error
    {
        assert(!cause.has_value());
        return Err(file, line, function, trace_msg, "", std::move(cause).error());
    }

    static auto Err(const char *file,
                    int line,
                    const char *function,
                    const std::string &trace_msg,
                    Error &&cause) -> Error
    {
        return Err(file, line, function, trace_msg, "", std::move(cause));
    }

    template <typename Value>
    static auto Err(const char *file,
                    int line,
                    const char *function,
                    const std::string &trace_msg,
                    tl::expected<Value, std::exception_ptr> &&cause,
                    int code = -1) -> Error
    {
        assert(!cause.has_value());
        return Err(file, line, function, trace_msg, std::move(cause).error(), code);
    }

    template <typename Value>
    static auto Err(const char *file,
                    int line,
                    const char *function,
                    const std::string &trace_msg,
                    const std::string &msg,
                    tl::expected<Value, std::exception_ptr> &&cause) -> Error
    {
        assert(!cause.has_value());
        return Err(file, line, function, trace_msg, msg, std::move(cause).error());
    }

private:
    explicit Error(std::unique_ptr<details::ErrorImpl> pImpl)
        : pImpl(std::move(pImpl))
    {
    }

    std::unique_ptr<details::ErrorImpl> pImpl;
};

template <typename Value>
using Result = tl::expected<Value, Error>;

} // namespace linglong::utils::error

// Use this macro to define trace message at the begining of function
#define LINGLONG_TRACE(message) std::string linglong_trace_message{ message }; // NOLINT

// Use this macro to create new error or wrap an existing error
// LINGLONG_ERR(message, code =-1)
// LINGLONG_ERR(message, /* const QFile& */)
// LINGLONG_ERR(/* const QFile& */)
// LINGLONG_ERR(message, /* std::exception_ptr */, code=-1)
// LINGLONG_ERR(/* std::exception_ptr */)
// LINGLONG_ERR(message, /* const std::exception & */, code=-1)
// LINGLONG_ERR(/* const std::exception & */)
// LINGLONG_ERR(message, /* const std::system_exception & */)
// LINGLONG_ERR(message, /* GError* */)
// LINGLONG_ERR(message, /* Result<Value>&& */)
// LINGLONG_ERR(/* Result<Value>&& */)
// LINGLONG_ERR(message, /* tl::expected<Value,std::exception_ptr>&& */, code=-1)
// LINGLONG_ERR(/* tl::expected<Value,std::exception_ptr>&& */)

template <typename... Args>
auto LINGLONG_ERR_IMPL(
  const char *file, int line, const char *function, const std::string &trace_msg, Args &&...args)
{
    return tl::unexpected(linglong::utils::error::Error::Err(file,
                                                             line,
                                                             function,
                                                             trace_msg,
                                                             std::forward<Args>(args)...));
}

#define LINGLONG_ERR(...) /*NOLINT*/ \
    LINGLONG_ERR_IMPL(__FILE__, __LINE__, __PRETTY_FUNCTION__, linglong_trace_message, __VA_ARGS__)

#define LINGLONG_OK \
    {               \
    }

#define LINGLONG_ERRV(...) /*NOLINT*/         \
    LINGLONG_ERR_IMPL(__FILE__,               \
                      __LINE__,               \
                      __PRETTY_FUNCTION__,    \
                      linglong_trace_message, \
                      __VA_ARGS__)            \
      .value()

// FIXME: remove later
#include <QDebug>

// https://github.com/AD-Vega/qarv/issues/22#issuecomment-1012011346
#if QT_VERSION < QT_VERSION_CHECK(5, 14, 0)
namespace Qt {
static auto endl = ::endl;
}
#endif

inline QDebug operator<<(QDebug debug, const linglong::utils::error::Error &err)
{
    debug.noquote().nospace() << "[code " << err.code() << " ] message:" << Qt::endl
                              << "\t"
                              << QString::fromStdString(err.message()).replace("\n", "\n\t");
    return debug;
}
