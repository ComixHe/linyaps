/*
 * SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

#pragma once

#include <memory>
#include <string>
#include <utility>

namespace linglong::utils::error::details {

class ErrorImpl
{
public:
    ErrorImpl(std::string file,
              int line,
              int code,
              std::string function,
              std::string trace_msg,
              std::string msg = "",
              std::unique_ptr<ErrorImpl> cause = nullptr)
        : line(line)
        , code_(code)
        , file(std::move(file))
        , trace_msg(std::move(trace_msg))
        , function(std::move(function))
        , msg(std::move(msg))
        , cause(std::move(cause))
    {
    }

    [[nodiscard]] auto code() const noexcept -> int { return code_; };

    [[nodiscard]] auto message() const -> std::string
    {
        std::string msg;
        for (const ErrorImpl *err = this; err != nullptr; err = err->cause.get()) {
            if (!msg.empty()) {
                msg += "\n";
            }

            msg.append(err->file + ":" + std::to_string(err->line) + " [" + err->function
                       + "]:" + err->trace_msg);

            if (!err->msg.empty()) {
                msg += ": " + err->msg;
            }
        }

        return msg;
    }

private:
    int line;
    int code_;
    std::string file;
    std::string trace_msg;
    std::string function;
    std::string msg;
    std::unique_ptr<ErrorImpl> cause;
};

} // namespace linglong::utils::error::details
