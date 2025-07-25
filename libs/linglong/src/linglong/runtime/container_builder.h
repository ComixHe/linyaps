/*
 * SPDX-FileCopyrightText: 2022 - 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

#pragma once

#include "linglong/oci-cfg-generators/container_cfg_builder.h"
#include "linglong/package/reference.h"
#include "linglong/runtime/container.h"
#include "linglong/utils/error/error.h"
#include "ocppi/cli/CLI.hpp"

#include <QCryptographicHash>
#include <QDir>
#include <QStandardPaths>

namespace linglong::runtime {

inline std::string genContainerID(const package::Reference &ref) noexcept
{
    auto content = (ref.toString().replace('/', '-') + ":").toStdString();
    auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    content.append(std::to_string(now));

    // 如果LINGLONG_DEBUG为true，则对ID进行编码，避免外部依赖该ID规则
    // 调试模式则不进行二次编码，便于跟踪排查
    if (::getenv("LINGLONG_DEBUG") != nullptr) {
        return content;
    }

    return QCryptographicHash::hash(QByteArray::fromStdString(content), QCryptographicHash::Sha256)
      .toHex()
      .toStdString();
}

// Used to obtain a clean container bundle directory.

inline std::filesystem::path getBundleDir(const std::string &containerID) noexcept
{
    const std::filesystem::path runtimeDir =
      QStandardPaths::writableLocation(QStandardPaths::RuntimeLocation).toStdString();
    return runtimeDir / "linglong" / containerID;
}

inline utils::error::Result<std::filesystem::path> makeBundleDir(const std::string &containerID)
{
    LINGLONG_TRACE("get bundle dir");
    auto bundle = getBundleDir(containerID);
    std::error_code ec;
    if (std::filesystem::exists(bundle, ec)) {
        std::filesystem::remove_all(bundle, ec);
        if (ec) {
            qWarning() << QString("failed to remove bundle directory %1: %2")
                            .arg(bundle.c_str(), ec.message().c_str());
        }
    }

    if (!std::filesystem::create_directories(bundle, ec) && ec) {
        return LINGLONG_ERR(QString("failed to create bundle directory %1: %2")
                              .arg(bundle.c_str(), ec.message().c_str()));
    }

    return bundle;
}

class ContainerBuilder : public QObject
{
    Q_OBJECT
public:
    explicit ContainerBuilder(ocppi::cli::CLI &cli);

    auto create(const linglong::generator::ContainerCfgBuilder &cfgBuilder,
                const QString &containerID) noexcept
      -> utils::error::Result<std::unique_ptr<Container>>;

private:
    ocppi::cli::CLI &cli;
};

}; // namespace linglong::runtime
