/*
 * SPDX-FileCopyrightText: 2022 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

#pragma once

#include "linglong/api/types/v1/CliContainer.hpp"
#include "linglong/api/types/v1/CommonResult.hpp"
#include "linglong/api/types/v1/LayerInfo.hpp"
#include "linglong/api/types/v1/PackageInfoV2.hpp"
#include "linglong/api/types/v1/RepoConfigV2.hpp"
#include "linglong/api/types/v1/UpgradeListResult.hpp"
#include "linglong/cli/printer.h"
#include "linglong/utils/error/error.h"

#include <QJsonObject>
#include <QObject>
#include <QString>

#include <string>

namespace linglong::cli {

class CLIPrinter : public Printer
{
public:
    CLIPrinter() = default;
    CLIPrinter(const CLIPrinter &) = delete;
    CLIPrinter(CLIPrinter &&) = delete;
    CLIPrinter &operator=(const CLIPrinter &) = delete;
    CLIPrinter &operator=(CLIPrinter &&) = delete;
    ~CLIPrinter() override = default;

    void printErr(const utils::error::Error &) override;
    void printPackage(const api::types::v1::PackageInfoV2 &) override;
    void printPackages(const std::vector<api::types::v1::PackageInfoDisplay> &) override;
    void
      printSearchResult(std::map<std::string, std::vector<api::types::v1::PackageInfoV2>>) override;
    void printPruneResult(const std::vector<api::types::v1::PackageInfoV2> &list) override;
    void printContainers(const std::vector<api::types::v1::CliContainer> &) override;
    void printReply(const api::types::v1::CommonResult &) override;
    void printRepoConfig(const api::types::v1::RepoConfigV2 &) override;
    void printLayerInfo(const api::types::v1::LayerInfo &) override;
    void printTaskState(double percentage,
                        const QString &message,
                        api::types::v1::State state,
                        api::types::v1::SubState subState) override;
    void printContent(const QStringList &filePaths) override;
    void printUpgradeList(std::vector<api::types::v1::UpgradeListResult> &) override;
    void printInspect(const api::types::v1::InspectResult &result) override;
    void printMessage(const QString &message) override;
};

} // namespace linglong::cli
