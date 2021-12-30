/*
 * Copyright (c) 2020-2021. Uniontech Software Ltd. All rights reserved.
 *
 * Author:     Iceyer <me@iceyer.net>
 *
 * Maintainer: Iceyer <me@iceyer.net>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef LINGLONG_BOX_SRC_MODULE_PACKAGE_REF_H_
#define LINGLONG_BOX_SRC_MODULE_PACKAGE_REF_H_

#include <QString>

namespace linglong {
namespace package {

const auto kDefaultRepo = "deepin";
const auto kDefaultChannel = "main";

class Ref
{
public:
    explicit Ref(const QString &appId);

    Ref(const QString &remote, const QString &appId, const QString &version, const QString &arch)
        : repo(remote)
        , appId(appId)
        , version(version)
        , arch(arch)
    {
    }

    QString toString() const
    {
        QString ref = repo.isEmpty() ? "" : repo + ":";
        return QString(ref + "%1/%2/%3").arg(appId, version, arch);
    }

    // FIXME: local().toString()?
    QString toLocalRefString() const { return QString("%1/%2/%3").arg(appId, version, arch); }

    QString repo;
    QString channel;
    QString appId;
    QString version;
    QString arch;

private:
    // TODO: now is app/runtime
    QString classify;
};

} // namespace package
} // namespace linglong

#endif /* LINGLONG_BOX_SRC_MODULE_PACKAGE_REF_H_ */