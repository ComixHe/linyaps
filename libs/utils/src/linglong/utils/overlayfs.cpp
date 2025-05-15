// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "overlayfs.h"

#include "linglong/utils/command/env.h"

#include <QDir>

#include <utility>

namespace linglong::utils {

OverlayFS::OverlayFS(QString lowerdir, QString upperdir, QString workdir, QString merged)
    : lowerdir_(std::move(lowerdir))
    , upperdir_(std::move(upperdir))
    , workdir_(std::move(workdir))
    , merged_(std::move(merged))
{
}

OverlayFS::~OverlayFS()
{
    auto res = utils::command::Exec("fusermount", { "-z", "-u", merged_ });
    if (!res) {
        qWarning() << QString("failed to umount %1 ").arg(merged_) << res.error().message();
    }
}

bool OverlayFS::mount()
{
    QDir upperDir(upperdir_);
    if (!upperDir.mkpath(".")) {
        return false;
    }

    QDir workDir(workdir_);
    if (!workDir.mkpath(".")) {
        return false;
    }

    QDir mergedDir(merged_);
    if (!mergedDir.mkpath(".")) {
        return false;
    }

    utils::command::Exec("fusermount", { "-z", "-u", merged_ });

    auto ret = utils::command::Exec(
      "fuse-overlayfs",
      { "fuse-overlayfs",
        "-o",
        QString("lowerdir=%1,upperdir=%2,workdir=%3").arg(lowerdir_, upperdir_, workdir_),
        merged_ });
    if (!ret) {
        qWarning() << "failed to mount " << ret.error().message();
    }

    return !!ret;
}

void OverlayFS::unmount(bool clean)
{
    auto res = utils::command::Exec("fusermount", { "-z", "-u", merged_ });
    if (!res) {
        qWarning() << QString("failed to umount %1 ").arg(merged_) << res.error().message();
    }

    if (clean) {
        QDir(upperdir_).removeRecursively();
        QDir(workdir_).removeRecursively();
    }
}

} // namespace linglong::utils
