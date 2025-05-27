/*
 * SPDX-FileCopyrightText: 2022 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

#include "linglong/runtime/container_builder.h"

#include "linglong/api/types/v1/ApplicationConfiguration.hpp"
#include "linglong/oci-cfg-generators/builtins.h"
#include "linglong/utils/configure.h"
#include "linglong/utils/error/error.h"
#include "linglong/utils/serialize/json.h"
#include "linglong/utils/serialize/yaml.h"
#include "ocppi/runtime/config/types/Generators.hpp"
#include "ocppi/runtime/config/types/Mount.hpp"

#include <QProcess>
#include <QStandardPaths>
#include <QTemporaryDir>

#include <fstream>

#include <fcntl.h>

namespace linglong::runtime {

namespace {
auto getPatchesForApplication(const QString &appID) noexcept
  -> std::vector<api::types::v1::OciConfigurationPatch>
{
    auto filePath =
      QStandardPaths::locate(QStandardPaths::ConfigLocation, "linglong/" + appID + "/config.yaml");
    if (filePath.isEmpty()) {
        return {};
    }

    LINGLONG_TRACE(QString("get OCI patches for application %1").arg(appID));

    auto config =
      utils::serialize::LoadYAMLFile<api::types::v1::ApplicationConfiguration>(filePath);
    if (!config) {
        qWarning() << LINGLONG_ERRV(config);
        Q_ASSERT(false);
        return {};
    }

    if (!config->permissions) {
        return {};
    }

    if (!config->permissions->binds) {
        return {};
    }

    std::vector<api::types::v1::OciConfigurationPatch> patches;
    patches.reserve(config->permissions->binds->size());

    for (const auto &bind : *config->permissions->binds) {
        patches.push_back({
          .ociVersion = "1.0.1",
          .patch = nlohmann::json::array({
            { "op", "add" },
            { "path", "/mounts/-" },
            { "value",
              { { "source", bind.source },
                { "destination", bind.destination },
                { "options",
                  nlohmann::json::array({
                    "rbind",
                    "nosuid",
                    "nodev",
                  }) } } },
          }),
        });
    }

    return patches;
}

void applyJSONPatch(nlohmann::json &cfg,
                    const api::types::v1::OciConfigurationPatch &patch) noexcept
{
    LINGLONG_TRACE("apply oci runtime config patch");

    try {
        cfg = cfg.patch(patch.patch);
    } catch (...) {
        qCritical() << LINGLONG_ERRV("apply patch", std::current_exception());
        Q_ASSERT(false);
        return;
    }
}

void applyJSONFilePatch(ocppi::runtime::config::types::Config &cfg,
                        const std::filesystem::path &patch) noexcept
{
    LINGLONG_TRACE(QString("apply oci runtime config patch file %1").arg(patch.c_str()));

    auto patchRet = utils::serialize::LoadJSONFile<api::types::v1::OciConfigurationPatch>(patch);
    if (!patchRet) {
        qWarning() << LINGLONG_ERRV(patchRet);
        Q_ASSERT(false);
        return;
    }
    const auto &content = *patchRet;

    if (cfg.ociVersion != content.ociVersion) {
        qWarning() << "ociVersion mismatched:"
                   << nlohmann::json(content).dump(-1, ' ', true).c_str();
        Q_ASSERT(false);
        return;
    }

    auto raw = nlohmann::json(cfg);
    applyJSONPatch(raw, content);
    cfg = raw.get<ocppi::runtime::config::types::Config>();
}

void applyExecutablePatch(ocppi::runtime::config::types::Config &cfg,
                          const std::filesystem::path &patch) noexcept
{
    LINGLONG_TRACE(QString("process oci configuration generator %1").arg(patch.c_str()));

    QProcess generatorProcess;
    generatorProcess.setProgram(patch.c_str());
    generatorProcess.start();
    generatorProcess.write(QByteArray::fromStdString(nlohmann::json(cfg).dump()));
    generatorProcess.closeWriteChannel();

    constexpr auto timeout = 200;
    if (!generatorProcess.waitForFinished(timeout)) {
        qCritical() << LINGLONG_ERRV(generatorProcess.errorString(), generatorProcess.error());
        Q_ASSERT(false);
        return;
    }

    auto error = generatorProcess.readAllStandardError();
    if (generatorProcess.exitCode() != 0) {
        qCritical() << "generator" << patch.c_str() << "return" << generatorProcess.exitCode()
                    << "\ninput:\n"
                    << nlohmann::json(cfg).dump().c_str() << "\n\nstderr:\n"
                    << qPrintable(error);
        Q_ASSERT(false);
        return;
    }
    if (not error.isEmpty()) {
        qDebug() << "generator" << patch.c_str() << "stderr:" << error;
    }

    auto result = generatorProcess.readAllStandardOutput();
    auto modified = utils::serialize::LoadJSON<ocppi::runtime::config::types::Config>(result);
    if (!modified) {
        qCritical() << LINGLONG_ERRV("parse stdout", modified);
        Q_ASSERT(false);
        return;
    }

    cfg = *modified;
}

void applyPatches(ocppi::runtime::config::types::Config &cfg,
                  const std::vector<std::filesystem::directory_entry> &patches) noexcept
{
    const auto &builtins = linglong::generator::builtin_generators();
    std::error_code ec;
    for (const auto &patch : patches) {
        const auto &path = patch.path();
        auto status = patch.symlink_status(ec);
        if (ec) {
            qWarning() << "check patch file" << path.c_str() << "failed:" << ec.message().c_str();
            continue;
        }

        if (!patch.is_regular_file(ec)) {
            if (ec) {
                qWarning() << "check patch file" << path.c_str()
                           << "failed:" << ec.message().c_str();
                continue;
            }

            qWarning() << "patch is not a regular file:" << path.c_str();
            continue;
        }

        if (path.has_extension() && path.extension() == ".json") {
            applyJSONFilePatch(cfg, patch);
            continue;
        }

        if ((status.permissions()
             & (std::filesystem::perms::owner_exec | std::filesystem::perms::group_exec
                | std::filesystem::perms::others_exec))
            != std::filesystem::perms::none) {
            applyExecutablePatch(cfg, patch);
            continue;
        }

        auto gen = builtins.find(path.filename().string());
        if (gen == builtins.cend()) {
            qDebug() << "unsupported generator:" << path.c_str();
            continue;
        }

        if (!gen->second->generate(cfg)) {
            qDebug() << "builtin generator failed:" << gen->first.data();
        }
    }
}

void applyPatches(ocppi::runtime::config::types::Config &cfg,
                  const std::vector<api::types::v1::OciConfigurationPatch> &patches) noexcept
{
    auto raw = nlohmann::json(cfg);
    for (const auto &patch : patches) {
        if (patch.ociVersion != cfg.ociVersion) {
            qWarning() << "ociVersion mismatched: "
                       << nlohmann::json(patch).dump(-1, ' ', true).c_str();
            continue;
        }

        applyJSONPatch(raw, patch);
    }

    cfg = raw.get<ocppi::runtime::config::types::Config>();
}

auto fixMount(ocppi::runtime::config::types::Config &config) noexcept -> utils::error::Result<void>
{

    LINGLONG_TRACE("fix mount points.")

    if (!config.mounts || !config.root) {
        return LINGLONG_OK;
    }

    std::error_code ec;
    auto originalRoot = std::filesystem::canonical(config.root->path, ec);
    if (ec) {
        return LINGLONG_ERR(ec.message().c_str());
    }

    config.root->path = "rootfs";
    config.root->readonly = false;

    auto &mounts = config.mounts.value();
    std::vector<std::filesystem::path> tmpfsPath;
    for (const auto &mount : mounts) {
        if (mount.destination.empty() || mount.destination.at(0) != '/') {
            continue;
        }

        auto destView =
          std::string_view(mount.destination.c_str() + 1, mount.destination.size() - 1);
        auto hostSource = originalRoot / destView;
        if (std::filesystem::exists(hostSource, ec)) {
            continue;
        }

        if (ec) {
            qWarning() << "failed to check host source:" << hostSource.c_str() << ":"
                       << ec.message().c_str();
            continue;
        }

        auto existsPath = hostSource;
        while (!existsPath.empty()) {
            std::ignore = std::filesystem::symlink_status(existsPath, ec);
            if (!ec) {
                break;
            }

            if (ec == std::errc::no_such_file_or_directory) {
                existsPath = existsPath.parent_path();
                continue;
            }

            qWarning() << "failed to check host source:" << existsPath.c_str() << ":"
                       << ec.message().c_str();
            existsPath.clear();
        }

        if (existsPath.empty()) {
            qWarning() << "invalid host source:" << hostSource;
            continue;
        }

        if (existsPath <= originalRoot) {
            continue;
        }

        bool newTmp{ true };
        for (const auto &it : tmpfsPath) {
            if (existsPath == it) {
                newTmp = false;
                break;
            }
        }

        if (newTmp) {
            tmpfsPath.emplace_back(std::move(existsPath));
        }
    }

    using MountType = std::remove_reference_t<decltype(mounts)>::value_type;
    auto rootItemIt = std::filesystem::directory_iterator{
        originalRoot,
        std::filesystem::directory_options::skip_permission_denied,
        ec
    };
    if (ec) {
        return LINGLONG_ERR(ec.message().c_str());
    }

    auto pos = mounts.begin();
    for (const auto &entry : rootItemIt) {
        auto mountPoint = MountType{
            .destination = "/" / entry.path().filename(),
            .options = { { "rbind", "ro" } },
            .source = entry.path(),
            .type = "bind",
        };

        auto status = std::filesystem::symlink_status(entry.path(), ec);
        if (ec) {
            return LINGLONG_ERR(ec.message().c_str());
        }

        if (status.type() == std::filesystem::file_type::symlink) {
            mountPoint.options->emplace_back("copy-symlink");
        }

        pos = mounts.insert(pos, std::move(mountPoint));
        ++pos;
    }

    for (const auto &tmpfs : tmpfsPath) {
        pos = mounts.emplace(pos,
                             MountType{
                               .destination = "/" / tmpfs.lexically_relative(originalRoot),
                               .options = { { "nodev", "nosuid", "mode=755" } },
                               .source = "tmpfs",
                               .type = "tmpfs",
                             });
        ++pos;

        auto dirIt = std::filesystem::directory_iterator{
            tmpfs,
            std::filesystem::directory_options::skip_permission_denied,
            ec
        };
        if (ec) {
            return LINGLONG_ERR(ec.message().c_str());
        }

        for (const auto &entry : dirIt) {
            auto mountPoint = MountType{
                .destination = "/" / entry.path().lexically_relative(originalRoot),
                .options = { { "rbind", "ro" } },
                .source = entry.path(),
                .type = "bind",
            };

            if (std::filesystem::is_symlink(entry.path(), ec)) {
                mountPoint.options->emplace_back("copy-symlink");
            }

            if (ec) {
                return LINGLONG_ERR(ec.message().c_str());
            }

            pos = mounts.emplace(pos, std::move(mountPoint));
            ++pos;
        }
    }

    // remove extra mount points
    std::unordered_set<std::string> dups;
    for (auto it = mounts.rbegin(); it != mounts.rend();) {
        if (dups.find(it->destination) != dups.end()) {
            auto next_forward = mounts.erase(std::prev(it.base()));
            it = std::make_reverse_iterator(next_forward);
            continue;
        }

        dups.emplace(it->destination);
        ++it;
    }

    return LINGLONG_OK;
};

} // namespace

ContainerBuilder::ContainerBuilder(ocppi::cli::CLI &cli)
    : cli(cli)
{
}

auto ContainerBuilder::create(const ContainerOptions &opts) noexcept
  -> utils::error::Result<std::unique_ptr<Container>>
{
    LINGLONG_TRACE("create container");

    std::error_code ec;
    const auto &bundle = opts.bundle;
    if (bundle.empty() || !bundle.is_absolute() || !std::filesystem::exists(bundle, ec)) {
        if (ec) {
            return LINGLONG_ERR("failed to check bundle directory", ec);
        }

        return LINGLONG_ERR(QString{ "invalid bundle directory: %1" }.arg(bundle.c_str()));
    }

    auto configRet = getOCIConfig(opts);
    if (!configRet) {
        return LINGLONG_ERR(configRet);
    }

    auto config = std::move(configRet).value();
    // save env to /run/user/1000/linglong/xxx/00env.sh, mount it to /etc/profile.d/00env.sh
    auto envShFile = bundle / "00env.sh";
    {
        std::ofstream ofs(envShFile);
        Q_ASSERT(ofs.is_open());
        if (!ofs.is_open()) {
            return LINGLONG_ERR("create 00env.sh failed in bundle directory");
        }

        for (const auto &env : config.process->env.value()) {
            const QString envStr = QString::fromStdString(env);
            auto pos = envStr.indexOf("=");
            auto value = envStr.mid(pos + 1, envStr.length());
            // here we process environment variables with single quotes.
            // A=a'b ===> A='a'\''b'
            value.replace("'", R"('\'')");

            // We need to quote the values environment variables
            // avoid loading errors when some environment variables have multiple values, such as
            // (a;b).
            const auto fixEnv = QString(R"(%1='%2')").arg(envStr.mid(0, pos)).arg(value);
            ofs << "export " << fixEnv.toStdString() << std::endl;
        }
        ofs.close();
    }

    config.mounts->push_back(ocppi::runtime::config::types::Mount{
      .destination = "/etc/profile.d/00env.sh",
      .gidMappings = {},
      .options = { { "ro", "rbind" } },
      .source = envShFile,
      .type = "bind",
      .uidMappings = {},
    });

    auto ret = fixMount(config);
    if (!ret) {
        return LINGLONG_ERR(ret);
    }

    // ensure container root exists
    auto containerRoot = bundle / config.root->path;
    if (!std::filesystem::create_directories(containerRoot, ec) && ec) {
        return LINGLONG_ERR("failed to create container root", ec);
    }

    return std::make_unique<Container>(std::move(config), opts.appID, opts.containerID, this->cli);
}

auto ContainerBuilder::createWithConfig(const ocppi::runtime::config::types::Config &originalConfig,
                                        const QString &containerID) noexcept
  -> utils::error::Result<std::unique_ptr<Container>>
{
    LINGLONG_TRACE("create container with config");

    if (!originalConfig.annotations) {
        return LINGLONG_ERR("missing annotations");
    }

    const auto &annotations = originalConfig.annotations.value();
    auto appID = annotations.find("org.deepin.linglong.appID");
    if (appID == annotations.end()) {
        return LINGLONG_ERR("missing appID");
    }

    return std::make_unique<Container>(originalConfig,
                                       QString::fromStdString(appID->second),
                                       containerID,
                                       this->cli);
}

auto ContainerBuilder::getOCIConfig(const ContainerOptions &opts) noexcept
  -> utils::error::Result<ocppi::runtime::config::types::Config>
{
    LINGLONG_TRACE("get origin OCI configuration file");

    std::filesystem::path containerConfigFilePath{ LINGLONG_INSTALL_PREFIX
                                                   "/lib/linglong/container/config.json" };
    auto *containerConfigFile = ::getenv("LINGLONG_CONTAINER_CONFIG");
    if (containerConfigFile != nullptr) {
        containerConfigFilePath = containerConfigFile;
    }

    std::error_code ec;
    if (!std::filesystem::exists(containerConfigFilePath, ec)) {
        if (ec) {
            return LINGLONG_ERR("failed to check container configuration file", ec);
        }

        return LINGLONG_ERR(
          QString("The container configuration file doesn't exist: %1\n"
                  "You can specify a custom location using the LINGLONG_CONTAINER_CONFIG")
            .arg(containerConfigFilePath.c_str()));
    }

    auto config = utils::serialize::LoadJSONFile<ocppi::runtime::config::types::Config>(
      containerConfigFilePath);
    if (!config) {
        Q_ASSERT(false);
        return LINGLONG_ERR(config);
    }

    config->root = ocppi::runtime::config::types::Root{
        .path = opts.baseDir.absoluteFilePath("files").toStdString(),
        .readonly = true,
    };

    auto annotations = config->annotations.value_or(std::map<std::string, std::string>{});
    annotations["org.deepin.linglong.appID"] = opts.appID.toStdString();
    annotations["org.deepin.linglong.baseDir"] = opts.baseDir.absolutePath().toStdString();
    annotations["org.deepin.linglong.bundleDir"] = opts.bundle;

    if (opts.runtimeDir) {
        annotations["org.deepin.linglong.runtimeDir"] =
          opts.runtimeDir->absolutePath().toStdString();
    }
    if (opts.appDir) {
        annotations["org.deepin.linglong.appDir"] = opts.appDir->absolutePath().toStdString();
    }
    config->annotations = std::move(annotations);

    auto configDotDDir = std::filesystem::directory_iterator{
        containerConfigFilePath.parent_path() / "config.d",
        std::filesystem::directory_options::skip_permission_denied,
        ec
    };
    if (ec) {
        return LINGLONG_ERR("failed to check container configuration directory", ec);
    }

    std::vector<std::filesystem::directory_entry> patches;
    for (const auto &entry : configDotDDir) {
        patches.emplace_back(entry.path());
    }
    std::sort(patches.begin(), patches.end(), [](const auto &a, const auto &b) {
        return a.path().filename() < b.path().filename();
    });

    applyPatches(*config, patches);

    auto appPatches = getPatchesForApplication(opts.appID);

    applyPatches(*config, appPatches);

    applyPatches(*config, opts.patches);

    Q_ASSERT(config->mounts.has_value());
    auto &mounts = *config->mounts;

    mounts.insert(mounts.end(), opts.mounts.begin(), opts.mounts.end());

    config->linux_->maskedPaths = opts.masks;

    config->hooks = opts.hooks;

    return config;
}
} // namespace linglong::runtime
