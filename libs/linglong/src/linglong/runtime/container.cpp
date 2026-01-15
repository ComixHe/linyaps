/*
 * SPDX-FileCopyrightText: 2022 - 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

#include "linglong/runtime/container.h"

#include "configure.h"
#include "linglong/common/dir.h"
#include "linglong/common/error.h"
#include "linglong/common/helper.h"
#include "linglong/common/socket.h"
#include "linglong/utils/bash_command_helper.h"
#include "linglong/utils/filelock.h"
#include "linglong/utils/finally/finally.h"
#include "linglong/utils/log/log.h"
#include "ocppi/runtime/ExecOption.hpp"
#include "ocppi/runtime/RunOption.hpp"
#include "ocppi/runtime/config/types/Generators.hpp"

#include <fmt/format.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/termios.h>

#include <fstream>
#include <utility>

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {
void mergeProcessConfig(ocppi::runtime::config::types::Process &dst,
                        const ocppi::runtime::config::types::Process &src)
{
    if (src.user) {
        dst.user = src.user;
    }

    if (src.apparmorProfile) {
        dst.apparmorProfile = src.apparmorProfile;
    }

    if (src.args) {
        dst.args = src.args;
    }

    if (src.capabilities) {
        dst.capabilities = src.capabilities;
    }

    if (src.commandLine) {
        dst.commandLine = src.commandLine;
    }

    if (src.consoleSize) {
        dst.consoleSize = src.consoleSize;
    }

    if (!src.cwd.empty()) {
        dst.cwd = src.cwd;
    }

    if (src.env) {
        if (!dst.env) {
            dst.env = src.env;
        } else {
            auto &dstEnv = dst.env.value();
            for (const auto &env : src.env.value()) {
                auto key = env.find_first_of('=');
                if (key == std::string::npos) {
                    continue;
                }

                auto it =
                  std::find_if(dstEnv.begin(), dstEnv.end(), [&key, &env](const std::string &dst) {
                      return dst.rfind(std::string_view(env.data(), key + 1), 0) == 0;
                  });

                if (it != dstEnv.end()) {
                    qWarning() << "environment set multiple times " << QString::fromStdString(*it)
                               << QString::fromStdString(env);
                    *it = env;
                } else {
                    dstEnv.emplace_back(env);
                }
            }
        }
    }

    if (src.ioPriority) {
        dst.ioPriority = src.ioPriority;
    }

    if (src.noNewPrivileges) {
        dst.noNewPrivileges = src.noNewPrivileges;
    }

    if (src.oomScoreAdj) {
        dst.oomScoreAdj = src.oomScoreAdj;
    }

    if (src.rlimits) {
        dst.rlimits = src.rlimits;
    }

    if (src.scheduler) {
        dst.scheduler = src.scheduler;
    }

    if (src.selinuxLabel) {
        dst.selinuxLabel = src.selinuxLabel;
    }

    if (src.terminal) {
        dst.terminal = src.terminal;
    }

    if (src.user) {
        dst.user = src.user;
    }
}
} // namespace

namespace linglong::runtime {

Container::Container(ocppi::runtime::config::types::Config cfg,
                     std::string containerId,
                     std::filesystem::path bundleDir,
                     ocppi::cli::CLI &cli)
    : cfg(std::move(cfg))
    , id(std::move(containerId))
    , bundleDir(std::move(bundleDir))
    , cli(cli)
{
    Q_ASSERT(cfg.process.has_value());
}

utils::error::Result<int> Container::reuse(const std::vector<std::string> &commands) noexcept
{
    LINGLONG_TRACE(fmt::format("reuse container {}", this->id))

    auto containerLock = common::dir::getBundleDir(id) / ".lock";
    auto lockRet = utils::filelock::FileLock::create(containerLock, false);
    if (!lockRet) {
        // maybe the main container is initializing
        return -1;
    }
    auto lock = std::move(lockRet).value();

    auto ret = lock.tryLock(utils::filelock::LockType::Read);
    if (!ret) {
        return LINGLONG_ERR(ret);
    }

    if (!*ret) {
        return -1;
    }

    {
        std::ifstream in(containerLock);
        std::string content;
        in >> content;
        if (content != "running") {
            return false;
        }
    }

    std::string script;
    for (const auto &arg : commands) {
        script.append(common::strings::quoteBashArg(arg));
        script.push_back(' ');
    }
    script.pop_back();

    const auto entrypoint = fmt::format("((source /etc/profile;exec {})& disown)& disown", script);
    auto delegateCmds = utils::BashCommandHelper::generateBashCommandBase();
    delegateCmds.push_back(entrypoint);
    auto bin = delegateCmds.at(0);
    std::vector<std::string> args;
    std::move(delegateCmds.begin() + 1, delegateCmds.end(), std::back_inserter(args));

    std::filesystem::path consoleSocket;
    auto remove = utils::finally::finally([&consoleSocket]() {
        if (!consoleSocket.empty()) {
            std::filesystem::remove(consoleSocket);
        }
    });

    std::variant<int, std::array<int, 2>> ioChannel;

    auto option = ocppi::runtime::ExecOption{ .uid = ::getuid(), .gid = ::getgid() };
    if (isatty(STDOUT_FILENO) != 0) {
        option.tty = true;

        consoleSocket =
          common::dir::getRuntimeDir() / ("socket-" + common::strings::generateRandomString(6));
        auto ret = common::socket::createUnixSocket(consoleSocket.c_str());
        if (!ret) {
            return LINGLONG_ERR(fmt::format("failed to create unix socket: {}", ret.error()));
        }

        ioChannel.emplace<int>(ret.value());
        option.extra.emplace_back(fmt::format("--console-socket={}", consoleSocket));
    } else {
        std::array<int, 2> sockPair{};
        auto ret = ::socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockPair.data());
        if (ret != 0) {
            return LINGLONG_ERR(
              fmt::format("failed to create socket pair: {}", common::error::errorString(errno)));
        }

        ioChannel.emplace<std::array<int, 2>>(sockPair);
    }

    auto child = ::fork();
    if (child == 0) {
        std::visit(common::helper::Overload{
                     [](const int &fd) {
                         auto ret = ::close(fd);
                         if (ret != 0) {
                             LogE("failed to close console socket fd: {}",
                                  common::error::errorString(errno));
                             _exit(EXIT_FAILURE);
                         }
                     },
                     [](const std::array<int, 2> &pair) {
                         auto ret = ::close(pair[0]);
                         if (ret != 0) {
                             LogE("failed to close fd: {}", common::error::errorString(errno));
                             _exit(EXIT_FAILURE);
                         }

                         ret = ::dup2(pair[1], STDIN_FILENO);
                         if (ret != 0) {
                             LogE("failed to dup2 socketpair to stdin: {}",
                                  common::error::errorString(errno));
                             _exit(EXIT_FAILURE);
                         }

                         ret = ::dup2(pair[1], STDOUT_FILENO);
                         if (ret != 0) {
                             LogE("failed to dup2 socketpair to stdout: {}",
                                  common::error::errorString(errno));
                             _exit(EXIT_FAILURE);
                         }

                         ret = ::dup2(pair[1], STDERR_FILENO);
                         if (ret != 0) {
                             LogE("failed to dup2 socketpair to stderr: {}",
                                  common::error::errorString(errno));
                             _exit(EXIT_FAILURE);
                         }

                         ret = ::close(pair[1]);
                         if (ret != 0) {
                             LogE("failed to close fd: {}", common::error::errorString(errno));
                             _exit(EXIT_FAILURE);
                         }
                     } },
                   ioChannel);

        auto result = cli.exec(id, bin, args, option);
        if (!result) {
            LogE("failed to exec container: {}", LINGLONG_ERRV("oci exec", result));
            _exit(EXIT_FAILURE);
        }

        _exit(EXIT_SUCCESS);
    }

    auto releaseIoChannel = utils::finally::finally([&ioChannel]() {
        std::visit(common::helper::Overload{ [](const int &fd) {
                                                if (fd != -1) {
                                                    ::close(fd);
                                                }
                                            },
                                             [](const std::array<int, 2> &pair) {
                                                 if (pair[0] != -1) {
                                                     ::close(pair[0]);
                                                 }

                                                 if (pair[1] != -1) {
                                                     ::close(pair[1]);
                                                 }
                                             } },
                   ioChannel);
    });

    auto chan = std::visit(common::helper::Overload{
                             [](int &fd) -> utils::error::Result<int> {
                                 LINGLONG_TRACE("receive clinet connection through socket")
                                 struct sockaddr_un client_addr{};
                                 socklen_t addr_len = sizeof(client_addr);
                                 auto client =
                                   ::accept4(fd,
                                             reinterpret_cast<struct sockaddr *>(&client_addr),
                                             &addr_len,
                                             SOCK_CLOEXEC);
                                 if (client < 0) {
                                     return LINGLONG_ERR(common::error::errorString(errno));
                                 }

                                 auto ret = ::close(fd);
                                 if (ret < 0) {
                                     ::close(client);
                                     return LINGLONG_ERR(common::error::errorString(errno));
                                 }
                                 fd = -1;

                                 return client;
                             },
                             [](std::array<int, 2> &pair) -> utils::error::Result<int> {
                                 LINGLONG_TRACE("use socketpair")
                                 auto ret = ::close(pair[1]);
                                 if (ret < 0) {
                                     return LINGLONG_ERR(common::error::errorString(errno));
                                 }
                                 pair[1] = -1;

                                 auto client = ::dup(pair[0]);
                                 if (client < 0) {
                                     return LINGLONG_ERR(common::error::errorString(errno));
                                 }

                                 ret = ::close(pair[0]);
                                 if (ret < 0) {
                                     ::close(client);
                                     return LINGLONG_ERR(common::error::errorString(errno));
                                 }
                                 pair[0] = -1;

                                 return client;
                             },
                           },
                           ioChannel);
    if (!chan) {
        return LINGLONG_ERR(chan);
    }

    std::optional<struct termios> originalTermios;
    auto recoveryTermios = utils::finally::finally([&originalTermios]() {
        if (originalTermios) {
            auto ret = ::tcsetattr(STDOUT_FILENO, TCSAFLUSH, &originalTermios.value());
            if (ret != 0) {
                LogE("failed to set terminal attributes: {}", common::error::errorString(errno));
            }
        }
    });

    if (option.tty) {
        originalTermios.emplace();
        auto ret = ::tcgetattr(STDOUT_FILENO, &originalTermios.value());
        if (ret != 0) {
            return LINGLONG_ERR(fmt::format("failed to get terminal attributes: {}",
                                            common::error::errorString(errno)));
        }

        auto raw = originalTermios.value();
        cfmakeraw(&raw);

        if (tcsetattr(STDOUT_FILENO, TCSAFLUSH, &raw) < 0) {
            return LINGLONG_ERR(
              fmt::format("failed to set terminal to raw mode", common::error::errorString(errno)));
        }

        struct winsize ws{};
        ret = ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws);
        if (ret != 0) {
            return LINGLONG_ERR(
              fmt::format("failed to get terminal size: {}", common::error::errorString(errno)));
        }

        ret = ioctl(*chan, TIOCSWINSZ, &ws);
        if (ret != 0) {
            return LINGLONG_ERR(
              fmt::format("failed to set terminal size: {}", common::error::errorString(errno)));
        }
    }

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGWINCH);
    if (sigprocmask(SIG_BLOCK, &mask, nullptr) < 0) {
        return LINGLONG_ERR(
          fmt::format("failed to mask signal: {}", common::error::errorString(errno)));
    }

    auto masterIn = std::move(chan).value();
    auto closeMasterIn = utils::finally::finally([&masterIn]() {
        if (masterIn != -1) {
            ::close(masterIn);
        }
    });

    auto masterOut = ::dup(masterIn);
    if (masterOut < 0) {
        return LINGLONG_ERR(common::error::errorString(errno));
    }

    auto closeMasterOut = utils::finally::finally([&masterOut]() {
        if (masterOut != -1) {
            ::close(masterOut);
        }
    });

    auto sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (sfd < 0) {
        return LINGLONG_ERR(
          fmt::format("failed to create signalfd: {}", common::error::errorString(errno)));
    }
    auto closeSfd = utils::finally::finally([sfd]() {
        ::close(sfd);
    });

    auto reapChild = [child]() -> int {
        int status{ 0 };
        while (true) {
            auto ret = ::waitpid(-1, &status, WNOHANG);
            if (ret > 0) {
                if (ret == child) {
                    if (WIFEXITED(status)) {
                        return WEXITSTATUS(status);
                    }

                    if (WIFSIGNALED(status)) {
                        return 128 + WTERMSIG(status);
                    }

                    return -1;
                }

                continue;
            }

            if (ret == 0) {
                break;
            }

            if (ret < 0) {
                if (errno == EINTR) {
                    continue;
                }

                if (errno == ECHILD) {
                    break;
                }

                return -1;
            }
        }

        return 0;
    };

    auto status = reapChild();
    if (status < 0) {
        // just kill child
        ::kill(child, SIGKILL);
        return LINGLONG_ERR(
          fmt::format("failed to reap child: {}", common::error::errorString(errno)));
    }

    int exit_status{ 0 };
    if (status > 0) {
        exit_status = status;
    }

    auto epfd = ::epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) {
        return LINGLONG_ERR(common::error::errorString(errno));
    }
    auto closeEpfd = utils::finally::finally([epfd]() {
        ::close(epfd);
    });

    // TODO: add all fd and handle event

    if (auto ret = lock.unlock(); !ret) {
        return LINGLONG_ERR(ret);
    }

    return exit_status;
}

utils::error::Result<void> Container::run(const ocppi::runtime::config::types::Process &process,
                                          ocppi::runtime::RunOption opt) noexcept
{
    LINGLONG_TRACE(fmt::format("run container {}", this->id));

    auto _ = utils::finally::finally([&]() {
        std::error_code ec;
        while (getenv("LINGLONG_DEBUG") != nullptr) {
            std::filesystem::path debugDir = common::dir::getRuntimeDir() / "debug";
            std::filesystem::create_directories(debugDir, ec);
            if (ec) {
                LogE("failed to create debug directory {}: {}", debugDir, ec.message());
                break;
            }

            auto archive = debugDir / this->bundleDir.filename();
            std::filesystem::rename(this->bundleDir, archive, ec);
            if (ec) {
                LogE("failed to rename bundle directory to {}: {}", archive, ec.message());
                break;
            }

            return;
        }

        std::filesystem::remove_all(this->bundleDir, ec);
        if (ec) {
            LogW("failed to remove bundle directory {}: {}", this->bundleDir, ec.message());
        }
    });

    auto curProcess =
      std::move(this->cfg.process).value_or(ocppi::runtime::config::types::Process{});
    mergeProcessConfig(curProcess, process);
    this->cfg.process = std::move(curProcess);

    std::error_code ec;
    if (this->cfg.process->cwd.empty()) {
        auto cwd = std::filesystem::current_path(ec);
        LogD("cwd of process is empty, run process in current directory {}.", cwd);
        this->cfg.process->cwd = std::filesystem::path{ "/run/host/rootfs" } / cwd;
    }

    if (!this->cfg.process->user) {
        this->cfg.process->user =
          ocppi::runtime::config::types::User{ .gid = ::getgid(), .uid = ::getuid() };
    }

    if (isatty(fileno(stdin)) != 0) {
        this->cfg.process->terminal = true;
    }

    this->cfg.mounts->push_back(ocppi::runtime::config::types::Mount{
      .destination = "/run/linglong/container-init",
      .options = { { "ro", "rbind" } },
      .source = std::string{ LINGLONG_CONTAINER_INIT },
      .type = "bind",
    });

    auto originalArgs =
      this->cfg.process->args.value_or(std::vector<std::string>{ "echo", "noting to run" });

    auto entrypoint = bundleDir / "entrypoint.sh";
    {
        std::ofstream ofs(entrypoint);
        Q_ASSERT(ofs.is_open());
        if (!ofs.is_open()) {
            return LINGLONG_ERR("create font config in bundle directory");
        }

        ofs << utils::BashCommandHelper::generateEntrypointScript(originalArgs);
    }

    std::filesystem::permissions(entrypoint, std::filesystem::perms::owner_all, ec);
    if (ec) {
        return LINGLONG_ERR("make entrypoint executable", ec);
    }

    const auto *entrypointPath = "/run/linglong/entrypoint.sh";

    this->cfg.mounts->push_back(ocppi::runtime::config::types::Mount{
      .destination = entrypointPath,
      .options = { { "ro", "rbind" } },
      .source = entrypoint,
      .type = "bind",
    });

    auto cmd = utils::BashCommandHelper::generateInitCommand(entrypointPath);
    this->cfg.process->args = cmd;

    {
        std::ofstream ofs(bundleDir / "config.json");
        Q_ASSERT(ofs.is_open());
        if (!ofs.is_open()) {
            return LINGLONG_ERR("create config.json in bundle directory");
        }

        ofs << nlohmann::json(this->cfg);
        ofs.close();
    }
    LogD("run container with bundle {}", bundleDir);
    // 禁用crun自己创建cgroup，便于AM识别和管理玲珑应用
    opt.GlobalOption::extra.emplace_back("--cgroup-manager=disabled");

    auto result = this->cli.run(this->id, bundleDir, opt);
    if (!result) {
        return LINGLONG_ERR("cli run", result);
    }

    return LINGLONG_OK;
}

} // namespace linglong::runtime
