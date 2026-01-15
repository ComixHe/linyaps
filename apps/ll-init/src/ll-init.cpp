// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "linglong/common/dir.h"

#include <fmt/format.h>
#include <sys/epoll.h>
#include <sys/fcntl.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>

#include <array>
#include <csignal>
#include <cstddef>
#include <cstring>
#include <vector>

#include <sys/wait.h>
#include <unistd.h>

// no need to block these signals
constexpr std::array unblock_signals{ SIGABRT, SIGBUS,  SIGFPE,  SIGILL, SIGSEGV,
                                      SIGSYS,  SIGTRAP, SIGXCPU, SIGXFSZ };

// now, we just inherit the control terminal from the outside and put all the processes in the
// same process group. maybe we need refactor this in the future.

namespace {
void print_sys_error(std::string_view msg, int error) noexcept
{
    auto msg_str = fmt::format("{}: {}", msg, ::strerror(error));
    fmt::println(stderr, msg_str);
}

void print_sys_error(std::string_view msg) noexcept
{
    print_sys_error(msg, errno);
}

void print_info(std::string_view msg) noexcept
{
    static const auto is_debug = ::getenv("LINYAPS_INIT_VERBOSE_OUTPUT") != nullptr;
    if (is_debug) {
        fmt::println(stderr, msg);
    }
}

class sigConf
{
public:
    sigConf() noexcept = default;
    sigConf(const sigConf &) = delete;
    sigConf(sigConf &&) = delete;
    sigConf &operator=(const sigConf &) = delete;
    sigConf &operator=(sigConf &&) = delete;
    ~sigConf() noexcept = default;

    bool block_signals() noexcept
    {
        ::sigfillset(&cur_set);
        for (auto signal : unblock_signals) {
            ::sigdelset(&cur_set, signal);
        }

        // ignore the rest of the signals
        auto ret = ::sigprocmask(SIG_SETMASK, &cur_set, &old_set);
        if (ret == -1) {
            print_sys_error("Failed to set signal mask");
            return false;
        }

        return true;
    }

    [[nodiscard]] bool restore_signals() const noexcept
    {
        auto ret = ::sigprocmask(SIG_SETMASK, &old_set, nullptr);
        if (ret == -1) {
            print_sys_error("Failed to restore signal mask");
            return false;
        }

        return true;
    }

    [[nodiscard]] const sigset_t &current_sigset() const noexcept { return cur_set; }

private:
    sigset_t cur_set{};
    sigset_t old_set{};
};

class file_descriptor_wrapper
{
public:
    explicit file_descriptor_wrapper(int fd) noexcept
        : fd(fd)
    {
    }

    file_descriptor_wrapper() noexcept = default;

    file_descriptor_wrapper(const file_descriptor_wrapper &) = delete;
    file_descriptor_wrapper &operator=(const file_descriptor_wrapper &) = delete;

    file_descriptor_wrapper(file_descriptor_wrapper &&other) noexcept
        : fd(other.fd)
    {
        other.fd = -1;
    }

    file_descriptor_wrapper &operator=(file_descriptor_wrapper &&other) noexcept
    {
        if (this == &other) {
            return *this;
        }

        close();
        fd = other.fd;
        other.fd = -1;

        return *this;
    }

    ~file_descriptor_wrapper() noexcept { close(); }

    void close() noexcept
    {
        if (fd != -1) {
            ::close(fd);
            fd = -1;
        }
    }

    explicit operator bool() const noexcept { return fd != -1; }

    operator int() const noexcept { return fd; } // NOLINT

private:
    int fd{ -1 };
};

file_descriptor_wrapper create_signalfd(const sigset_t &sigset) noexcept
{
    auto fd = ::signalfd(-1, &sigset, SFD_NONBLOCK | SFD_CLOEXEC);
    if (fd == -1) {
        print_sys_error("Failed to create signalfd");
    }

    return file_descriptor_wrapper(fd);
}

file_descriptor_wrapper create_epoll() noexcept
{
    auto fd = ::epoll_create1(0);
    if (fd == -1) {
        print_sys_error("Failed to create epoll");
    }

    return file_descriptor_wrapper(fd);
}

template <std::size_t N>
constexpr auto make_array(const char (&str)[N]) noexcept // NOLINT
{
    static_assert(N > 0, "N must be greater than 0");
    std::array<char, N - 1> arr{};
    for (std::size_t i = 0; i < N - 1; ++i) {
        arr[i] = str[i];
    }

    return arr;
}

std::vector<const char *> parse_args(int argc, char *argv[]) noexcept
{
    std::vector<const char *> args;
    int idx{ 1 };

    while (idx < argc) {
        args.emplace_back(argv[idx++]);
    }
    args.emplace_back(nullptr);

    return args;
}

void print_child_status(int status, const std::string &pid) noexcept
{
    if (WIFEXITED(status)) {
        print_info(fmt::format("child {} exited with status {}", pid, WEXITSTATUS(status)));
    } else if (WIFSIGNALED(status)) {
        print_info(fmt::format("child {} exited with signal {}", pid, WTERMSIG(status)));
    } else {
        print_info(fmt::format("child {} exited with unknown status {}", pid, status));
    }
}

pid_t run(std::vector<const char *> args, const sigConf &conf) noexcept
{
    auto pid = ::fork();
    if (pid == -1) {
        print_sys_error("Failed to fork");
        return -1;
    }

    // Now, we wouldn't create new session because we need to inherit the terminal from the outside
    // we could do this if linyaps-box support '--console-socket' in the future.
    if (pid == 0) {
        auto ret = ::setpgid(0, 0);
        if (ret == -1) {
            print_sys_error("Failed to set process group");
            return -1;
        }

        ret = ::tcsetpgrp(0, ::getpid());
        if (ret == -1 && errno != ENOTTY) {
            print_sys_error("Failed to set terminal process group");
            return -1;
        }

        if (!conf.restore_signals()) {
            return -1;
        }

        ::execvp(args[0], const_cast<char *const *>(args.data()));
        print_sys_error("Failed to run process");
        ::_exit(EXIT_FAILURE);
    }

    return pid;
}

bool handle_sigevent(const file_descriptor_wrapper &sigfd, pid_t &child) noexcept
{
    while (true) {
        signalfd_siginfo info{};
        auto ret = ::read(sigfd, &info, sizeof(info));
        if (ret == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }

            print_sys_error("Failed to read from signalfd");
            return false;
        }

        if (info.ssi_signo != SIGCHLD) {
            auto ret = ::kill(child, info.ssi_signo);
            if (ret == -1) {
                print_sys_error(
                  fmt::format("Failed to forward signal {}", ::strsignal(info.ssi_signo)));
            }
            continue;
        }

        while (true) {
            int status{};
            auto ret = ::waitpid(-1, &status, WNOHANG);
            if (ret == 0 || (ret == -1 && errno == ECHILD)) {
                break;
            }

            if (ret == -1) {
                print_sys_error("Failed to wait for child");
                return false;
            }

            print_child_status(status, std::to_string(ret));

            if (ret == child) {
                // Init process will propagate received signals to all child processes (using
                // pid -1) after initial child exits
                // we don't specify WUNTRACED flag here, so no need to handle WIFSTOPPED
                child = -1;
            }
        }
    }

    return true;
}

bool shouldWait() noexcept
{
    while (true) {
        int stat_loc{};
        auto ret = ::waitpid(-1, &stat_loc, WNOHANG);
        if (ret == -1) {
            if (errno == EINTR) {
                continue;
            }

            if (errno == ECHILD) {
                return false;
            }

            print_sys_error("waitpid failed in shouldWait");
            return true; // we assume that we should wait
        }

        if (ret > 0) {
            print_child_status(stat_loc, std::to_string(ret));
        }

        return true;
    }
}

bool register_event(const file_descriptor_wrapper &epfd,
                    const file_descriptor_wrapper &fd,
                    epoll_event ev) noexcept
{
    auto ret = ::epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
    if (ret == -1) {
        print_sys_error("Failed to add event to epoll");
        return false;
    }

    return true;
}

int lock(const file_descriptor_wrapper &fd, bool blocked) noexcept
{
    auto flag = (blocked) ? F_SETLKW : F_SETLK;
    struct flock fl{ static_cast<short>(flag), SEEK_SET, 0, 0, 0 };
    auto ret = fcntl(fd, F_SETLK, &fl);
    if (ret == -1) {
        return errno;
    }

    return 0;
}

int unlock(const file_descriptor_wrapper &fd) noexcept
{
    struct flock fl{ F_UNLCK, SEEK_SET, 0, 0, 0 };
    auto ret = fcntl(fd, F_SETLK, &fl);
    if (ret == -1) {
        return errno;
    }

    return 0;
}

bool overwrite_file(const file_descriptor_wrapper &fd, const std::string_view content) noexcept
{
    if (ftruncate(fd, 0) == -1) {
        print_sys_error("Failed to truncate file");
        return false;
    }

    if (lseek(fd, 0, SEEK_SET) == -1) {
        print_sys_error("Failed to seek to beginning of file");
        return false;
    }

    while (true) {
        auto written = ::write(fd, content.data(), content.size());
        if (written == -1) {
            if (errno == EINTR) {

                continue;
            }

            print_sys_error("Failed to write to file");
            return false;
        }

        break;
    }

    return true;
}

} // namespace

int main(int argc, char **argv) // NOLINT
{
    sigConf conf;
    if (!conf.block_signals()) {
        return -1;
    }

    auto lockFd = ::open(linglong::common::dir::containerLockPath, O_RDWR | O_CLOEXEC);
    if (lockFd == -1) {
        print_sys_error("Failed to open lock file");
        return -1;
    }

    const file_descriptor_wrapper containerLock(lockFd);
    if (auto ret = lock(containerLock, true); ret != 0) {
        print_sys_error(fmt::format("internal error: failed to lock container lock {} ", ret));
        return -1;
    }

    auto ret = ::prctl(PR_SET_CHILD_SUBREAPER, 1);
    if (ret == -1) {
        print_sys_error("Failed to set child subreaper");
        return -1;
    }

    auto args = parse_args(argc, argv);
    if (args.empty()) {
        print_info("No arguments provided");
        return -1;
    }

    auto child = run(args, conf);
    if (child == -1) {
        print_info("Failed to run child process");
        return -1;
    }
    print_info("run child " + std::to_string(child));

    auto epfd = create_epoll();
    if (!epfd) {
        return -1;
    }

    auto sigfd = create_signalfd(conf.current_sigset());
    if (!sigfd) {
        return -1;
    }

    const struct epoll_event ev{ .events = EPOLLIN | EPOLLET, .data = { .fd = sigfd } };
    if (!register_event(epfd, sigfd, ev)) {
        return -1;
    }

    bool done{ false };
    std::array<struct epoll_event, 4> events{};

    if (!overwrite_file(containerLock, "running")) {
        print_info("internal error: failed to update lock state");
        return -1;
    }

    if (auto ret = unlock(containerLock); ret != 0) {
        print_sys_error("internal error: failed to unlock lock file {}", ret);
        return -1;
    }

    while (true) {
        ret = ::epoll_wait(epfd, events.data(), events.size(), -1);
        if (ret == -1) {
            if (errno == EINTR) {
                continue;
            }

            print_sys_error("Failed to wait for events");
            return -1;
        }

        for (auto i = 0; i < ret; ++i) {
            const auto event = events.at(i);
            if (event.data.fd == sigfd) {
                if (!handle_sigevent(sigfd, child)) {
                    return -1;
                }

                if (!shouldWait()) {
                    done = true;
                    break;
                }

                continue;
            }
        }

        if (done) {
            auto ret = lock(containerLock, false);
            if (ret != 0) {
                done = false;
                if (ret != EAGAIN && ret != EACCES) {
                    print_sys_error("internal error: failed to lock container lock {}", ret);
                }

                continue;
            }

            if (!overwrite_file(containerLock, "quitting")) {
                print_info("internal error: failed to update lock state");
            }

            ret = unlock(containerLock);
            if (ret != 0) {
                print_sys_error("internal error: failed to unlock container lock {}", ret);
            }

            break;
        }
    }

    return 0;
}
