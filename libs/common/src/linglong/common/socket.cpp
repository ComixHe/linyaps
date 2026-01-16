// SPDX-FileCopyrightText: 2026 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "linglong/common/socket.h"

#include <cstring>

#include <sys/socket.h>
#include <unistd.h>

namespace linglong::common::socket {

tl::expected<SocketData, std::string> recvFdWithPayload(int fd, std::size_t bufSize)
{
    if (fd < 0) {
        return tl::make_unexpected("Invalid file descriptor");
    }

    struct msghdr msg{};
    std::string payload_buffer(bufSize, '\0');

    struct iovec iov{};
    iov.iov_base = payload_buffer.data();
    iov.iov_len = payload_buffer.size();
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    std::array<std::byte, CMSG_SPACE(sizeof(int))> control_buf{};
    msg.msg_control = control_buf.data();
    msg.msg_controllen = control_buf.size();

    auto n = [&]() -> ssize_t {
        while (true) {
            auto ret = recvmsg(fd, &msg, 0);
            if (ret < 0) {
                if (errno == EINTR) {
                    continue;
                }

                return -1;
            }

            return ret;
        }
    }();

    if (n < 0) {
        return tl::make_unexpected(std::string{ "Failed to receive message" } + ::strerror(errno));
    }

    int received_fd{ -1 };
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

    if (cmsg == nullptr) {
        return tl::make_unexpected("Failed to receive data");
    }

    if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
        return tl::make_unexpected("Not ancillary data with file descriptor");
    }

    std::memcpy(&received_fd, CMSG_DATA(cmsg), sizeof(int));

    return SocketData{ received_fd, std::string(payload_buffer.data(), n) };
}

tl::expected<void, std::string> sendFdWithPayload(int socketFd, int fd, const std::string &payload)
{
    struct msghdr msg{};

    struct iovec iov{};
    iov.iov_base = const_cast<char *>(payload.data());
    iov.iov_len = payload.size();
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    alignas(struct cmsghdr) std::array<std::byte, CMSG_SPACE(sizeof(int))> control_buf{};

    msg.msg_control = control_buf.data();
    msg.msg_controllen = control_buf.size();

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));

    std::memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

    auto n = [&]() -> ssize_t {
        while (true) {
            auto ret = sendmsg(socketFd, &msg, 0);
            if (ret < 0) {
                if (errno == EINTR) {
                    continue;
                }

                return -1;
            }

            return ret;
        }
    }();

    if (n < 0) {
        return tl::make_unexpected("sendmsg failed: " + std::string(strerror(errno)));
    }

    if (static_cast<size_t>(n) < payload.size()) {
        return tl::make_unexpected("Partial write: payload not fully sent");
    }

    return {};
}

} // namespace linglong::common::socket
