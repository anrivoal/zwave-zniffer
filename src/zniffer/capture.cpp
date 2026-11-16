// SPDX-License-Identifier: BSD-3-Clause
#include "zniffer/capture.hpp"
#include "zniffer/radio.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

namespace zw::zniffer {
namespace {

std::uint64_t now_dotnet_binary() {
    using namespace std::chrono;
    constexpr std::uint64_t epoch_ticks = 621355968000000000ULL;
    const auto since_epoch = duration_cast<nanoseconds>(system_clock::now().time_since_epoch()).count();
    return 0x8000000000000000ULL | (epoch_ticks + static_cast<std::uint64_t>(since_epoch / 100));
}

int connect_socket(const std::string& host, std::uint16_t port, std::atomic<bool>& stop_requested,
                   std::string& error) {
    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    addrinfo* addresses = nullptr;
    const auto service = std::to_string(port);
    const auto status = getaddrinfo(host.c_str(), service.c_str(), &hints, &addresses);
    if (status != 0) { error = gai_strerror(status); return -1; }
    int connected = -1;
    for (auto* addr = addresses; addr && !stop_requested; addr = addr->ai_next) {
        const int fd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (fd < 0) continue;
        const int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            error = std::strerror(errno);
            close(fd);
            continue;
        }
        const auto result = connect(fd, addr->ai_addr, addr->ai_addrlen);
        if (result == 0 || errno == EINPROGRESS) {
            pollfd candidate{fd, POLLOUT, 0};
            for (int attempts = 0; attempts < 50 && !stop_requested; ++attempts) {
                const auto ready = ::poll(&candidate, 1, 100);
                if (ready < 0 && errno == EINTR) continue;
                if (ready <= 0) continue;
                int socket_error = 0;
                socklen_t len = sizeof(socket_error);
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &len);
                if (socket_error == 0) connected = fd;
                else error = std::strerror(socket_error);
                break;
            }
        } else error = std::strerror(errno);
        if (connected >= 0) break;
        close(fd);
    }
    freeaddrinfo(addresses);
    if (connected < 0 && error.empty()) error = "connection timed out";
    return connected;
}

} // namespace

TcpPtiCapture::TcpPtiCapture(std::string host, std::uint16_t port)
    : host_(std::move(host)), port_(port) {}

TcpPtiCapture::~TcpPtiCapture() { stop(); }

void TcpPtiCapture::start() { worker_ = std::thread(&TcpPtiCapture::run, this); }

void TcpPtiCapture::stop() {
    stop_requested_ = true;
    const int fd = socket_.load();
    if (fd >= 0) shutdown(fd, SHUT_RDWR);
    if (worker_.joinable()) worker_.join();
}

SerialCapture::SerialCapture(std::string device, int baud, bool start_v4)
    : device_(std::move(device)), baud_(baud), start_v4_(start_v4) {}

SerialCapture::~SerialCapture() { stop(); }

void SerialCapture::start() { worker_ = std::thread(&SerialCapture::run, this); }

void SerialCapture::stop() {
    stop_requested_ = true;
    if (worker_.joinable()) worker_.join();
}

void SerialCapture::set_status(std::string status, std::string error) {
    std::lock_guard lock(mutex_);
    status_ = std::move(status);
    error_ = std::move(error);
}

CaptureSnapshot SerialCapture::poll() {
    std::lock_guard lock(mutex_);
    CaptureSnapshot snapshot;
    snapshot.status = status_;
    snapshot.error = error_;
    const auto count = std::min<std::size_t>(queue_.size(), 256);
    snapshot.records.assign(std::make_move_iterator(queue_.begin()),
                            std::make_move_iterator(queue_.begin() + count));
    queue_.erase(queue_.begin(), queue_.begin() + count);
    snapshot.pending = !queue_.empty();
    return snapshot;
}

void SerialCapture::run() {
    const int fd = open(device_.c_str(), O_RDWR | O_NOCTTY | O_NONBLOCK | O_NOFOLLOW);
    if (fd < 0) { set_status("error", std::strerror(errno)); return; }
    struct stat info{};
    if (fstat(fd, &info) != 0 || !S_ISCHR(info.st_mode)) {
        set_status("error", "serial path is not a character device");
        close(fd);
        return;
    }
    termios settings{};
    const auto speed = baud_ == 230400 ? B230400 : B115200;
    if (tcgetattr(fd, &settings) != 0) {
        set_status("error", std::strerror(errno));
        close(fd);
        return;
    }
    cfmakeraw(&settings);
    settings.c_cflag |= CLOCAL | CREAD;
    settings.c_cflag &= ~CRTSCTS;
    cfsetispeed(&settings, speed);
    cfsetospeed(&settings, speed);
    if (tcsetattr(fd, TCSANOW, &settings) != 0) {
        set_status("error", std::strerror(errno));
        close(fd);
        return;
    }
    if (start_v4_) {
        // Match the C# 4.x command framing: SOF, command, zero payload length.
        constexpr std::uint8_t stop_cmd[]{0x23, 0x05, 0x00};
        constexpr std::uint8_t version_cmd[]{0x23, 0x01, 0x00};
        constexpr std::uint8_t start_cmd[]{0x23, 0x04, 0x00};
        for (const auto* cmd : {stop_cmd, version_cmd, start_cmd}) {
            if (write(fd, cmd, 3) != 3) {
                set_status("error", "failed to initialize Zniffer 4.x");
                close(fd);
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    set_status("capturing");
    std::uint8_t buffer[4096];
    std::string error;
    while (!stop_requested_) {
        pollfd candidate{fd, POLLIN, 0};
        const auto ready = ::poll(&candidate, 1, 250);
        if (ready == 0 || (ready < 0 && errno == EINTR)) continue;
        if (ready < 0) { error = std::strerror(errno); break; }
        if (candidate.revents & (POLLHUP | POLLNVAL)) { error = "serial device disconnected"; break; }
        const auto n = read(fd, buffer, sizeof(buffer));
        if (n < 0 && (errno == EAGAIN || errno == EINTR)) continue;
        if (n < 0) { error = std::strerror(errno); break; }
        if (n == 0) continue;
        zlf::Record record;
        record.datetime_binary = now_dotnet_binary();
        record.session_id = 1;
        record.api_type = static_cast<std::uint8_t>(zlf::ApiType::zniffer);
        record.eod = static_cast<std::uint8_t>(0xfe - record.api_type);
        record.data.assign(buffer, buffer + n);
        std::lock_guard lock(mutex_);
        if (queue_.size() >= 2048) {
            error_ = "capture buffer is full; browser must drain frames";
            status_ = "error";
            stop_requested_ = true;
            break;
        }
        queue_.push_back(std::move(record));
    }
    if (start_v4_) {
        constexpr std::uint8_t stop_cmd[]{0x23, 0x05, 0x00};
        (void)write(fd, stop_cmd, sizeof(stop_cmd));
    }
    close(fd);
    if (stop_requested_) {
        std::lock_guard lock(mutex_);
        if (status_ != "error") status_ = "stopped";
    } else set_status("error", error);
}

void TcpPtiCapture::set_status(std::string status, std::string error) {
    std::lock_guard lock(mutex_);
    status_ = std::move(status);
    error_ = std::move(error);
}

CaptureSnapshot TcpPtiCapture::poll() {
    std::lock_guard lock(mutex_);
    CaptureSnapshot snapshot;
    snapshot.status = status_;
    snapshot.error = error_;
    const auto count = std::min<std::size_t>(queue_.size(), 256);
    snapshot.records.assign(std::make_move_iterator(queue_.begin()),
                            std::make_move_iterator(queue_.begin() + count));
    queue_.erase(queue_.begin(), queue_.begin() + count);
    snapshot.pending = !queue_.empty();
    return snapshot;
}

void TcpPtiCapture::emit(std::span<const std::uint8_t> bytes) {
    zlf::Record record;
    record.datetime_binary = now_dotnet_binary();
    record.session_id = 1;
    record.api_type = static_cast<std::uint8_t>(zlf::ApiType::pti);
    record.data.assign(bytes.begin(), bytes.end());
    if (const auto decoded = decode_pti(record); decoded.empty() || !decoded[0].issue.empty())
        record.api_type = static_cast<std::uint8_t>(zlf::ApiType::pti_diagnostic);
    record.eod = static_cast<std::uint8_t>(0xfe - record.api_type);
    std::lock_guard lock(mutex_);
    if (queue_.size() >= 2048) {
        error_ = "capture buffer is full; browser must drain frames";
        status_ = "error";
        stop_requested_ = true;
        return;
    }
    queue_.push_back(std::move(record));
}

void TcpPtiCapture::run() {
    std::string error;
    const int fd = connect_socket(host_, port_, stop_requested_, error);
    if (fd < 0) {
        if (!stop_requested_) set_status("error", error);
        return;
    }
    socket_ = fd;
    set_status("capturing");
    std::vector<std::uint8_t> pending;
    std::uint8_t buffer[8192];
    while (!stop_requested_) {
        pollfd candidate{fd, POLLIN, 0};
        const auto ready = ::poll(&candidate, 1, 500);
        if (ready == 0) continue;
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) { error = std::strerror(errno); break; }
        const auto n = recv(fd, buffer, sizeof(buffer), 0);
        if (n == 0) { error = "device closed connection"; break; }
        if (n < 0 && (errno == EAGAIN || errno == EINTR)) continue;
        if (n < 0) { error = std::strerror(errno); break; }
        pending.insert(pending.end(), buffer, buffer + n);
        std::size_t consumed = 0;
        while (pending.size() - consumed >= 4) {
            if (pending[consumed] != 0x5b) { ++consumed; continue; }
            const auto length = static_cast<std::size_t>(pending[consumed + 1] |
                (pending[consumed + 2] << 8)) + 2;
            if (length < 5 || length > 65536) { ++consumed; continue; }
            if (pending.size() - consumed < length) break;
            emit(std::span<const std::uint8_t>(pending).subspan(consumed, length));
            consumed += length;
            if (stop_requested_) break;
        }
        if (consumed) pending.erase(pending.begin(), pending.begin() + consumed);
        if (pending.size() > 65536) { error = "invalid DCH stream framing"; break; }
    }
    close(fd);
    socket_ = -1;
    if (stop_requested_) {
        std::lock_guard lock(mutex_);
        if (status_ != "error") status_ = "stopped";
    } else set_status("error", error);
}

} // namespace zw::zniffer
