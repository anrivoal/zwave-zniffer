// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include "zniffer/zlf.hpp"

#include <atomic>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace zw::zniffer {

struct CaptureSnapshot {
    std::string status;
    std::string error;
    std::vector<zlf::Record> records;
    bool pending{};
};

class TcpPtiCapture {
public:
    TcpPtiCapture(std::string host, std::uint16_t port);
    ~TcpPtiCapture();
    TcpPtiCapture(const TcpPtiCapture&) = delete;
    TcpPtiCapture& operator=(const TcpPtiCapture&) = delete;
    void start();
    void stop();
    CaptureSnapshot poll();

private:
    void run();
    void emit(std::span<const std::uint8_t> bytes);
    void set_status(std::string status, std::string error = {});
    std::string host_;
    std::uint16_t port_;
    std::mutex mutex_;
    std::string status_ = "connecting";
    std::string error_;
    std::deque<zlf::Record> queue_;
    std::thread worker_;
    std::atomic<bool> stop_requested_{};
    std::atomic<int> socket_{-1};
};

class SerialCapture {
public:
    SerialCapture(std::string device, int baud, bool start_v4);
    ~SerialCapture();
    SerialCapture(const SerialCapture&) = delete;
    SerialCapture& operator=(const SerialCapture&) = delete;
    void start();
    void stop();
    CaptureSnapshot poll();

private:
    void run();
    void set_status(std::string status, std::string error = {});
    std::string device_;
    int baud_;
    bool start_v4_;
    std::mutex mutex_;
    std::string status_ = "connecting";
    std::string error_;
    std::deque<zlf::Record> queue_;
    std::thread worker_;
    std::atomic<bool> stop_requested_{};
};

} // namespace zw::zniffer
