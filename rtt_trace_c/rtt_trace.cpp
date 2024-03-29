/***************************************************************
 * rtt_trace.cpp - Main logic of tracing rtt
 *
 * Platform: linux
 *
 * Copyright (c) 2023 Hankin.
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * 11-Dec-2023   Hankin       Created this.
 ****************************************************************/
#include <iostream>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <cstring>
#include <deque>
#include <vector>
#include <thread>
#include <memory>
#include <mutex>
#include <sstream>
#include <map>
#include <chrono>
#include <signal.h>
#include "user_header.h"

struct user_header
{
    struct timeval ts{};
    struct user_data data{};
    uint8_t direction{ 0 }; // 0 - begin, 1 - end
};

std::mutex mtx;
std::deque<std::shared_ptr<std::vector<user_header>>> shared_data;
std::deque<std::shared_ptr<std::vector<user_header>>> pool;

static uint32_t dst_ip_begin = 0;
static uint32_t src_ip_begin = 0;
static uint32_t dst_ip_end = 0;
static uint32_t src_ip_end = 0;

const uint32_t MAX_DATA_PER_BATCH = 10000;
std::map<user_data, struct timeval> rtt_map;
pthread_t catch_thread_id;
pthread_t calculate_thread_id;

const uint16_t UNSET_PORT = 0;
const uint32_t UNSET_IP = 0;
const uint8_t DIRECTION_BEGIN = 0;
const uint8_t DIRECTION_END = 1;

static char* transfer_time(const struct timeval& tv)
{
    static char buffer[27];
    struct tm* tm_info = localtime(&tv.tv_sec);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d_%H:%M:%S", tm_info);
    snprintf(buffer + 19, 7, ".%06ld", tv.tv_usec);
    return buffer;
}

static std::shared_ptr<std::vector<user_header>> get_vector()
{
    if (pool.empty()) {
        auto ptr = std::make_shared<std::vector<user_header>>();
        ptr->reserve(MAX_DATA_PER_BATCH);
        return ptr;
    }
    auto ptr = pool.front();
    pool.pop_front();
    return ptr;
}
std::shared_ptr<std::vector<user_header>> cur_ptr = get_vector();
bool is_cur_ptr_in_use = false; // used in signal handler to determine if cur_ptr is in used

static std::string get_filter()
{
    std::stringstream custom_filter;
    custom_filter << "udp ";
    std::stringstream tmp_begin;
    if (dst_port_for_begin != UNSET_PORT) {
        tmp_begin << "dst port " << dst_port_for_begin << " ";
    }
    if (dst_ip_begin != UNSET_IP) {
        if (! tmp_begin.str().empty()) {
            tmp_begin << "and ";
        }
        tmp_begin << "dst host " << dst_ip_for_begin << " ";
    }
    if (src_port_for_begin != UNSET_IP) {
        if (! tmp_begin.str().empty()) {
            tmp_begin << "and ";
        }
        tmp_begin << "src port " << src_port_for_begin << " ";
    }
    if (src_ip_begin != UNSET_IP) {
        if (! tmp_begin.str().empty()) {
            tmp_begin << "and ";
        }
        tmp_begin << "src host " << src_ip_for_begin << " ";
    }

    std::stringstream tmp_end;
    if (dst_port_for_end != UNSET_PORT) {
        tmp_end << "dst port " << dst_port_for_end << " ";
    }
    if (dst_ip_end != UNSET_IP) {
        if (! tmp_end.str().empty()) {
            tmp_end << "and ";
        }
        tmp_end << "dst host " << dst_ip_for_end << " ";
    }
    if (src_port_for_end != UNSET_IP) {
        if (! tmp_end.str().empty()) {
            tmp_end << "and ";
        }
        tmp_end << "src port " << src_port_for_end << " ";
    }
    if (src_ip_end != UNSET_IP) {
        if (! tmp_end.str().empty()) {
            tmp_end << "and ";
        }
        tmp_end << "src host " << src_ip_for_end << " ";
    }

    if (! tmp_begin.str().empty() && ! tmp_end.str().empty()) {
        custom_filter << "and ((" << tmp_begin.str() << ") or (" << tmp_end.str() << "))";
    } else if (! tmp_begin.str().empty()) {
        custom_filter << "and (" << tmp_begin.str() << ")";
    } else if (! tmp_end.str().empty()) {
        custom_filter << "and (" << tmp_end.str() << ")";
    }
    return custom_filter.str();
}

static void init_ip()
{
    if (dst_ip_for_begin)
        dst_ip_begin = inet_addr(dst_ip_for_begin);
    if (src_ip_for_begin)
        src_ip_begin = inet_addr(src_ip_for_begin);
    if (dst_ip_for_end)
        dst_ip_end = inet_addr(dst_ip_for_end);
    if (src_ip_for_end)
        src_ip_end = inet_addr(src_ip_for_end);
}

static bool is_rtt_begin(struct iphdr* ip_hdr)
{
    struct udphdr* udp_hdr = (struct udphdr*)(ip_hdr + 1);
    if (dst_port_for_begin != UNSET_PORT && ntohs(udp_hdr->uh_dport) != dst_port_for_begin)
        return false;
    if (src_port_for_begin != UNSET_PORT && ntohs(udp_hdr->uh_sport) != src_port_for_begin)
        return false;
    if (dst_ip_begin != UNSET_IP && ip_hdr->daddr != dst_ip_begin)
        return false;
    if (src_ip_begin != UNSET_IP && ip_hdr->saddr != src_ip_begin)
        return false;
    return true;
}

static bool is_rtt_end(struct iphdr* ip_hdr)
{
    struct udphdr* udp_hdr = (struct udphdr*)(ip_hdr + 1);
    if (dst_port_for_end != UNSET_PORT && ntohs(udp_hdr->uh_dport) != dst_port_for_end)
        return false;
    if (src_port_for_end != UNSET_PORT && ntohs(udp_hdr->uh_sport) != src_port_for_end)
        return false;
    if (dst_ip_end != UNSET_IP && ip_hdr->daddr != dst_ip_end)
        return false;
    if (src_ip_end != UNSET_IP && ip_hdr->saddr != src_ip_end)
        return false;
    return true;
}

void pcap_callback(u_char* user, const struct pcap_pkthdr* packet_header, const u_char* packet_content) {
    struct iphdr* ip_hdr = (struct iphdr*)((char*)packet_content + sizeof(struct ether_header));
    char* user_data = (char*)(ip_hdr + 1) + sizeof(struct udphdr);
    struct user_header data{};
    data.ts = packet_header->ts;
    if (is_rtt_begin(ip_hdr)) {
        pkg_type_t_begin val = *(pkg_type_t_begin*)(user_data + pkg_type_offset_for_begin);
        if (val != pkg_type_value_for_begin) {
            return;
        }
        data.data.set_user_data_for_begin(user_data);
        data.direction = DIRECTION_BEGIN;
    } else if (is_rtt_end(ip_hdr)) {
        pkg_type_t_end val = *(pkg_type_t_end*)(user_data + pkg_type_offset_for_end);
        if (val != pkg_type_value_for_end) {
            return;
        }
        data.data.set_user_data_for_end(user_data);
        data.direction = DIRECTION_END;
    } else {
        return;
    }
    is_cur_ptr_in_use = true;
    cur_ptr->push_back(data);
    if (cur_ptr->size() >= MAX_DATA_PER_BATCH) {
        {
            std::lock_guard<std::mutex> lock(mtx);
            shared_data.push_back(cur_ptr);
            cur_ptr = get_vector();
        }
    }
    is_cur_ptr_in_use = false;
}

void sig_handler(int signo)
{
    // this handler is only triggered in catch_thread
    if (! is_cur_ptr_in_use) {
        if (mtx.try_lock()) {
            shared_data.push_back(cur_ptr);
            cur_ptr = get_vector();
            mtx.unlock();
        }
    }
}

void init_signal()
{
    struct sigaction act;
    act.sa_flags = 0;
    act.sa_handler = sig_handler;
    if (sigaction(SIGUSR1, &act, NULL) == -1) {
        std::cerr << "call sigaction failed" << std::endl;
        exit(-1);
    }
}

void* thread_catch_packets(void* handle1)
{
    pcap_t* handle = (pcap_t*)handle1;
    if (pcap_loop(handle, -1, pcap_callback, nullptr) == -1) {
        std::cerr << "catch package failed, " << pcap_geterr(handle)
            << std::endl;
        pcap_close(handle);
        return NULL;
    }
    pcap_close(handle);
    return NULL;
}

void* thread_calculate_rtt(void*)
{
    bool has_data = false;
    uint32_t idle_cnt = 0;
    constexpr uint32_t MAX_IDLE_CNT = 20;
    while (true) {
        std::atomic_thread_fence(std::memory_order_relaxed);
        if (shared_data.empty()) {
            ++idle_cnt;
            if (idle_cnt >= MAX_IDLE_CNT) {
                idle_cnt = 0;
                auto ret = pthread_kill(catch_thread_id, SIGUSR1);
                if (ret != 0) {
                    std::cerr << "pthread_kill failed" << std::endl;
                }
            } else {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            continue;
        }
        std::shared_ptr<std::vector<user_header>> tmp{ nullptr };
        {
            std::lock_guard<std::mutex> lock(mtx);
            tmp = shared_data.front();
            shared_data.pop_front();
        }
        idle_cnt = 0;
        //calculate rtt
        for (auto& u_h : *tmp) {
            if (u_h.direction == DIRECTION_BEGIN) {
                rtt_map[u_h.data] = u_h.ts;
            } else {
                auto iter = rtt_map.find(u_h.data);
                if (iter != rtt_map.end()) {
                    auto time_diff_s = u_h.ts.tv_sec - iter->second.tv_sec;
                    uint64_t time_diff_us = 0;
                    if (u_h.ts.tv_usec >= iter->second.tv_usec) {
                        time_diff_us = u_h.ts.tv_usec - iter->second.tv_usec;
                    } else {
                        if (time_diff_s > 0) {
                            --time_diff_s;
                            time_diff_us = u_h.ts.tv_usec + 1000000 - iter->second.tv_usec;
                        } else {
                            rtt_map.erase(iter);
                            continue;
                        }
                    }
                    if (time_diff_s >= RTT_THRESHOLD_S) {
                        if (time_diff_s == 0) {
                            if (time_diff_us < RTT_THRESHOLD_US) {
                                rtt_map.erase(iter);
                                continue;
                            }
                            printf("Time = [%-26s], rtt = [%uus], key = [%s]\n", transfer_time(iter->second),
                                   time_diff_us, u_h.data.to_str());
                        } else {
                            printf("Time = [%-26s], rtt = [%us%uus], key = [%s]\n", transfer_time(iter->second),
                                   time_diff_s, time_diff_us, u_h.data.to_str());
                        }
                    }
                    rtt_map.erase(iter);
                }
            }
        }

        tmp->clear();
        std::lock_guard<std::mutex> lock(mtx);
        pool.push_back(tmp);
    }
    return NULL;
}

int main()
{
    init_ip();
    init_signal();
    char err_buf[PCAP_ERRBUF_SIZE];
    int snaplen = 65535;
    int promisc = 1;
    int to_ms = 1;
    std::string filter = get_filter();
    std::cout << "Filter is [" << filter << "]" << std::endl;
    pcap_t* handle = pcap_open_live(DEV, snaplen, promisc, to_ms, err_buf);

    if (handle == nullptr) {
        std::cerr << "Could not create pcap handle: " << err_buf << std::endl;
        return -1;
    }

    if (! filter.empty()) {
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, filter.c_str(), 0, 0) == -1) {
            std::cerr << "Could not parse filter " << filter << ", " << pcap_geterr(handle)
                << std::endl;
            pcap_close(handle);
            return -1;
        }

        if (pcap_setfilter(handle, &fp) == -1) {
            std::cerr << "Could not install filter " << filter << ", " << pcap_geterr(handle)
                << std::endl;
            pcap_close(handle);
            return -1;
        }
    }

    auto ret = pthread_create(&catch_thread_id, NULL, &thread_catch_packets, handle);
    if (ret != 0) {
        std::cerr << "create thread for catching packets failed" << std::endl;
        return -1;
    }

    ret = pthread_create(&calculate_thread_id, NULL, &thread_calculate_rtt, NULL);
    if (ret != 0) {
        std::cerr << "create thread for calculate rtt failed" << std::endl;
        return -1;
    }

    ret = pthread_join(catch_thread_id, NULL);
    if (ret != 0) {
        std::cerr << "join thread for catching packets failed" << std::endl;
        return -1;
    }

    ret = pthread_join(calculate_thread_id, NULL);
    if (ret != 0) {
        std::cerr << "join thread for calculate rtt failed" << std::endl;
        return -1;
    }

    return 0;
}

