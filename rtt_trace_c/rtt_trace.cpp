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
#include <map>
#include <chrono>
#include "user_header.h"

std::mutex mtx;
std::deque<std::shared_ptr<std::vector<user_header>>> shared_data;
std::deque<std::shared_ptr<std::vector<user_header>>> pool;

static uint32_t dst_ip_begin = 0;
static uint32_t src_ip_begin = 0;
static uint32_t dst_ip_end = 0;
static uint32_t src_ip_end = 0;

const uint32_t MAX_DATA_PER_BATCH = 10000;
const uint32_t RTT_THRESHOLD_S = 0;
const uint32_t RTT_THRESHOLD_uS = 1000;
std::map<user_data, struct timeval> rtt_map;

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
    //std::cout << "get udp package" << std::endl;
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
    cur_ptr->push_back(data);
    if (cur_ptr->size() >= MAX_DATA_PER_BATCH) {
        {
            std::lock_guard<std::mutex> lock(mtx);
            shared_data.push_back(cur_ptr);
            cur_ptr = get_vector();
        }
    }
}

void thread_catch_packets(pcap_t* handle)
{
    if (pcap_loop(handle, -1, pcap_callback, nullptr) == -1) {
        std::cerr << "catch package failed, " << pcap_geterr(handle)
            << std::endl;
        pcap_close(handle);
        return;
    }
    pcap_close(handle);
}

void thread_calculate_rtt()
{
    while (true) {
        std::atomic_thread_fence(std::memory_order_relaxed);
        if (shared_data.empty())
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        std::shared_ptr<std::vector<user_header>> tmp{ nullptr };
        {
            std::lock_guard<std::mutex> lock(mtx);
            tmp = shared_data.front();
            shared_data.pop_front();
        }
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
                            if (time_diff_us < RTT_THRESHOLD_uS) {
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
}

int main()
{
    init_ip();
    const char* dev = "eth0";
    char err_buf[PCAP_ERRBUF_SIZE];
    int snaplen = 65535;
    int promisc = 1;
    int to_ms = 1;
    const char* filter = "udp";
    pcap_t* handle = pcap_open_live(dev, snaplen, promisc, to_ms, err_buf);

    if (handle == nullptr) {
        std::cerr << "Could not create pcap handle: " << err_buf << std::endl;
        return -1;
    }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter, 0, 0) == -1) {
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

    std::thread catch_thread(thread_catch_packets, handle);
    std::thread calucate_thread(thread_calculate_rtt);

    catch_thread.join();
    calucate_thread.join();

    return 0;
}

