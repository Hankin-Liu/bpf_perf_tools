#pragma once

#define pkg_type_offset_for_begin 1
#define pkg_type_t_begin uint32_t
#define pkg_type_value_for_begin 10
#define pkg_type_offset_for_end 1
#define pkg_type_t_end uint32_t
#define pkg_type_value_for_end 10
#define dst_port_for_begin 10000
#define dst_ip_for_begin "232.0.0.1"
#define src_port_for_begin 0
#define src_ip_for_begin 0
#define dst_port_for_end 10000
#define dst_ip_for_end "232.0.0.1"
#define src_port_for_end 0
#define src_ip_for_end 0
#define match_arg1_offset_for_begin 1
#define match_arg2_offset_for_begin 1
#define match_arg3_offset_for_begin 1
#define match_arg1_offset_for_end 1
#define match_arg2_offset_for_end 1
#define match_arg3_offset_for_end 1
#define arg1_type uint64_t
#define arg2_type uint32_t
#define arg3_type uint32_t

const uint16_t UNSET_PORT = 0;
const uint32_t UNSET_IP = 0;
const uint8_t DIRECTION_BEGIN = 0;
const uint8_t DIRECTION_END = 1;

// user defined data
struct user_data
{
    bool operator < (const user_data& other) const {
        return data_1 < other.data_1
            || (data_1 == other.data_1 && data_2 < other.data_2)
            || (data_1 == other.data_1 && data_2 == other.data_2 && data_3 < other.data_3);
    }

    char* to_str()
    {
        static char buffer[32];
        snprintf(buffer, sizeof(buffer), "%ju, %u, %u", data_1, data_2, data_3);
        return buffer;
    }

    void set_user_data_for_begin(char* user_data)
    {
        data_1 = *(arg1_type*)(user_data + match_arg1_offset_for_begin);
        data_2 = *(arg2_type*)(user_data + match_arg2_offset_for_begin);
        data_3 = *(arg3_type*)(user_data + match_arg3_offset_for_begin);
    }

    void set_user_data_for_end(char* user_data)
    {
        data_1 = *(arg1_type*)(user_data + match_arg1_offset_for_end);
        data_2 = *(arg2_type*)(user_data + match_arg2_offset_for_end);
        data_3 = *(arg3_type*)(user_data + match_arg3_offset_for_end);
    }

    arg1_type data_1{ 0 };
    arg2_type data_2{ 0 };
    arg3_type data_3{ 0 };
};

struct user_header
{
    struct timeval ts{};
    struct user_data data{};
    uint8_t direction{ 0 }; // 0 - begin, 1 - end
};

