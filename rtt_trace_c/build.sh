#!/bin/bash
build_type="D"
if [ $# -gt 0 ];then
    build_type=$1
fi

chmod u+x configure
./configure

if [[ $build_type == "R" ]];then
    echo "compile release version"
    g++ rtt_trace.cpp -o rtt_trace -std=c++11 -g -lpcap -lpthread -O2
else
    echo "compile debug version"
    g++ rtt_trace.cpp -o rtt_trace -std=c++11 -g -lpcap -lpthread -O0
fi
