# bpf_perf_tools
bpf performance tools

Useful tools for observing program performance.
1. func_latency  
   Calculate latency for functions. Support to fetch arguments and stacks. Support to output a histogram.
2. off_cpu  
   Capture off cpu event. Support to fetch stacks.  
3. func_args  
   Fetch function arguments.  
4. cpu_cache_stat  
   Sumarize cpu cache miss.  
5. net_latency
   Sumarize latency of kernel network stack.
6. rtt_trace_c
   Calculate rtt, currently, only support calculate rtt for udp package.

## Dependencies
1. python2/3
2. python2/3-bcc

## Supported OS
1. Redhat 8+  
2. Fedora release 34 (Thirty Four)  
3. Kylin V10
      from bcc import BPF  ==> from bpfcc import BPF

Other OS will test later
