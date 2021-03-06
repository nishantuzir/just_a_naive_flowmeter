#!/usr/bin/env python
import json
import os
import pandas as pd
import numpy as np
from scipy.stats import kurtosis,skew,hmean
from scipy.stats.mstats import gmean
import time
from datetime import datetime

def generate_flows(pcap_file_path,time_out):
    print("creating json...")
    os.system('tshark -2 -R "ssl" -r '+pcap_file_path+' -T json >'+pcap_file_path.rsplit('.pcap')[0] + '.json')
    print("json created...")
    with open(pcap_file_path.rsplit('.pcap')[0] + '.json','r') as f:
        raw_data = json.load(f)
    
    ips = []
    for p in range(len(raw_data)):
        if 'ip' in raw_data[p]['_source']['layers']:
            if 'ip.src' in raw_data[p]['_source']['layers']['ip']:
                lengths = raw_data[p]['_source']['layers']['ip']['ip.src']
                if lengths in ips:
                    continue
                ips.append(lengths)
    
    #time_out = 1.0
    time_queue = []
    src = 0
    dst = src + 1
    for src in range(0,len(ips)-1):
        for dst in range(src+1,len(ips)):
            count1 = 0
            count2 = 0
            packet_length1 = []
            packet_length2 = []
            for packet in range(len(raw_data)):
                if 'ip' in raw_data[packet]['_source']['layers']:
                    if 'ip.src' in raw_data[packet]['_source']['layers']['ip']:
                        #if float(raw_data[packet]['_source']['layers']['frame']['frame.time_delta']) <= time_out:
                        
                        t2 = raw_data[packet]['_source']['layers']['frame']['frame.time'].rstrip(' IST')
                        t2 = datetime.strptime(t2, '%b  %d, %Y %H:%M:%S.%f000')
                        t2 = time.mktime(t2.timetuple())
                        #time_queue.append(t2)
                        if len(time_queue) != 0:
                            t1 = time_queue[0]
                            time_delta = t2 - t1
                            if time_delta <= time_out:
                                if raw_data[packet]['_source']['layers']['ip']['ip.src'] == ips[src] and raw_data[packet]['_source']['layers']['ip']['ip.dst'] == ips[dst] or raw_data[packet]['_source']['layers']['ip']['ip.src'] == ips[dst] and raw_data[packet]['_source']['layers']['ip']['ip.dst'] == ips[src]:
                                    count1 +=1
                                    src_port = raw_data[packet]['_source']['layers']['tcp']['tcp.srcport']
                                    dst_port = raw_data[packet]['_source']['layers']['tcp']['tcp.dstport']
                                    if 'ssl' in raw_data[packet]['_source']['layers']:
                                        if 'ssl.record' in raw_data[packet]['_source']['layers']['ssl']:
                                            if 'ssl.record.length' in raw_data[packet]['_source']['layers']['ssl']['ssl.record']:
                                                packet_length1.append(int(raw_data[packet]['_source']['layers']['ssl']['ssl.record']['ssl.record.length']))
                                time_queue.pop()
                                time_queue.append(t2)
                            else:    
                                if raw_data[packet]['_source']['layers']['ip']['ip.src'] == ips[src] and raw_data[packet]['_source']['layers']['ip']['ip.dst'] == ips[dst] or raw_data[packet]['_source']['layers']['ip']['ip.src'] == ips[dst] and raw_data[packet]['_source']['layers']['ip']['ip.dst'] == ips[src]:
                                    count2 +=1
                                    src_port = raw_data[packet]['_source']['layers']['tcp']['tcp.srcport']
                                    dst_port = raw_data[packet]['_source']['layers']['tcp']['tcp.dstport']
                                    if 'ssl' in raw_data[packet]['_source']['layers']:
                                        if 'ssl.record' in raw_data[packet]['_source']['layers']['ssl']:
                                            if 'ssl.record.length' in raw_data[packet]['_source']['layers']['ssl']['ssl.record']:
                                                packet_length2.append(int(raw_data[packet]['_source']['layers']['ssl']['ssl.record']['ssl.record.length']))

                        else:
                            if raw_data[packet]['_source']['layers']['ip']['ip.src'] == ips[src] and raw_data[packet]['_source']['layers']['ip']['ip.dst'] == ips[dst] or raw_data[packet]['_source']['layers']['ip']['ip.src'] == ips[dst] and raw_data[packet]['_source']['layers']['ip']['ip.dst'] == ips[src]:
                                    count1 +=1
                                    src_port = raw_data[packet]['_source']['layers']['tcp']['tcp.srcport']
                                    dst_port = raw_data[packet]['_source']['layers']['tcp']['tcp.dstport']
                                    if 'ssl' in raw_data[packet]['_source']['layers']:
                                        if 'ssl.record' in raw_data[packet]['_source']['layers']['ssl']:
                                            if 'ssl.record.length' in raw_data[packet]['_source']['layers']['ssl']['ssl.record']:
                                                packet_length1.append(int(raw_data[packet]['_source']['layers']['ssl']['ssl.record']['ssl.record.length']))
                            time_queue.append(t2)    
        
            if count1 != 0 and packet_length1 != []:
                with open(pcap_file_path.rsplit('.pcap')[0] + '.txt','a') as f:
                    f.write('{0}\t{1}\t{2}\t{3}\t{4}\t{5}\t{6:0.3f}\t{7:0.3f}\t{8:0.3f}\t{9:0.3f}\t{10:0.3f}\t{11:0.3f}\n'.format(ips[src],ips[dst],src_port,dst_port,count1,packet_length1,np.mean(packet_length1),np.std(packet_length1),kurtosis(packet_length1),skew(packet_length1),hmean(packet_length1),gmean(packet_length1)))
            if count2 != 0 and packet_length2 != []:
                with open(pcap_file_path.rsplit('.pcap')[0] + '.txt','a') as f:
                    f.write('{0}\t{1}\t{2}\t{3}\t{4}\t{5}\t{6:0.3f}\t{7:0.3f}\t{8:0.3f}\t{9:0.3f}\t{10:0.3f}\t{11:0.3f}\n'.format(ips[src],ips[dst],src_port,dst_port,count2,packet_length2,np.mean(packet_length2),np.std(packet_length2),kurtosis(packet_length2),skew(packet_length2),hmean(packet_length2),gmean(packet_length2)))
    
    os.remove(pcap_file_path.rsplit('.pcap')[0] + '.json')
    print('json cleanup done.')
    print('flow created')
    print('-----------------------')
              
if __name__ == "__main__":
    import sys
    import argparse
    parser = argparse.ArgumentParser(description='convert pcap file to flows')
    parser.add_argument('-p', '--pcap', default=None, help='specify the pcap file you want to process')
    parser.add_argument('-t', '--time_out', default=10.0, type=float, help='time out time in seconds')
    args = parser.parse_args()
    if args.pcap:
        generate_flows(args.pcap, args.time_out)
    else:
        parser.print_help()
    
