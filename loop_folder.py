#!/usr/bin/env python
from janf import *
import os
from pathlib import Path
def loop_through_folder(directory,time_out):
    pathlist = Path(directory).glob('**/*.pcap')
    for path in pathlist:
        path_in_str = str(path)
        print('working on {}'.format(path_in_str))
        generate_flows(path_in_str,time_out)
    

if __name__ == "__main__":
    import sys
    import argparse
    parser = argparse.ArgumentParser(description='convert pcap file to flows')
    parser.add_argument('-p', '--pcap', default=None, help='specify the pcap file you want to process')
    parser.add_argument('-f', '--folder', default=None, help='specify the folder you want to loop through')
    parser.add_argument('-t', '--time_out', default=10, type=float, help='time out time in seconds')
    args = parser.parse_args()
    if args.pcap:
        generate_flows(args.pcap, args.time_out)
    elif args.folder:
    	loop_through_folder(args.folder, args.time_out)
    else:
        parser.print_help()
    