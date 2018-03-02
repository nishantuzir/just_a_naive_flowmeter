
DESCRIPTION:
------------
This is a simple tool to create a flow from a pcap file. To be specific, it takes in 'ssl' packets and converts them into flows. It does not employ the conventional(and more efficient) procedure of parsing a pcap file to create the flows. Instead, it converts the pcap file to a json file and does json parsing in order to create the flows, based on a given timeout.

OUTPUT FORMAT:
--------------
<IP1><IP2><port1><port2><total ssl packets exchanged between IP1 and IP2><list of lengths of the encrypted payload of the individual packets exchanged><mean of encrypted packet lengths><standard deviation of encrypted packet length><kurtosis of encrypted packet lengths><skewness of encrypted packet lengths><harmonic mean of encrypted packet length>

172.20.10.3	216.58.220.35	34684	443	41	[137, 41, 2885, 2885, 2885, 2885, 2885, 41, 1320, 113, 121, 176, 41, 41, 97, 2885, 2885, 2885, 2885, 2885, 2157, 2885, 2885, 2885, 2885, 2885, 2157, 2885, 2885, 2885, 2885, 2885, 2157, 1673, 71, 259, 50, 41, 41]	1754.718	1291.517	-1.701	-0.426	166.404

PS: Each value is tab separated

USAGE:
------
$ python3 ./janf.py -p ./sample/testing.pcap -t 1.00

if you need help, the following command would be useful:
$ ./janf.py -h

DEPENDENCY:
-----------
python3.x
tshark 2.4.x
