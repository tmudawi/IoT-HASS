##################################################################
#                                                                #
# IoT-HASS Service                                               #
# =====================================                          #
#                                                                #
# This is the main program for the IoT-HASS framework. It calls  #
# different engines to perform IDS/IPS, Privacy Monitoring and   # 
# Device Management. I also perform a logging for all traffic    #
# whether normal or attacks.                                     #
##################################################################

# Importing external custom modules
import ips_engine as ips
import privacy_monitoring_engine as pmv
import device_management_engine as dm

# Importing the libraries
import numpy as np
import pandas as pd
#from scapy.all import *
#from scapy.utils import hexdump
from multiprocessing import Process
import socket
import struct
import textwrap
import datetime
import os 
from datetime import timedelta
import statistics as stats

IPS = ips.IPS_Engine
DM = dm.DM_Engine
PMV = pmv.Privacy_Engine

# Function to format IP address as ipv4 
def format_ip_to_ipv4(addr):
    return '.'.join(map(str, addr))

# Function to extract the packet header information including source and target IPs
def ipv4_packet_header(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, format_ip_to_ipv4(src), format_ip_to_ipv4(target), data[header_length:]  

# Function to retuen properly formatted mac address     
def get_mac_address(bytes_addr):
    bytes_addr = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_addr).upper()

# Function to unpack tcp segment
def unpack_tcp_segment(data):
     (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
     offset = (offset_reserved_flags >> 12) * 4
     flag_urg = (offset_reserved_flags & 32) >> 5
     flag_ack = (offset_reserved_flags & 16) >> 4
     flag_psh = (offset_reserved_flags & 8) >> 3
     flag_rst = (offset_reserved_flags & 4) >> 2
     flag_syn = (offset_reserved_flags & 2) >> 1
     flag_fin = offset_reserved_flags & 1
     return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

# Function to unpack ethernet frame
def unpack_ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_address(dest_mac), get_mac_address(src_mac), socket.htons(proto), data[14:]            


# Function to start and run both IDS and Privacy engine simultanuosly by using Python threading
def iot_hass(mean_biat, std_biat, max_biat, pkt_len_varience, std_idle, src, target, classifier, dest_mac, src_mac, raw_data):
    print("IoT-HASS is Running Protecting Your Home Realtime Now!")
    # Call the IPS Engine
    p1 = Process(target = IPS.ips_engine(mean_biat, std_biat, max_biat, pkt_len_varience, std_idle, src, target, classifier))
    p1.start()
    
    # Call the privacy_protction_engine
    p2 = Process(target = PMV.privacy_monitoring_engine(dest_mac, src_mac, raw_data, src, target))
    p2.start()
    

def main():

    print("Validating Connected IoT Devices!")
    DM.dm_engine()
    
    DM.block_all_ips()
    
    # Importing the dataset
    dataset = pd.read_csv('/home/pi/Software/IoT-HASS/CICIDS2017_Sample.csv')

    X = dataset.iloc[:, :-1].values
    y = dataset.iloc[:, 78].values
    
    # Splitting the dataset into the Training set and Test set
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.20, random_state = 0)
    
    ############## Start of Feature Scaling ###################
    from sklearn.preprocessing import StandardScaler
    sc = StandardScaler()
    X_train = sc.fit_transform(X_train)
    X_test = sc.transform(X_test)
    
    # Fitting Decision Tree Classification to the Training set
    from sklearn.tree import DecisionTreeClassifier
    classifier = DecisionTreeClassifier(criterion = 'entropy', random_state = 0)
    classifier.fit(X_train, y_train)

    # Feature Selection
    from sklearn.feature_selection import SelectKBest, SelectPercentile, chi2

    KBestSelector = SelectKBest(k=5)
    KBestSelector = KBestSelector.fit(X_train, y_train)
    X_train_FS = KBestSelector.transform(X_train)

    names = dataset.iloc[:, :-1].columns.values[KBestSelector.get_support()]
    scores = KBestSelector.scores_[KBestSelector.get_support()]
    names_scores = list(zip(names, scores))
    ns_df = pd.DataFrame(data= names_scores, columns=['Feat_Name', 'F_Score'])
    ns_df_sorted = ns_df.sort_values(['F_Score', 'Feat_Name'])
    #print(ns_df_sorted)

    # Fit the model with the new reduced features
    classifier.fit(X_train_FS, y_train)

    # Predicting the Test set results
    X_test_FS = KBestSelector.transform(X_test)
    y_pred = classifier.predict(X_test_FS)

    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    
    # define array variables to hold time and statistics
    TimeBetBwdPkts = 0
    NumBwdPkts = 0
    NumIdleFlow = 0
    prev_fin_flag = 0
    flow_idle_start_time = datetime.datetime.now()
    flow_idle_end_time = datetime.datetime.now()
    AllTimesBetBwdPkts = []
    AllflowIdleTimes = []
    AllPacketLengths = []

    max_biat = 0
    mean_biat = 0
    std_biat = 0
    pkt_len_varience = 0
    std_idle = 0

    while True:
        raw_data, addr = conn.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = unpack_ethernet_frame(raw_data)

        # get packet length or size
        packet_length = len(raw_data)
        AllPacketLengths.append(packet_length)

        # IPv4
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet_header(data)
            
            # TCP packet
            if proto == 6:
                (src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = unpack_tcp_segment(data)

                # capture packet flow
                # we will identifiy each flow by determining when src and dst ip change

                # first capture the original src and dst IPs
                prev_src_ip = src
                prev_target_ip = target
                
                if flag_fin == '1' and prev_fin_flag == '0':
                    flow_idle_start_time = datetime.datetime.now()
                    NumIdleFlow = NumIdleFlow + 1
                elif flag_fin == '0' and prev_fin_flag == '1':
                    flow_idle_end_time = datetime.datetime.now()  
                else:
                    flow_idle_start_time = datetime.datetime.now()
                    flow_idle_end_time = datetime.datetime.now()

                prev_fin_flag = flag_fin
                
                flowIdleTime = (flow_idle_end_time - flow_idle_start_time).microseconds

                AllflowIdleTimes.append(flowIdleTime)                      

                LastTimeBwdPktSeen = datetime.datetime.now()

                if(NumBwdPkts == 1):
                    TimeBetBwdPkts = 0                    
                elif(NumBwdPkts > 1):
                    TimeBetBwdPkts = (datetime.datetime.now() - LastTimeBwdPktSeen).microseconds
                else:
                    TimeBetBwdPkts = 0
                    
                NumBwdPkts = NumBwdPkts + 1
                AllTimesBetBwdPkts.append(TimeBetBwdPkts)
                
            # get statistics values for backwards packets
            if sum(AllTimesBetBwdPkts) == 0:
                mean_biat = 0
                max_biat = 0
                std_biat = 0
            else:
                mean_biat = stats.mean(AllTimesBetBwdPkts)
                max_biat = max(AllTimesBetBwdPkts)
                std_biat = stats.stdev(AllTimesBetBwdPkts)

            if(sum(AllflowIdleTimes) > 0 and len(AllflowIdleTimes) > 1):
                std_idle = stats.stdev(AllflowIdleTimes)
                
            else:
                std_idle = 0
            
            if(sum(AllPacketLengths) > 0 and len(AllPacketLengths) > 1):                
                pkt_len_varience = stats.variance(AllPacketLengths)
            else:
                pkt_len_varience = 0
                
            # Invoking iot_hass() function
            iot_hass(mean_biat, std_biat, max_biat, pkt_len_varience, std_idle, src, target, classifier, dest_mac, src_mac, raw_data)
            

if __name__ =="__main__":
    main()
