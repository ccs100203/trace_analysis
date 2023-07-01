import pickle
import numpy as np
import pandas as pd
import random
import time
from datetime import datetime
import json
from collections import Counter
import os
import copy
import socket
import struct

####################################

# @upper_bound: the upper limit of returning filenames
def get_all_filenames(base='./data/caida', upper_bound=0):
    dir_list = [base]
    ret_ll = []

    cnt = 0

    # go through all directory on the `base`
    while dir_list:
        cur_dir = dir_list.pop(0)
        cur_list = os.listdir(cur_dir)
        # go through all directory on a directory
        for cur in cur_list:            
            path = cur_dir + '/' + cur
            # is a pcap file, run pcapParser
            if (os.path.isfile(path)):
                ret_ll.append(path)
                cnt += 1
            # isdirectory, push to list
            else:
                dir_list.append(path)
            # number of files processed is below the upper bound
            if upper_bound != 0 and cnt >= upper_bound:
                print(f'files count: {cnt}')
                return ret_ll
    print(f'files count: {cnt}')
    return ret_ll

####################################
# define ip address <--> int converting function
def ip2long(ip):
    """
    Convert an IP string to long
    """
    packedIP = socket.inet_aton(ip)
    return struct.unpack("!L", packedIP)[0]

def long2ip(val):
    return socket.inet_ntoa(struct.pack('!L', val))

####################################

# define class of distributions
# https://numpy.org/doc/1.16/reference/routines.random.html
# only same number  of total packets
class Distribution_isFixNumberofPacket:
    def __init__(self, dataframe, output_dir = './distributions/', output_filename = 'tmp', \
                 num_of_epoch = 2, flowkeys = ['srcip']):
        self.df = dataframe
        self.output_dir = output_dir
        self.output_filename = output_filename
        self.num_of_epoch = num_of_epoch
        self.flowkeys = flowkeys

        self.exp_counts_list = []
        self.name_list = []

        self.setup_dataframe()

    def setup_dataframe(self):
        self.total_num_of_pkt = len(df)
        self.total_num_of_flow = len(df.groupby(flowkeys).size())

        # # flowkey & packet size mapping
        # self.flowkey_to_pktsize = self.df.groupby(self.flowkeys).size()
        # # print(flowkey_to_pktsize)
        
        # # how many flowkeys
        # self.flowkeys_count = len(self.df.groupby(self.flowkeys).size())
        # # print('\nflowkeys_count:', flowkeys_count)

        # self.flowkeys_list = list(self.df.groupby(self.flowkeys).size().index)
        
        # values (packet size) of each flowkeys
        self.df_vals = self.df.groupby(self.flowkeys).size().values

        # set the max packet size of 1 flow
        self.threshold = int(np.max(self.df_vals) / self.num_of_epoch)
        print(f"max packet size (self.threshold): {self.threshold:,}")

        # num of flow in one epoch (sample_times)
        self.target_num_of_flow = int(self.total_num_of_flow / self.num_of_epoch)
        print(f'target number of flow (sample_times): {self.target_num_of_flow:,}')
        # num of packet in one epoch
        self.target_num_of_pkt = int(self.total_num_of_pkt / self.num_of_epoch)
        print(f'target number of packet: {self.target_num_of_pkt:,}')
    
    def add_zipf(self, zipf_alpha = 1.1):

        s = np.random.zipf(a=zipf_alpha, size=self.target_num_of_flow)
        # print('sum:', f'{s.sum():,}')
        cnt = 0
        tmp = []
        for idx, d in enumerate(s):
            # avoid 1 flowkey has too many packets (drop if too large)
            if d <= self.threshold:
                cnt += d
                tmp.append(d)
                if cnt > self.target_num_of_pkt:
                    print('flowkeys_cnt:', idx, f'total_packet_cnt: {cnt:,}')
                    break
        s = tmp

        bin_count = np.bincount(s)[1:]
        print(f'zipf-{zipf_alpha}:', bin_count[:10], f'{len(bin_count):,}')
        x = np.arange(1, len(bin_count) + 1)
        
        self.exp_counts_list.append(bin_count)
        self.name_list.append(f'zipf-{zipf_alpha}')

    def add_uniform(self, interval = 100):
        high_bound = (int)(self.threshold / interval)
        s = np.random.uniform(1, high_bound + 1, self.target_num_of_flow)
        s = s.astype(int)
        # print('sum:', f'{s.sum():,}')
        cnt = 0
        tmp = []

        for idx, d in enumerate(s):
            # sampling interval, e.g. 100, 200, 300....
            d *= interval
            # avoid 1 flowkey has too many packets (drop if too large)
            if d <= self.threshold:
                cnt += d
                tmp.append(d)
                if cnt > self.target_num_of_pkt:
                    print('flowkeys_cnt:', idx, f'total_packet_cnt: {cnt:,}')
                    break
        s = tmp

        bin_count = np.bincount(s)
        print('uniform:', bin_count[:10], f'{len(bin_count):,}')
        # a = plt.hist(s, density=True)
        x = np.arange(1, len(bin_count) + 1)

        self.exp_counts_list.append(bin_count)
        self.name_list.append(f'uniform-{interval}')
    
    def save_to_file(self):
        # create directory if it doesn't exist
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        tmp_key = self.flowkeys[0]
        if tmp_key == "srcip":
            tmp_key = "srcIP"

        for exp_count, dist_name in zip(self.exp_counts_list, self.name_list):
            filename = os.path.join(self.output_dir, self.output_filename + \
                                    '-' + dist_name + '-fixPkt-' + tmp_key)
            print(filename)
            
            with open(f'{filename}.txt', 'w') as file:
                file.write('\n'.join(str(exp) for exp in exp_count))

    def get_counts(self):
        return self.exp_counts_list
    
    def get_names(self):
        return self.name_list

####################################
# fix number of total flows and total packets
class Distribution_FixNumberofPacketFlows:
    def __init__(self, dataframe, output_dir = './distributions/', output_filename = 'tmp', \
                 num_of_epoch = 2, flowkeys = ['srcip']):
        self.df = dataframe
        self.output_dir = output_dir
        self.output_filename = output_filename
        self.num_of_epoch = num_of_epoch
        self.flowkeys = flowkeys

        self.exp_counts_list = []
        self.name_list = []

        self.setup_dataframe()
    
    def setup_dataframe(self):
        self.total_num_of_pkt = len(df)
        self.total_num_of_flow = len(df.groupby(flowkeys).size())

        # # flowkey & packet size mapping
        # self.flowkey_to_pktsize = self.df.groupby(self.flowkeys).size()
        # # print(flowkey_to_pktsize)
        
        # # how many flowkeys
        # self.flowkeys_count = len(self.df.groupby(self.flowkeys).size())
        # # print('\nflowkeys_count:', flowkeys_count)

        # self.flowkeys_list = list(self.df.groupby(self.flowkeys).size().index)
        
        # size of each flowkeys
        self.df_vals = self.df.groupby(self.flowkeys).size().values

        # set the max packet size of 1 flow
        self.threshold = int(np.max(self.df_vals) / self.num_of_epoch)
        print(f"max packet size (self.threshold): {self.threshold:,}")

        # num of flow in one epoch (sample_times)
        self.target_num_of_flow = int(self.total_num_of_flow / self.num_of_epoch)
        print(f'target number of flow (sample_times): {self.target_num_of_flow:,}')
        # num of packet in one epoch
        self.target_num_of_pkt = int(self.total_num_of_pkt / self.num_of_epoch)
        print(f'target number of packet: {self.target_num_of_pkt:,}')
    
    def add_zipf(self, zipf_alpha = 1.1):
        print(f'------add_zipf {zipf_alpha}------')
        
        # create zipf by given number of flows
        s = np.random.zipf(a=zipf_alpha, size=self.target_num_of_flow)
        # print('sum:', f'{s.sum():,}')
        cnt = 0
        tmp = []
        for d in s:
            # avoid 1 flow has too many packets (module if it's too large)
            val = d % self.threshold
            if val == 0:
                val = 1
            cnt += val
            tmp.append(val)
        print(f'total_num_of_pkt before ratio: {cnt:,}')

        # control the number of packets as same as original pcap
        ratio = cnt / self.target_num_of_pkt
        print(f'cnt / target_num_of_pkt ratio: {ratio}')
        tmp /= ratio
        tmp = tmp.astype(int)
        tmp += 1

        print(f'total_num_of_pkt after ratio: {sum(tmp):,}')
        print(f'max flow size: {max(tmp):,}')
        print(f'total_num_of_flow : {len(tmp):,}')
        
        s = tmp

        bin_count = np.bincount(s)[1:]
        print(f'zipf-{zipf_alpha}:', bin_count[:10], f'{len(bin_count):,}')
        # x = np.arange(1, len(bin_count) + 1)
        
        self.exp_counts_list.append(bin_count)
        self.name_list.append(f'zipf-{zipf_alpha}')

    def add_uniform(self):
        print(f'------add_uniform------')
        # calculate the high bound of uniform distribution
        high_bound = int(2 * self.target_num_of_pkt / self.target_num_of_flow)
        print(f'high_bound: {high_bound}')

        # create uniform by given number of flows & number of packets
        s = np.random.uniform(1, high_bound + 1, self.target_num_of_flow)
        s = s.astype(int)
        # print('sum:', f'{s.sum():,}')
        cnt = 0
        tmp = []

        for d in s:
            # avoid 1 flowkey has too many packets (drop if too large)
            if d <= self.threshold:
                cnt += d
                tmp.append(d)

        print(f'total_num_of_pkt: {cnt:,}')
        print(f'max flow size: {max(tmp):,}')
        print(f'total_num_of_flow : {len(tmp):,}')
        s = tmp

        bin_count = np.bincount(s)[1:]
        print('uniform:', bin_count[:10], f'{len(bin_count):,}')
        # a = plt.hist(s, density=True)
        x = np.arange(1, len(bin_count) + 1)

        self.exp_counts_list.append(bin_count)
        self.name_list.append(f'uniform')
    
    def save_to_file(self):
        # create directory if it doesn't exist
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        tmp_key = self.flowkeys[0]
        if tmp_key == "srcip":
            tmp_key = "srcIP"

        for exp_count, dist_name in zip(self.exp_counts_list, self.name_list):
            filename = os.path.join(self.output_dir, self.output_filename + \
                                    '-' + dist_name + '-fixFlowPkt-' + tmp_key)
            print(filename)
            
            with open(f'{filename}.txt', 'w') as file:
                file.write('\n'.join(str(exp) for exp in exp_count))

    def get_counts(self):
        return self.exp_counts_list
    
    def get_names(self):
        return self.name_list


####################################
# test different number of flows on given distributions
class Distribution_diff_NumberofFlow:
    def __init__(self, dataframe, output_dir = './distributions/', output_filename = 'tmp', \
                 num_of_epoch = 2, flowkeys = ['srcip']):
        self.df = dataframe
        self.output_dir = output_dir
        self.output_filename = output_filename
        self.num_of_epoch = num_of_epoch
        self.flowkeys = flowkeys

        self.exp_counts_list = []
        self.name_list = []

        self.setup_dataframe()
    
    def setup_dataframe(self):
        self.total_num_of_pkt = len(df)
        self.total_num_of_flow = len(df.groupby(flowkeys).size())
        
        # size of each flowkeys
        self.df_vals = self.df.groupby(self.flowkeys).size().values

        # set the max packet size of 1 flow
        self.threshold = int(np.max(self.df_vals) / self.num_of_epoch)
        print(f"max packet size (self.threshold): {self.threshold:,}")

        # num of flow in one epoch (sample_times)
        self.target_num_of_flow = int(self.total_num_of_flow / self.num_of_epoch)
        print(f'target number of flow (sample_times): {self.target_num_of_flow:,}')
        # num of packet in one epoch
        self.target_num_of_pkt = int(self.total_num_of_pkt / self.num_of_epoch)
        print(f'target number of packet: {self.target_num_of_pkt:,}')
    
    def add_zipf(self, zipf_alpha = 1.1):
        print(f'------add_zipf {zipf_alpha}------')
        # target_num_of_flow_list = [self.target_num_of_flow, \
        #                             int(self.target_num_of_flow/2), int(self.target_num_of_flow*2)]
        # filename_suffix_list = ['1x', '0.5x', '2x']
        target_num_of_flow_list = [int(self.target_num_of_flow * 0.1), \
                                    int(self.target_num_of_flow * 4), int(self.target_num_of_flow * 10)]
        filename_suffix_list = ['0.1x', '4x', '10x']
        for cur_target_num_of_flow, filename_suffix in zip(target_num_of_flow_list, filename_suffix_list):
            print(f'cur_target_num_of_flow: {cur_target_num_of_flow:,}')
        
            # create zipf by given number of flows
            s = np.random.zipf(a=zipf_alpha, size=cur_target_num_of_flow)
            # print('sum:', f'{s.sum():,}')
            cnt = 0
            tmp = []
            for d in s:
                # avoid 1 flow has too many packets (module if it's too large)
                val = d % self.threshold
                if val == 0:
                    val = 1
                cnt += val
                tmp.append(val)
            print(f'total_num_of_pkt before ratio: {cnt:,}')

            # control the number of packets as same as original pcap
            ratio = cnt / self.target_num_of_pkt
            print(f'cnt / target_num_of_pkt ratio: {ratio}')
            tmp /= ratio
            tmp = tmp.astype(int)
            tmp += 1

            print(f'total_num_of_pkt after ratio: {sum(tmp):,}')
            print(f'max flow size: {max(tmp):,}')
            print(f'total_num_of_flow : {len(tmp):,}')
            
            s = tmp

            bin_count = np.bincount(s)[1:]
            print(f'zipf-{zipf_alpha}:', bin_count[:10], f'{len(bin_count):,}')
            print()
            # x = np.arange(1, len(bin_count) + 1)
            
            self.exp_counts_list.append(bin_count)
            self.name_list.append(f'zipf-{zipf_alpha}-numberofFlow-{filename_suffix}')
    
    def save_to_file(self):
        # create directory if it doesn't exist
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        tmp_key = self.flowkeys[0]
        if tmp_key == "srcip":
            tmp_key = "srcIP"

        for exp_count, dist_name in zip(self.exp_counts_list, self.name_list):
            filename = os.path.join(self.output_dir, self.output_filename + '-' + \
                                    dist_name + '-' + tmp_key)
            print(filename)
            
            with open(f'{filename}.txt', 'w') as file:
                file.write('\n'.join(str(exp) for exp in exp_count))

    def get_counts(self):
        return self.exp_counts_list
    
    def get_names(self):
        return self.name_list

####################################
# test different number of Packets on given distributions
class Distribution_diff_NumberofPkt:
    def __init__(self, dataframe, output_dir = './distributions/', output_filename = 'tmp', \
                 num_of_epoch = 2, flowkeys = ['srcip']):
        self.df = dataframe
        self.output_dir = output_dir
        self.output_filename = output_filename
        self.num_of_epoch = num_of_epoch
        self.flowkeys = flowkeys

        self.exp_counts_list = []
        self.name_list = []

        self.setup_dataframe()
    
    def setup_dataframe(self):
        self.total_num_of_pkt = len(df)
        self.total_num_of_flow = len(df.groupby(flowkeys).size())
        
        # size of each flowkeys
        self.df_vals = self.df.groupby(self.flowkeys).size().values

        # set the max packet size of 1 flow
        self.threshold = int(np.max(self.df_vals) / self.num_of_epoch)
        print(f"max packet size (self.threshold): {self.threshold:,}")

        # num of flow in one epoch (sample_times)
        self.target_num_of_flow = int(self.total_num_of_flow / self.num_of_epoch)
        print(f'target number of flow (sample_times): {self.target_num_of_flow:,}')
        # num of packet in one epoch
        self.target_num_of_pkt = int(self.total_num_of_pkt / self.num_of_epoch)
        print(f'target number of packet: {self.target_num_of_pkt:,}')
    
    def add_zipf(self, zipf_alpha = 1.1):
        print(f'------add_zipf {zipf_alpha}------')
        target_num_of_pkt_list = [self.target_num_of_pkt, \
                                    int(self.target_num_of_pkt*0.3), int(self.target_num_of_pkt*0.6)]
        filename_suffix_list = ['1x', '0.3x', '0.6x']
        for cur_target_num_of_pkt, filename_suffix in zip(target_num_of_pkt_list, filename_suffix_list):
            print(f'cur_target_num_of_pkt: {cur_target_num_of_pkt:,}')
        
            # create zipf by given number of flows
            s = np.random.zipf(a=zipf_alpha, size=self.target_num_of_flow)
            # print('sum:', f'{s.sum():,}')
            cnt = 0
            tmp = []
            for d in s:
                # avoid 1 flow has too many packets (module if it's too large)
                val = d % self.threshold
                if val == 0:
                    val = 1
                cnt += val
                tmp.append(val)
            print(f'total_num_of_pkt before ratio: {cnt:,}')

            # control the number of packets as same as original pcap
            ratio = cnt / cur_target_num_of_pkt
            print(f'cnt / cur_target_num_of_pkt ratio: {ratio}')
            tmp /= ratio
            tmp = tmp.astype(int)
            tmp += 1

            print(f'total_num_of_pkt after ratio: {sum(tmp):,}')
            print(f'max flow size: {max(tmp):,}')
            print(f'total_num_of_flow : {len(tmp):,}')
            
            s = tmp

            bin_count = np.bincount(s)[1:]
            print(f'zipf-{zipf_alpha}:', bin_count[:10], f'{len(bin_count):,}')
            # x = np.arange(1, len(bin_count) + 1)
            
            self.exp_counts_list.append(bin_count)
            self.name_list.append(f'zipf-{zipf_alpha}-numberofPkt-{filename_suffix}')
    
    def save_to_file(self):
        # create directory if it doesn't exist
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        tmp_key = self.flowkeys[0]
        if tmp_key == "srcip":
            tmp_key = "srcIP"

        for exp_count, dist_name in zip(self.exp_counts_list, self.name_list):
            filename = os.path.join(self.output_dir, self.output_filename + '-' + \
                                    dist_name + '-' + tmp_key)
            print(filename)
            
            with open(f'{filename}.txt', 'w') as file:
                file.write('\n'.join(str(exp) for exp in exp_count))

    def get_counts(self):
        return self.exp_counts_list
    
    def get_names(self):
        return self.name_list
####################################


if __name__ == '__main__':
    filename_list = get_all_filenames('./data/caida')
    flowkeys = ['srcip']

    # setup epoch & timestamp
    pcap_total_time = 60 # 60 sec
    epoch = 30 # 30 sec
    num_of_epoch = int(pcap_total_time/epoch)

    ## generate a distribution for one epoch
    ## Next, generate a pcap with N epoch by this distribution (in .cpp file)

    isFixNumberofPacket = False
    isFixNumberofPacketFlows = False
    isTestNumberofFlow = True
    isTestNumberofPkt = False

    if isFixNumberofPacket:
        # This creates a distribution list for one epoch in a pcap
        # default: one epoch is 30 sec, a pcap has 60 seconds

        # iterate over all files
        for filename in filename_list:
            file_date = filename.split('/')[3]
            file_time = filename.split('-')[2].split('.')[0]
            # print(file_date)
            # print(file_time)
            # output path for distributions
            output_dir = './distributions/' + 'fixPkt/' + file_date + '/'
            output_filename = file_date + '-' + file_time

            print(f'filename: {filename}')
            start = time.time()
            df = pd.read_csv(filename)
            end = time.time()
            print('read_csv:', end - start, 'sec')
            print('df.shape', df.shape)

            # create distribution for this pcap
            dist = Distribution_isFixNumberofPacket(df, output_dir, output_filename, num_of_epoch, flowkeys)
            # dist.add_zipf(1.05)
            dist.add_zipf(1.1)
            # dist.add_zipf(1.3)
            dist.add_uniform()
            print('dist_name_list:', dist.get_names())
            
            dist.save_to_file()
            print('---------------------')
            # break
    # test for different distributions
    # fix number of packets & number of flows
    if isFixNumberofPacketFlows:
        # iterate over all files
        for filename in filename_list:
            file_date = filename.split('/')[3]
            file_time = filename.split('-')[2].split('.')[0]
            # print(file_date)
            # print(file_time)

            ### fix total # of packet
            # output path for distributions
            output_dir = './distributions/' + 'fixFlowPkt/' + file_date + '/'
            output_filename = file_date + '-' + file_time

            print(f'filename: {filename}')
            start = time.time()
            df = pd.read_csv(filename)
            end = time.time()
            print('read_csv:', end - start, 'sec')
            print('df.shape', df.shape)

            # create distribution for this pcap
            dist = Distribution_FixNumberofPacketFlows(df, output_dir, output_filename, num_of_epoch, flowkeys)
            # dist.add_zipf(1.05)
            dist.add_zipf(1.1)
            dist.add_zipf(1.3)
            dist.add_zipf(1.5)
            dist.add_uniform()
            print('dist_name_list:', dist.get_names())
            
            dist.save_to_file()
            print('---------------------')
            # break
    # test for different number of flows
    # fix number of packets
    if isTestNumberofFlow:
        # iterate over all files
        for filename in filename_list:
            file_date = filename.split('/')[3]
            file_time = filename.split('-')[2].split('.')[0]
            # print(file_date)
            # print(file_time)

            ### fix total # of packet
            # output path for distributions
            output_dir = './distributions/' + 'numberofFlow/' + file_date + '/'
            output_filename = file_date + '-' + file_time

            print(f'filename: {filename}')
            start = time.time()
            df = pd.read_csv(filename)
            end = time.time()
            print('read_csv:', end - start, 'sec')
            print('df.shape', df.shape)

            # create distribution for this pcap
            dist = Distribution_diff_NumberofFlow(df, output_dir, output_filename, num_of_epoch, flowkeys)
            dist.add_zipf(1.1)
            print('dist_name_list:', dist.get_names())
            
            dist.save_to_file()
            # break
            print('---------------------')

    # test for different number of packets
    # fix number of flows
    if isTestNumberofPkt:
        # iterate over all files
        for filename in filename_list:
            file_date = filename.split('/')[3]
            file_time = filename.split('-')[2].split('.')[0]
            # print(file_date)
            # print(file_time)

            ### fix total # of packet
            # output path for distributions
            output_dir = './distributions/' + 'numberofPkt/' + file_date + '/'
            output_filename = file_date + '-' + file_time

            print(f'filename: {filename}')
            start = time.time()
            df = pd.read_csv(filename)
            end = time.time()
            print('read_csv:', end - start, 'sec')
            print('df.shape', df.shape)

            # create distribution for this pcap
            dist = Distribution_diff_NumberofPkt(df, output_dir, output_filename, num_of_epoch, flowkeys)
            dist.add_zipf(1.1)
            print('dist_name_list:', dist.get_names())
            
            dist.save_to_file()
            # break
            print('---------------------')




    

