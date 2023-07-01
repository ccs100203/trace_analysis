import pickle
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
import pandas as pd
import random
import time
from datetime import datetime
import json
from collections import Counter
import os
import copy
import seaborn as sns
import socket
import struct
from scapy.all import Ether, IP, TCP, UDP, wrpcap, rdpcap

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
class Distribution:
        
    def __init__(self, sample_times = 200000):
        self.sample_times = sample_times
        self.init_zipf()
        self.init_uniform()
    
    ####################################
    def init_zipf(self, zipf_alpha = 1.9):

        s = np.random.zipf(a=zipf_alpha, size=self.sample_times)
        bin_count = np.bincount(s)[1:]
        print('zipf:', bin_count[:10], len(bin_count))

        x = np.arange(1, len(bin_count) + 1)
        
        self.zipf_x = x
        self.zipf_count = bin_count
    
    def get_zipf_count(self):
        return self.zipf_count
    
    ####################################
    def init_uniform(self, high_bound = 50):
        s = np.random.uniform(0, high_bound, self.sample_times)
        s = s.astype(int)
        bin_count = np.bincount(s)
        print('uniform:', bin_count[:10], len(bin_count))
        # a = plt.hist(s, density=True)

        x = np.arange(1, len(bin_count) + 1)
        self.uniform_x = x
        self.uniform_count = bin_count
    
    def get_uniform_count(self):
        return self.uniform_count
    
    ####################################
    def get_count_of_distributions(self):
        return [self.zipf_count, self.uniform_count]
    
    def get_name_of_distributions(self):
        return ['zipf', 'uniform']
    

####################################

class Pcap:
    def __init__(self, exp_count, input_filename = './data/caida/20181018/60s/equinix-nyc.dirA.20181018-130900.UTC.anon.csv', \
                 output_filename='20181018-130900_srcip_zipf', output_directory='./output/', flowkeys = ['srcip']):
        self.exp_count = exp_count
        self.input_filename = input_filename
        self.output_filename = output_filename
        self.output_directory = output_directory
        self.flowkeys = flowkeys
        self.log_directory = './log/' + output_directory[1:]

        # create directory if it doesn't exist
        if not os.path.exists(self.output_directory):
            os.makedirs(self.output_directory)

        if not os.path.exists(self.log_directory):
            os.makedirs(self.log_directory)
        
    def setup_dataframe(self):
        start = time.time()
        self.df = pd.read_csv(self.input_filename)
        end = time.time()
        print('read_csv:', end - start, 'sec')
        print('df.shape', self.df.shape)
        
        # flowkey & packet size mapping
        self.flowkey_to_pktsize = self.df.groupby(self.flowkeys).size()
        # print(flowkey_to_pktsize)
        
        # how many flowkeys
        self.flowkeys_count = len(self.df.groupby(self.flowkeys).size())
        # print('\nflowkeys_count:', flowkeys_count)
        
        # values (packet size) of each flowkeys
        self.df_vals = self.df.groupby(self.flowkeys).size().values
        
    # get real distribution of this dataset (pcap file)
    # return:
    # @real_count: number of flowskeys in given x
    # @x: index of flowkeys, the value of `x` means the size (number of packets) of the flowkeys
    def get_real_count(self):
        dist_dict = dict(Counter(self.df_vals))
        dist_dict = {k: v for k, v in sorted(dist_dict.items(), key = lambda x: x[0])}
        x = dist_dict.keys()
        x = list(x)

        count = np.asarray(list(dist_dict.values()), dtype=int) # / float(sum(dist_dict.values()))
        print('real_count:', x[-10:], count[-10:])

        self.real_x = x
        self.real_count = count
        return x, count
    
    # calculate the difference between `real_count` and `exp_count`
    # return:
    # @diff_count: difference between `real_count` and `exp_count`
    # @pktsize_to_probability: probability about keeping flowkeys(`remaining_keys`) for the pcap
    def get_probability_and_difference(self):
        pktsize_to_probability = {}
        # calculate the difference between real & expect
        diff_count = copy.deepcopy(self.exp_count)
        for idx, cnt in zip(self.real_x, self.real_count):
            try:
                exp_cnt = self.exp_count[idx - 1]
                diff_count[idx - 1] -= cnt
            except:
                exp_cnt = 0

            # flowkey's keeping probability
            prob = float(exp_cnt) / cnt
            # if prob > 1:
            #     print(exp_cnt / cnt)
            pktsize_to_probability[idx] = prob
            # print(idx, cnt, prob)
        print('len(self.exp_count):', len(self.exp_count), 'len(pktsize_to_probability):', len(pktsize_to_probability))
        self.diff_count = diff_count
        self.pktsize_to_probability = pktsize_to_probability
        return diff_count, pktsize_to_probability
    
    # split flowkeys into `remaining_keys` and `removed_keys`
    # and create dataframe `df_remaining_keys` for remaining_keys
    # return:
    # @remaining_keys: the remaining flowkeys
    # @removed_keys: the removed flowkeys
    # @df_remaining_keys: the dataframe of remaining_keys
    def split_flowkeys(self):
        cnt = 0
        drop_cnt = 0
        df2 = self.df.copy(deep=True)

        remaining_keys = []
        removed_keys = []
        ### Drop flowkeys which more than distribution
        start = time.time()
        for key in list(self.df.groupby(self.flowkeys).size().index):
            pktsize = self.flowkey_to_pktsize[key]
            prob = self.pktsize_to_probability[pktsize]
            # drop this flowkey
            if random.random() > prob:
                drop_cnt += 1
                removed_keys.append(key)
            # keep this key
            else:
                remaining_keys.append(key)
            cnt += 1

        end = time.time()
        print('split_flowkeys:', end - start, 'sec')
        print('total cnt:', cnt, 'drop cnt:', drop_cnt)

        df2 = df2.loc[df2['srcip'].isin(remaining_keys)]
        
        self.remaining_keys = remaining_keys
        self.removed_keys = removed_keys
        self.df_remaining_keys = df2
        
        print('len(remaining_keys):', len(remaining_keys), 'len(removed_keys):', len(removed_keys))
        print('df_remaining_keys.shape:', self.df_remaining_keys.shape)
        print('df.shape:', self.df.shape)

        return remaining_keys, removed_keys, df2
    

    # create dummy packet which flowkey less than distribution from removed keys
    # return:
    # @my_dummy_pkts_list: created dummy packet list
    def create_dummy_packet(self):
        dummy_pkt_cnt = 0
        idx_removed_key = 0
        pkts_list = []

        try:
            # `i` is index in `diff_count`, `i + 1` is also the packet size
            for i, diff in enumerate(self.diff_count):
                # it needs to create dummy packet
                if diff > 0:
                    # print(i, d)
                    pktsize = i + 1
                    dummy_pkt_cnt += pktsize * diff
                    # print(pktsize)
                    # how many flowkey should be created on this packet size
                    for num in range(diff):
                        pkt_info = self.df[self.df['srcip'] == self.removed_keys[idx_removed_key]].iloc[0]
                        tmp_ll = []
                        # TCP
                        if pkt_info['proto'] == 'TCP':
                            pkt = Ether(dst='00:11:22:33:44:55')/IP(src=long2ip(pkt_info['srcip']), dst=long2ip(pkt_info['dstip']))/TCP(sport=pkt_info['srcport'], dport=pkt_info['dstport'])
                        # UDP
                        else:
                            pkt = Ether(dst='00:11:22:33:44:55')/IP(src=long2ip(pkt_info['srcip']), dst=long2ip(pkt_info['dstip']))/UDP(sport=pkt_info['srcport'], dport=pkt_info['dstport'])

                        # setup timestamp
                        pkt.time = pkt_info.time / 1e6
                        # duplicate packets, according to pktsize
                        tmp_ll = [pkt] * pktsize
                        pkts_list += tmp_ll
                        idx_removed_key += 1
        except Exception as e: 
            log = open(pcap.log_directory + '/' + pcap.output_filename + '.txt', "a")
            log.write('===================================================\n')
            log.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '\n')
            log.write(str(e))
            log.write('\n')
            log.write('create_dummy_packet------inner\n')
            log.write('dummy_pkt_cnt: ' + str(dummy_pkt_cnt) + '\n')
            log.write('idx_removed_key: ' + str(idx_removed_key) + '\n')
            log.write('len(self.diff_count), i: ' + str(len(self.diff_count)) + ', ' + str(i) + '\n')
            log.write('===================================================\n')
            log.close()

        print('dummy_pkt_cnt', dummy_pkt_cnt)
        print('idx_removed_key:', idx_removed_key)
        print('len(pkts_list):', len(pkts_list))
        
        self.my_dummy_pkts_list = pkts_list
        
        return pkts_list

    # create packet for remaining flowkeys
    def create_packet(self, pkt_info):
        self.pkt_cnt_of_remaining_key += 1
        if self.pkt_cnt_of_remaining_key % 100000 == 0:
            print('create_packet:', self.pkt_cnt_of_remaining_key)

        if pkt_info['proto'] == 'TCP':
            pkt = Ether(dst='00:11:22:33:44:55')/IP(src=long2ip(pkt_info['srcip']), dst=long2ip(pkt_info['dstip']))/TCP(sport=pkt_info['srcport'], dport=pkt_info['dstport'])
        # UDP
        else:
            pkt = Ether(dst='00:11:22:33:44:55')/IP(src=long2ip(pkt_info['srcip']), dst=long2ip(pkt_info['dstip']))/UDP(sport=pkt_info['srcport'], dport=pkt_info['dstport'])

        # setup timestamp
        pkt.time = pkt_info.time / 1e6
        self.pkt_of_remaining_key.append(pkt)
        
    # create packets for remaining keys
    def create_pkt_for_remaining_keys(self):        
        self.pkt_cnt_of_remaining_key = 0
        self.pkt_of_remaining_key = []
        
        start = time.time()
        # create packets for remaining keys
        self.df_remaining_keys.apply(self.create_packet, axis=1)

        end = time.time()
        print('create_pkt_for_remaining_keys:', end - start, 'sec')

        assert(len(self.pkt_of_remaining_key) == self.pkt_cnt_of_remaining_key)
        print('len(self.pkt_of_remaining_key):', len(self.pkt_of_remaining_key))
        
        
    def save_pcap(self):
        name = self.output_directory + self.output_filename
        f_log = open(self.log_directory + '/' + self.output_filename + '.txt', "a")
        f_log.write('===================================================\n')
        f_log.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '\n')
        print('output filename:', name)
        f_log.write('output filename: ' + name + '\n')

        # concatenate packets of remaining keys & dummy keys, svae into pcap files
        start = time.time()

        ll = self.pkt_of_remaining_key + self.my_dummy_pkts_list
        print('packet count of remaining:',len(self.pkt_of_remaining_key), 'packet count of dummy keys:',len(self.my_dummy_pkts_list))
        print('total count of packet:', len(ll))
        f_log.write('packet count of remaining: ' + str(len(self.pkt_of_remaining_key)) + ', packet count of dummy keys: ' + str(len(self.my_dummy_pkts_list)) + '\n')
        f_log.write('total count of packet: ' + str(len(ll)) + '\n')
        
        wrpcap(name + '.pcap', ll)

        end = time.time()
        print('save_pcap:', end - start, 'sec')
        f_log.write('save_pcap: ' + str(end - start) + 'sec' + '\n')
        f_log.write('===================================================\n')
        f_log.close()


####################################
# def test(pcap):
#     log = open(pcap.log_directory + '/' + pcap.output_filename + '.txt', "a")
#     try:
#         pcap.save_pcap()
#     except Exception as e: 
#         log.write('===================================================\n')
#         log.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '\n')
#         log.write(str(e))
#         log.write('\n')
#         log.write('save_pcap\n')
#         log.write('===================================================\n')
#         log.close()
#         return
    
#     log.close()

# execution function
def create_wanted_pcap(pcap):
    log = open(pcap.log_directory + '/' + pcap.output_filename + '.txt', "a")
    try:
        pcap.setup_dataframe()
    except Exception as e: 
        log.write('===================================================\n')
        log.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '\n')
        log.write(str(e))
        log.write('\n')
        log.write('setup_dataframe\n')
        log.write('===================================================\n')
        log.close()
        return
    
    try:
        pcap.get_real_count()
    except Exception as e: 
        log.write('===================================================\n')
        log.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '\n')
        log.write(str(e))
        log.write('\n')
        log.write('get_real_count\n')
        log.write('===================================================\n')
        log.close()
        return
    
    try:
        pcap.get_probability_and_difference()
    except Exception as e: 
        log.write('===================================================\n')
        log.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '\n')
        log.write(str(e))
        log.write('\n')
        log.write('get_probability_and_difference\n')
        log.write('===================================================\n')
        log.close()
        return
    
    try:
        pcap.split_flowkeys()
    except Exception as e: 
        log.write('===================================================\n')
        log.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '\n')
        log.write(str(e))
        log.write('\n')
        log.write('split_flowkeys\n')
        log.write('===================================================\n')
        log.close()
        return
    
    try:
        # create packet for remaining flowkeys
        pcap.create_pkt_for_remaining_keys()
    except Exception as e: 
        log.write('===================================================\n')
        log.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '\n')
        log.write(str(e))
        log.write('\n')
        log.write('create_pkt_for_remaining_keys\n')
        log.write('===================================================\n')
        log.close()
        return
    
    try:
        # if x-axis less than distribution, 
        # it needs to create dummy packet from removed flowkeys
        pcap.create_dummy_packet()
    except Exception as e: 
        log.write('===================================================\n')
        log.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '\n')
        log.write(str(e))
        log.write('\n')
        log.write('create_dummy_packet----outside\n')
        log.write('===================================================\n')
        log.close()
        return
    
    try:
        pcap.save_pcap()
    except Exception as e: 
        log.write('===================================================\n')
        log.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '\n')
        log.write(str(e))
        log.write('\n')
        log.write('save_pcap\n')
        log.write('===================================================\n')
        log.close()
        return
    
    log.close()


if __name__ == '__main__':
    filename_list = get_all_filenames()
    flowkeys = ['srcip']

    output_base = './output/'
    
    dist = Distribution()
    exp_count_list = dist.get_count_of_distributions()
    dist_name_list = dist.get_name_of_distributions()
    print('len(dist_name_list):', len(dist_name_list))
    
    from python_lib.run_parallel_helper import ParallelRunHelper
    # number of processes in parallel
    helper = ParallelRunHelper(6)

    for filename in filename_list:
        for exp_count, dist_name in zip(exp_count_list, dist_name_list):
            file_date = filename.split('/')[3]
            file_time = filename.split('-')[2].split('.')[0]

            output_filename = file_date + '-' + file_time + '-' + flowkeys[0] + '-' + dist_name
            print(output_filename)
            output_directory = output_base + '/' + file_date + '/'

            pcap = Pcap(exp_count, filename, output_filename, output_directory, flowkeys)
            helper.call(create_wanted_pcap, (pcap, ))
            # helper.call(test, (pcap, ))

    

