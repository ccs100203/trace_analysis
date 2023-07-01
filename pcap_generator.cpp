#include <iostream>
#include <unordered_map>
#include <chrono>
#include <arpa/inet.h>
#include <experimental/filesystem>
#include <sys/stat.h>
#include <random>

// pcapplusplus
#include "IPv4Layer.h"
#include "Packet.h"
#include "EthLayer.h"
#include "UdpLayer.h"
#include "TcpLayer.h"
#include "DnsLayer.h"
#include "PcapFileDevice.h"
#include "MacAddress.h"
#include "IpAddress.h"
#include "SystemUtils.h"
#include "RawPacket.h"

using namespace std;
namespace filesystem = std::experimental::filesystem;

typedef struct {
    string srcip;
    string dstip;
    string srcport;
    string dstport;
    string proto;
    string time;
    string pkt_len;
    string version;
    string ihl;
    string tos;
    string id;
    string flag;
    string off;
    string ttl;
    string chksum;
    struct timespec ts;
} Pkt_info;

// cout for Pkt_info
ostream & operator << (ostream &out, const Pkt_info &pkt)
{
    out << pkt.srcip << ", " << pkt.dstip << ", ";
    out << pkt.srcport << ", " << pkt.dstport << ", ";
    out << pkt.proto << ", ";
    out << pkt.time << ", " << pkt.pkt_len << ", ";
    out << pkt.version << ", " << pkt.ihl << ", ";
    out << pkt.tos << ", " << pkt.id << ", ";
    out << pkt.flag << ", " << pkt.off << ", ";
    out << pkt.ttl << ", " << pkt.chksum;
    return out;
}

vector<string> getAllFilenames(string base = "./data/caida", int upper_bound = 0) {
    vector<string> v;

    // This structure would distinguish a file from a directory
    struct stat sb;
 
    // Looping until all the items of the directory are
    // exhausted
    for (const auto& entry : filesystem::recursive_directory_iterator(base)) {
 
        // Converting the path to const char * in the
        // subsequent lines
        filesystem::path outfilename = entry.path();
        std::string outfilename_str = outfilename.string();
        const char* path = outfilename_str.c_str();
 
        // Testing whether the path points to a
        // non-directory or not If it does, displays path
        if (stat(path, &sb) == 0 && !(sb.st_mode & S_IFDIR)) {
            std::cout << outfilename_str << std::endl;
            v.emplace_back(outfilename_str);
        }
    }

    cout << "file counts: " << v.size() << endl;
    return v;
}

bool readCsv(string filename, vector<Pkt_info> &v, unordered_map<string, int> &key2cnt) {
    // string filename = "./data/caida/20181018/60s/equinix-nyc.dirA.20181018-130900.UTC.anon.csv";
    // string filename = "./1_new_packet.csv";
    ifstream fin(filename);
    // vector<Pkt_info> v;
    // unordered_map<string, int> key2cnt;

    int cnt = 0;
    Pkt_info pkt;
    while (getline(fin, pkt.srcip, ',')) {
        getline(fin, pkt.dstip, ',');
        getline(fin, pkt.srcport, ',');
        getline(fin, pkt.dstport, ',');
        getline(fin, pkt.proto, ',');
        getline(fin, pkt.time, ',');
        getline(fin, pkt.pkt_len, ',');
        getline(fin, pkt.version, ',');
        getline(fin, pkt.ihl, ',');
        getline(fin, pkt.tos, ',');
        getline(fin, pkt.id, ',');
        getline(fin, pkt.flag, ',');
        getline(fin, pkt.off, ',');
        getline(fin, pkt.ttl, ',');
        getline(fin, pkt.chksum);
        pkt.ts = {1539868140, 1000}; // initialize to a casual number

        // don't push first row, which is column names
        if (cnt++ > 0) {
            v.push_back(pkt);
            // setup flowkeys
            key2cnt[pkt.srcip] = 0;
        }
    }
    return true;
}

vector<int> getExpCountFromFile(string filename = "./distributions/20180517/20180517-130900-zipf-1.7.txt") {
    ifstream fin(filename);
    string val = "";
    vector<int> v;
    while (getline(fin, val, '\n')) {
        v.emplace_back(stoi(val));
    }

    return v;
}

bool createPacketForGivenCnt(Pkt_info &pkt, int pktcnt, pcpp::PcapFileWriterDevice &writer2) {
    while (pktcnt --> 0) {
        // create a new Ethernet layer
        // pcpp::EthLayer newEthernetLayer(pcpp::MacAddress("00:50:43:11:22:33"), pcpp::MacAddress("aa:bb:cc:dd:ee"));
        
        // create a new IPv4 layer
        pcpp::IPv4Layer newIPLayer(pcpp::IPv4Address(htonl(stol(pkt.srcip))), pcpp::IPv4Address(htonl(stol(pkt.dstip))));
        newIPLayer.getIPv4Header()->ipId = pcpp::hostToNet16(stol(pkt.id));
        newIPLayer.getIPv4Header()->timeToLive = stol(pkt.ttl);

        // create a new UDP layer
        pcpp::UdpLayer newUdpLayer(stol(pkt.srcport), stol(pkt.dstport));
        // create a new TCP layer
        pcpp::TcpLayer newTcpLayer(stol(pkt.srcport), stol(pkt.dstport));

        pcpp::Packet newPacket(100);
        newPacket.addLayer(&newIPLayer);

        if (pkt.proto == "UDP") {
            newPacket.addLayer(&newUdpLayer);
        } else if (pkt.proto == "TCP") {
            newPacket.addLayer(&newTcpLayer);
        } else {
            cout << pkt.proto << endl;
            perror("\n =====pkt.proto: shouldn't come here====== \n");
            return false;
        }

        // setup timestamp
        newPacket.getRawPacket()->setPacketTimeStamp(pkt.ts);

        // compute all calculated fields
        newPacket.computeCalculateFields();
        // write the new packet to a pcap file
        writer2.writePacket(*(newPacket.getRawPacket()));
    }
    
    return true;
}

Pkt_info getNextPktinfo(int &idx_flowkey, vector<Pkt_info> &v, unordered_map<string, int> &key2cnt) {
    // key is not enough, creating flowkey by myself
    if (idx_flowkey == -1) {
        // random generate flowkey (srcIP)
        std::random_device dev;
        std::mt19937 rng(dev());
        // distribution in range [1, 255.255.255.255]
        std::uniform_int_distribution<std::mt19937::result_type> dist_ip(1, 0xffffffff); 

        // avoid use non-tcp & non-udp packets, default is 0
        int packet_idx = 0;
        // find the unused flowkey
        while (true) {
            string my_flowkey = to_string(dist_ip(rng));
            // it means this flowkey was unused
            if (key2cnt.find(my_flowkey) == key2cnt.end()) {
                Pkt_info new_pkt = v.at(packet_idx);
                
                // it doesn't use this packet
                if (new_pkt.proto != "UDP" && new_pkt.proto != "TCP") {
                    packet_idx++;
                    continue;
                }

                key2cnt[my_flowkey] = 1;
                new_pkt.srcip = my_flowkey;
                return new_pkt;
            }
        }
        perror("\n ====== idx_flowkey: should not come here!! ====== \n");
        return Pkt_info();
    } // retrieve the existing flowkey
    else {
        while(true) {
            // check whether flowkey is enough
            if ((unsigned int)idx_flowkey >= v.size()) {
                // perror("key is not enough!");
                cout << "key is not enough, create by myself" << endl;
                idx_flowkey = -1;
                return getNextPktinfo(idx_flowkey, v, key2cnt);
            }

            // setup flowkey
            string key = v.at(idx_flowkey).srcip;
            if (key2cnt[key] == 0 && (v.at(idx_flowkey).proto == "UDP" || v.at(idx_flowkey).proto == "TCP")) {
                key2cnt[key]++;
                return v.at(idx_flowkey++);
            } else {
                idx_flowkey++;
            }
        }
    }
    
}

bool createDummyPacket(int pcap_total_time, int epoch, \
                        string output_filename, string distribution_filename, \
                        vector<Pkt_info> &pkt_vec, unordered_map<string, int> &key2cnt) {

    // start time stamp of current epoch
    struct timespec start_ts;
    long long tmp_time = stoll(pkt_vec[0].time); // us
    start_ts.tv_sec = tmp_time / 1000000; // sec
    start_ts.tv_nsec = (tmp_time % 1000000) * 1000; // ns

    // index for pkt_vec, it indirects the next pkt_info which should be used
    int idx_flowkey = 0;
    // record total count of created packets
    long long total_pkt_cnt = 0;

    pcpp::PcapFileWriterDevice writer2(output_filename);
    writer2.open(); // overwrite previous pcap file & create new one
    writer2.close();
    writer2.open(true); // append mode

    // iterate over each epoch
    for (int cur_epoch = 0; cur_epoch < pcap_total_time/epoch; cur_epoch++) {
        // setup timestamp
        struct timespec ts;
        ts.tv_sec = start_ts.tv_sec + epoch * cur_epoch;
        ts.tv_nsec = start_ts.tv_nsec + 1000 * cur_epoch;
        
        vector<int> exp_count_list = getExpCountFromFile(distribution_filename);
        // vector<int> exp_count_list = {1, 0};

        // `i` is index in `exp_count`, `i + 1` is also the packet size for this flowkey
        // @exp means count of flowkeys in this index (packet size/cnt)
        for (unsigned int i = 0; i < exp_count_list.size(); ++i) {
            unsigned int exp = exp_count_list[i];
            // if it needs to create dummy packet
            if (exp > 0) {
                int pktcnt = i + 1;
                total_pkt_cnt += pktcnt * exp;

                // how many flowkey should be created on this packet cnt
                for (unsigned int j = 0; j < exp; ++j) {
                    Pkt_info pkt_info;
                    try {
                        pkt_info = getNextPktinfo(idx_flowkey, pkt_vec, key2cnt);
                        pkt_info.ts = ts;
                    } catch (std::exception &e) { // exception should be caught by reference
                        cout << "exception: " << e.what() << "\n";
                        return false;
                    }

                    if(!createPacketForGivenCnt(pkt_info, pktcnt, writer2)) {
                        perror("\n ====== createPacketForGivenCnt failed =====\n");
                        return false;
                    }
                }
            }
        }
    }

    writer2.close();
    cout << "total_pkt_cnt: " << total_pkt_cnt << endl;
    
    return true;
}

vector<string> getStringSplitByIndex(string s = "scott>=tiger>=mushroom", string delimiter = ">=") {
    vector<string> ret;
    size_t pos = 0;
    std::string token;
    while ((pos = s.find(delimiter)) != std::string::npos) {
        token = s.substr(0, pos);
        ret.emplace_back(token);
        s.erase(0, pos + delimiter.length());
    }
    ret.emplace_back(s);
    return ret;
}

int main(int argc, char* argv[]) {
    vector<string> filename_list = getAllFilenames("./data/caida");
    // test
    // vector<string> filename_list = {"./data/caida/20181018/60s/equinix-nyc.dirA.20181018-130900.UTC.anon.csv"};
    // vector<string> distribution_list = {"zipf-1.05", "zipf-1.1", "zipf-1.3", "uniform-100"};
    
    // Different distributions with fixed number of flows & packets
    // vector<string> distribution_list = {"zipf-1.1", "zipf-1.3", "zipf-1.5", "uniform"};
    // string distribution_feature = "fixFlowPkt";
    // vector<string> distribution_feature_suffix_list = {""};
    
    // Different number of flows
    // vector<string> distribution_list = {"zipf-1.1"};
    // string distribution_feature = "numberofFlow";
    // vector<string> distribution_feature_suffix_list = {"-1x", "-0.5x", "-2x"};
    vector<string> distribution_list = {"zipf-1.1"};
    string distribution_feature = "numberofFlow";
    vector<string> distribution_feature_suffix_list = {"-0.1x", "-4x", "-10x"};

    // Different number of packets
    // vector<string> distribution_list = {"zipf-1.1"};
    // string distribution_feature = "numberofPkt";
    // vector<string> distribution_feature_suffix_list = {"-1x", "-0.3x", "-0.6x"};

    string flowkey = "srcIP";
    // setup epoch & timestamp
    int pcap_total_time = 60; // 60 sec
    int epoch = 30; // 30 sec

    for (unsigned int i = 0; i < filename_list.size(); ++i) {
        string filename = filename_list.at(i);

        vector<Pkt_info> pkt_vec;
        // record if this key is already used for creating dummy packet
        unordered_map<string, int> key2cnt;

        std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
        readCsv(filename, pkt_vec, key2cnt);
        // readCsv("./1_new_packet.csv", pkt_vec, key2cnt);
        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        std::cout << "readCsv(): " << std::chrono::duration_cast<std::chrono::seconds>(end - begin).count() << " sec" << std::endl;

        for (unsigned int j = 0; j < distribution_list.size(); ++j) {
            for (string distribution_feature_suffix : distribution_feature_suffix_list) {
                string distribution = distribution_list.at(j);
                string file_date = getStringSplitByIndex(filename, "/")[3];
                string file_time = getStringSplitByIndex(getStringSplitByIndex(filename, "-")[2], ".")[0];

                // ./my_pcaps/zipf-1.05-srcIP/20181220/60s/
                string output_directory = "./my_pcaps/" + distribution_feature + "/" + distribution + "-" + flowkey + "/" + file_date + "/" + std::to_string(pcap_total_time) + "s/";

                // 20181220-131100-zipf-1.05-srcIP
                string base_filename = file_date + "-" + file_time + "-" + distribution + "-" + distribution_feature \
                                        + distribution_feature_suffix + "-" + flowkey;

                // ./my_pcaps/fixFlowPkt/zipf-1.05-srcIP/20181220/60s/20181220-131100-zipf-1.1-fixFlowPkt-srcIP.pcap
                string output_filename = output_directory + base_filename + ".pcap";
                // ./distributions/fixFlowPkt/20181220/20181220-131100-zipf-1.1-fixFlowPkt-srcIP.txt
                string distribution_filename = "./distributions/" + distribution_feature + "/" + file_date + "/" + base_filename + ".txt";
                cout << output_filename << endl;
                cout << distribution_filename << endl;


                // create output directory if not exists
                filesystem::create_directories(output_directory);

                // copy a new key2cnt map
                unordered_map<string, int> key2cnt_tmp(key2cnt);

                begin = std::chrono::steady_clock::now();
                createDummyPacket(pcap_total_time, epoch, output_filename, 
                                    distribution_filename, pkt_vec, key2cnt_tmp);
                end = std::chrono::steady_clock::now();
                std::cout << distribution +  "-createDummyPacket(): " << std::chrono::duration_cast<std::chrono::seconds>(end - begin).count() << " sec" << std::endl;
            }
        }
    }
    
    return 0;
}