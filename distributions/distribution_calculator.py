
if __name__ == '__main__':

    filename = './numberofFlow/20180517/20180517-130900-zipf-1.1-numberofFlow-0.1x-srcIP.txt'
    print(filename)
    file = open(filename, 'r')
    flowsize = 1
    number_of_flows = 0
    number_of_pkt = 0
    for item in file:
        number_of_flows += int(item)
        number_of_pkt += int(item) * flowsize
        flowsize += 1

    print(f'Number of flows: {number_of_flows:,}')
    print(f'Number of packets: {number_of_pkt:,}')