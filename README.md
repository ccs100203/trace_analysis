# Experiments of Master Thesis at NYCU

## Functionality
### distribution_generator.py
- Generate wanted distributions
- index is flow size (number of packets), it represents how many packets in this flow
- values is number fo flows, it means how many flows of this flow size

### pcap_generator.cpp, analyzer.ipynb, analyzer.py
Generate pcaps according to the above distributions
- analyzer.ipynb, analyzer.py:
  - It's too slow to generation pcaps efficiently
- pcap_generator.cpp:
  - It's written from python to cpp
  - Recommend to use cpp version only

### plot.py
Plot the generated pcaps for validation
