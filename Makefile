include /usr/local/etc/PcapPlusPlus.mk

# All Target
all:
	g++ $(PCAPPP_BUILD_FLAGS) $(PCAPPP_INCLUDES) -c -o pcap_generator.o pcap_generator.cpp -lstdc++fs
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o pcap_generator pcap_generator.o $(PCAPPP_LIBS) -lstdc++fs

# Clean Target
clean:
	rm pcap_generator.o
	rm pcap_generator