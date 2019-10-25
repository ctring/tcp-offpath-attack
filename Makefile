CXX := g++
CXXFLAGS := -g -std=c++14 -Wall
LDFLAGS := -lpthread -ltins -lpcap

.PHONY: all
all: main

main: main.o packet_counter.o common.o port_finder.o
	$(CXX) $(CXXFLAGS) -o main common.o packet_counter.o port_finder.o main.o $(LDFLAGS)

main.o: main.cpp common.h
	$(CXX) $(CXXFLAGS) -c main.cpp

packet_counter.o: packet_counter.cpp
	$(CXX) $(CXXFLAGS) -c packet_counter.cpp

common.o: common.cpp
	$(CXX) $(CXXFLAGS) -c common.cpp

port_finder.o: port_finder.cpp
	$(CXX) $(CXXFLAGS) -c port_finder.cpp

.PHONY: clean
clean:
	rm -f *.o main