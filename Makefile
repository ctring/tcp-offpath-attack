CXX := g++
CXXFLAGS := -g -std=c++14 -Wall
LDFLAGS := -lpthread -ltins -lpcap

.PHONY: all
all: main

main: main.o packet_counter.o
	$(CXX) $(CXXFLAGS) -o main packet_counter.o main.o $(LDFLAGS)

main.o: main.cpp common.h
	$(CXX) $(CXXFLAGS) -c main.cpp

packet_counter.o: packet_counter.cpp
	$(CXX) $(CXXFLAGS) -c packet_counter.cpp

.PHONY: clean
clean:
	rm -f *.o main