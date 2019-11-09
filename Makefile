CXX := g++
CXXFLAGS := -g -std=c++14 -Wall
LDFLAGS := -lpthread -ltins -lpcap

.PHONY: all
all: main

main: main.o packet_counter.o common.o attacker.o
	$(CXX) $(CXXFLAGS) -o main common.o packet_counter.o attacker.o main.o $(LDFLAGS)

main.o: main.cpp
	$(CXX) $(CXXFLAGS) -c main.cpp

packet_counter.o: packet_counter.cpp packet_counter.h
	$(CXX) $(CXXFLAGS) -c packet_counter.cpp

common.o: common.cpp common.h
	$(CXX) $(CXXFLAGS) -c common.cpp

attacker.o: attacker.cpp attacker.h
	$(CXX) $(CXXFLAGS) -c attacker.cpp

.PHONY: clean
clean:
	rm -f *.o main