TARGET=airodump
LDLIBS += -lpcap
CXX = g++
CXXFLAGS = -O0 -g -std=c++17

all: $(TARGET)

tools.o: tools.h tools.cpp
	$(CXX) -c tools.cpp -o tools.o

parser.o: RadiotapParser.h RadiotapParser.cpp
	$(CXX) -c RadiotapParser.cpp -o parser.o

main.o: main.cpp tools.h RadiotapParser.h
	$(CXX) -c main.cpp

$(TARGET): tools.o parser.o main.o
	$(CXX) tools.o parser.o main.o -o $(TARGET) $(LOADLIBES) $(LDLIBS)

clean:
	rm -f $(TARGET) *.o
