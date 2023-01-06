TARGET=custom-airodump
LDLIBS += -lpcap

all: $(TARGET)

main.o: main.cpp

$(TARGET): main.o
	$(LINK.cpp) $^ $(LOADLIBES) $(LDLIBS) -o $@ -g
clean:
	rm -f $(TARGET) *.o
