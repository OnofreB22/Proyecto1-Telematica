CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -pthread
TARGET = server

all: $(TARGET)

$(TARGET): main.cpp
	$(CXX) $(CXXFLAGS) -o $(TARGET) main.cpp

clean:
	rm -f $(TARGET)

.PHONY: all clean
