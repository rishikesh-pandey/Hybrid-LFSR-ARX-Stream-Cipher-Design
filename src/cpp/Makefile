CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O3 -march=native
TARGET = hybrid_cipher
SRC = hybrid_cipher.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC)

benchmark: $(TARGET)
	./$(TARGET) --benchmark

clean:
	rm -f $(TARGET)

.PHONY: all benchmark clean
