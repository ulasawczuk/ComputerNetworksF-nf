# Define compiler and flags
CXX = g++
CXXFLAGS = -std=c++11
SERVER_FLAGS = -pthread

# Define targets
CLIENT_TARGET = client
SERVER_TARGET = tsamgroup12

# Define source files
CLIENT_SRC = client.cpp
SERVER_SRC = server.cpp

# Default target
all: $(CLIENT_TARGET) $(SERVER_TARGET)

# Client target
$(CLIENT_TARGET): $(CLIENT_SRC)
	$(CXX) $(CXXFLAGS) -o $(CLIENT_TARGET) $(CLIENT_SRC)

# Server target
$(SERVER_TARGET): $(SERVER_SRC)
	$(CXX) $(CXXFLAGS) $(SERVER_FLAGS) -o $(SERVER_TARGET) $(SERVER_SRC)

# Clean up build artifacts
clean:
	rm -f $(CLIENT_TARGET) $(SERVER_TARGET)

# Phony targets
.PHONY: all clean
