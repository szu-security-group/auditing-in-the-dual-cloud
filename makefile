CXX = g++
CXXFLAGS = -std=c++17 -Wall -msse4.1 -maes -mpclmul -msse2
LDFLAGS = -lssl -lcrypto -lcryptopp


SRCS = Client.cpp general.cpp gfmul.cpp main.cpp rc4.cpp rijndael.cpp Server.cpp timer.cpp update.cpp


TARGET = run
STATIC_TARGET = static_run



$(TARGET): $(SRCS)
	$(CXX) -O3 $(CXXFLAGS) -o $(TARGET) $(SRCS) $(LDFLAGS)

$(STATIC_TARGET): $(SRCS)
	$(CXX) -O3 $(CXXFLAGS) -o $(STATIC_TARGET) $(SRCS) -static $(LDFLAGS) 

clean:
	rm -f $(TARGET) $(STATIC_TARGET)

