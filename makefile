CXX = g++

CXXFLAGS = -std=c++11 -Wall

LDFLAGS = -lssl -lcrypto

OBJS = test_handy_crypto.o handy_crypto.o

test: clean test_handy_crypto.exe
	./test_handy_crypto.exe

test_handy_crypto.exe: test_handy_crypto.o handy_crypto.o
	$(CXX) $(CXXFLAGS) -o test_handy_crypto.exe test_handy_crypto.o handy_crypto.o $(LDFLAGS)

test_handy_crypto.o: ./test/test_handy_crypto.cpp
	cd ./test && py generate_aes_key.py
	cd ./test && py generate_key_pair.py keygen
	$(CXX) $(CXXFLAGS) -I./src -c ./test/test_handy_crypto.cpp -o test_handy_crypto.o

handy_crypto.o: ./src/handy_crypto.cpp ./src/handy_crypto.hpp
	$(CXX) $(CXXFLAGS) -c ./src/handy_crypto.cpp -o handy_crypto.o

clean:
	rm -f $(OBJS) test_handy_crypto.exe
	rm -f *.aes
	rm -f ./test/*key.h
	rm -f ./test/*.pem
