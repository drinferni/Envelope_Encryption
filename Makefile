CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall
LDFLAGS = -lcrypto

OBJS = main.o asym.o sym.o hash.o

lab3: $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJS) $(LDFLAGS)

main.o: main.cpp asym_enc.h sym_enc.h hash.h 
	$(CXX) $(CXXFLAGS) -c main.cpp -o $@

asym.o: asym_enc.cpp asym_enc.h
	$(CXX) $(CXXFLAGS) -c asym_enc.cpp -o $@

sym.o: sym_enc.cpp sym_enc.h
	$(CXX) $(CXXFLAGS) -c sym_enc.cpp -o $@

hash.o: hash.cpp hash.h
	$(CXX) $(CXXFLAGS) -c hash.cpp -o $@

clean:
	rm -f *.o lab3
