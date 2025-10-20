CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall
LDFLAGS = -lcrypto -lssl

OBJS = HSM_driver.o KeyVault.o HSM.o CryptoProcessor.o AccessController.o

HSM: $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJS) $(LDFLAGS)

HSM_driver.o: HSM_server.cpp HSM.h
	$(CXX) $(CXXFLAGS) -c HSM_server.cpp -o $@

KeyVault.o: KeyVault.cpp KeyVault.h
	$(CXX) $(CXXFLAGS) -c KeyVault.cpp -o $@

HSM.o : HSM.h HSM.cpp
	$(CXX) $(CXXFLAGS) -c HSM.cpp -o $@

CryptoProcessor.o: CryptoProcessor.cpp CryptoProcessor.h
	$(CXX) $(CXXFLAGS) -c CryptoProcessor.cpp -o $@

AccessController.o: AccessController.cpp AccessController.h
	$(CXX) $(CXXFLAGS) -c AccessController.cpp -o $@



clean:
	rm -f *.o HSM
