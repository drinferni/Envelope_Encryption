CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall
LDFLAGS = -lcrypto -lssl

OBJS = 


BCP_test : BCPtester.o KeyVault.o BaseCryptoProcessor.o Utils.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)


BCPtester.o : BaseCryptoProcessor.h KeyVault.h BCP_tester.cpp
	$(CXX) $(CXXFLAGS) -c BCP_tester.cpp -o $@

BaseCryptoProcessor.o : BaseCryptoProcessor.h BaseCryptoProcessor.cpp KeyVault.h Utils.cpp
	$(CXX) $(CXXFLAGS) -c BaseCryptoProcessor.cpp -o $@

KeyVault_test : KeyVault.o KeyVaulttest.o Utils.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

KeyVaulttest.o : KeyVault.h KeyVaulttest.cpp 
	$(CXX) $(CXXFLAGS) -c KeyVaulttest.cpp -o $@

KeyVault.o: KeyVault.cpp KeyVault.h Utils.cpp
	$(CXX) $(CXXFLAGS) -c KeyVault.cpp -o $@

AccessController.o: AccessController.cpp AccessController.h
	$(CXX) $(CXXFLAGS) -c AccessController.cpp -o $@

Utils.o : Utils.cpp
	$(CXX) $(CXXFLAGS) -c Utils.cpp -o $@



clean:
	rm -f *.o HSM
