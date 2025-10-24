CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall
LDFLAGS = -lcrypto -lssl

OBJS = AWSHSM.o BaseCryptoProcessor.o KeyVault.o AccessController.o Utils.o


AWS_test : AWSclient.o $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)


EG : Env.o 
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

Env.o : envgen.cpp 
	$(CXX) $(CXXFLAGS) -c envgen.cpp -o $@

AWSclient.o : AWS_client.cpp 
	$(CXX) $(CXXFLAGS) -c AWS_client.cpp -o $@

AWS : AWSserver.o $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

AWSserver.o : AWS_server.cpp AWSHSM.o AWSHSM.h 
	$(CXX) $(CXXFLAGS) -c AWS_server.cpp -o $@

AWSHSM.o : AWSHSM.h AWSHSM.cpp BaseCryptoProcessor.o KeyVault.o AccessController.o Utils.o 
	$(CXX) $(CXXFLAGS) -c AWSHSM.cpp -o $@

BaseCryptoProcessor.o : ../HSM/BaseCryptoProcessor.h ../HSM/BaseCryptoProcessor.cpp ../HSM/KeyVault.h ../HSM/Utils.cpp
	$(CXX) $(CXXFLAGS) -c ../HSM/BaseCryptoProcessor.cpp -o $@

KeyVault.o: ../HSM/KeyVault.cpp ../HSM/KeyVault.h ../HSM/Utils.cpp
	$(CXX) $(CXXFLAGS) -c ../HSM/KeyVault.cpp -o $@

AccessController.o: ../HSM/AccessController.cpp ../HSM/AccessController.h
	$(CXX) $(CXXFLAGS) -c ../HSM/AccessController.cpp -o $@

Utils.o : ../HSM/Utils.cpp
	$(CXX) $(CXXFLAGS) -c ../HSM/Utils.cpp -o $@

clean:
	rm -f *.o AWS AWS_test EG
