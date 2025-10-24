CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall
LDFLAGS = -lcrypto -lssl

OBJS = AzureHSM.o BaseCryptoProcessor.o KeyVault.o AccessController.o Utils.o


Azure_test : Azureclient.o $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)


EG : Env.o 
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

Env.o : envgen.cpp 
	$(CXX) $(CXXFLAGS) -c envgen.cpp -o $@

Azureclient.o : Azure_client.cpp 
	$(CXX) $(CXXFLAGS) -c Azure_client.cpp -o $@

Azure : Azureserver.o $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

Azureserver.o : Azure_server.cpp AzureHSM.o AzureHSM.h 
	$(CXX) $(CXXFLAGS) -c Azure_server.cpp -o $@

AzureHSM.o : AzureHSM.h AzureHSM.cpp BaseCryptoProcessor.o KeyVault.o AccessController.o Utils.o 
	$(CXX) $(CXXFLAGS) -c AzureHSM.cpp -o $@

BaseCryptoProcessor.o : ../HSM/BaseCryptoProcessor.h ../HSM/BaseCryptoProcessor.cpp ../HSM/KeyVault.h ../HSM/Utils.cpp
	$(CXX) $(CXXFLAGS) -c ../HSM/BaseCryptoProcessor.cpp -o $@

KeyVault.o: ../HSM/KeyVault.cpp ../HSM/KeyVault.h ../HSM/Utils.cpp
	$(CXX) $(CXXFLAGS) -c ../HSM/KeyVault.cpp -o $@

AccessController.o: ../HSM/AccessController.cpp ../HSM/AccessController.h
	$(CXX) $(CXXFLAGS) -c ../HSM/AccessController.cpp -o $@

Utils.o : ../HSM/Utils.cpp
	$(CXX) $(CXXFLAGS) -c ../HSM/Utils.cpp -o $@

clean:
	rm -f *.o Azure Azure_test EG
