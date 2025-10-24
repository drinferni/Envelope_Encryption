CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall
LDFLAGS = -lcrypto -lssl

OBJS = GCHSM.o BaseCryptoProcessor.o KeyVault.o AccessController.o Utils.o


GC_test : GCclient.o $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)


EG : Env.o 
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

Env.o : envgen.cpp 
	$(CXX) $(CXXFLAGS) -c envgen.cpp -o $@

GCclient.o : GC_client.cpp 
	$(CXX) $(CXXFLAGS) -c GC_client.cpp -o $@

GC : GCserver.o $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

GCserver.o : GC_server.cpp GCHSM.o GCHSM.h 
	$(CXX) $(CXXFLAGS) -c GC_server.cpp -o $@

GCHSM.o : GCHSM.h GCHSM.cpp BaseCryptoProcessor.o KeyVault.o AccessController.o Utils.o 
	$(CXX) $(CXXFLAGS) -c GCHSM.cpp -o $@

BaseCryptoProcessor.o : ../HSM/BaseCryptoProcessor.h ../HSM/BaseCryptoProcessor.cpp ../HSM/KeyVault.h ../HSM/Utils.cpp
	$(CXX) $(CXXFLAGS) -c ../HSM/BaseCryptoProcessor.cpp -o $@

KeyVault.o: ../HSM/KeyVault.cpp ../HSM/KeyVault.h ../HSM/Utils.cpp
	$(CXX) $(CXXFLAGS) -c ../HSM/KeyVault.cpp -o $@

AccessController.o: ../HSM/AccessController.cpp ../HSM/AccessController.h
	$(CXX) $(CXXFLAGS) -c ../HSM/AccessController.cpp -o $@

Utils.o : ../HSM/Utils.cpp
	$(CXX) $(CXXFLAGS) -c ../HSM/Utils.cpp -o $@

clean:
	rm -f *.o GC GC_test EG
