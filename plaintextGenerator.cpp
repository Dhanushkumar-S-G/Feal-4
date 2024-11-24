#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdlib>
#include <ctime>
#include <sstream>


using namespace std;


void WriteFile(const vector<string>& hexPairs) {
    ofstream fileOut("plaintexts2.txt", ofstream::trunc);
    for (const auto& hex : hexPairs) {
        fileOut << hex << endl;
    }
    fileOut.close();
}

int main() {
    unsigned long long diff = 0x0000000002000000LL;
    vector<string> hexPairs;
    srand(time(NULL));

    for (int c = 0; c < 4; c++) {
        unsigned long long plain0;
        unsigned long long plain1;
        plain0 = (unsigned long long)(rand() & 0xFFFFLL) << 48LL;
        plain0 += (unsigned long long)(rand() & 0xFFFFLL) << 32LL;
        plain0 += (unsigned long long)(rand() & 0xFFFFLL) << 16LL;
        plain0 += (unsigned long long)(rand() & 0xFFFFLL);
        plain1 = plain0^diff;

        
        stringstream ss;
        ss << hex << setw(16) << setfill('0') << plain0;  
        hexPairs.push_back(ss.str());

        
        ss.str(""); 
        ss << hex << setw(16) << setfill('0') << (plain1);
        hexPairs.push_back(ss.str());
    }

    WriteFile(hexPairs);

    return 0;
}
