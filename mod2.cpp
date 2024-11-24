/*
 *	Differential cryptanalytic attack on FEAL-4 (CPA) - Modified with Two-Phase Attack
 *	Based on original work by Ankit Kumar Misra and Kartikey Gupta
 */

#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <algorithm>
#include <fstream>
#include <string>
#include <cstdlib>
#include <ctime>
using namespace std;
typedef unsigned char BYTE;

#define MAX_CHOSEN_PAIRS 10000

typedef unsigned long long ull;
typedef unsigned uint;
typedef unsigned char byt;

int num_plaintexts;
uint key[6];

ull plaintext0[MAX_CHOSEN_PAIRS];
ull ciphertext0[MAX_CHOSEN_PAIRS];
ull plaintext1[MAX_CHOSEN_PAIRS];
ull ciphertext1[MAX_CHOSEN_PAIRS];

inline uint getLeftHalf(ull x) {
    return x >> 32;
}

inline uint getRightHalf(ull x) {
    return x & 0xFFFFFFFFULL;
}

inline ull getCombinedHalves(uint a, uint b) {
    return (ull(a)<<32) | (ull(b) & 0xFFFFFFFFULL);
}

inline uint32_t ROT2(uint32_t x) {
    return ((x) << 2) | ((x) >> 6);
}

inline BYTE G0(BYTE a, BYTE b) {
    return ROT2(static_cast<BYTE>((a + b)%256));
}

inline BYTE G1(BYTE a, BYTE b) {
    return ROT2(static_cast<BYTE>((a + b + 1)%256));
}

inline uint32_t pack32(const BYTE* b) {
    return static_cast<uint32_t>(b[3]) | (static_cast<uint32_t>(b[2]) << 8) |
           (static_cast<uint32_t>(b[1]) << 16) | (static_cast<uint32_t>(b[0]) << 24);
}

inline void unpack32(uint32_t a, BYTE* b) {
    b[0] = static_cast<BYTE>(a >> 24);
    b[1] = static_cast<BYTE>(a >> 16);
    b[2] = static_cast<BYTE>(a >> 8);
    b[3] = static_cast<BYTE>(a);
}

uint32_t f(uint32_t input) {
    BYTE x[4], y[4];
    unpack32(input, x);
    y[1] = G1(x[1] ^ x[0], x[2] ^ x[3]);
    y[0] = G0(x[0], y[1]);
    y[2] = G0(y[1], x[2] ^ x[3]);
    y[3] = G1(y[2], x[3]);
    return pack32(y);
}

// M function for two-phase attack
inline uint32_t M(uint32_t x) {
    uint32_t a0 = (x >> 24) & 0xFF;
    uint32_t a1 = (x >> 16) & 0xFF;
    uint32_t a2 = (x >> 8) & 0xFF;
    uint32_t a3 = x & 0xFF;
    return (0x00 << 24) | ((a0 ^ a1) << 16) | ((a2 ^ a3) << 8) | 0x00;
}

// Primary phase of the attack
vector<uint32_t> primaryPhase(uint differential) {
    vector<uint32_t> candidate_A_values;
    bool first_pair = true;

    for (int i = 0; i < num_plaintexts; i++) {
        uint32_t L0 = getLeftHalf(ciphertext0[i]);
        uint32_t R0 = getRightHalf(ciphertext0[i]);
        uint32_t L1 = getLeftHalf(ciphertext1[i]);
        uint32_t R1 = getRightHalf(ciphertext1[i]);

        uint32_t L_prime = L0 ^ L1;
        uint32_t Z_prime = L_prime ^ differential;

        vector<uint32_t> pair_candidates;

        for (uint32_t a0 = 0x00; a0 <= 0xFF; ++a0) {
            for (uint32_t a1 = 0x00; a1 <= 0xFF; ++a1) {
                uint32_t A = (a0 << 8) | a1;

                uint32_t Q0 = f(M(R0) ^ (0x00 << 24 | a0 << 16 | a1 << 8 | 0x00));
                uint32_t Q1 = f(M(R1) ^ (0x00 << 24 | a0 << 16 | a1 << 8 | 0x00));

                if (((Q0 ^ Q1) & 0x00FFFF00) == (Z_prime & 0x00FFFF00)) {
                    pair_candidates.push_back(A);
                }
            }
        }

        if (first_pair) {
            candidate_A_values = pair_candidates;
            first_pair = false;
        } else {
            vector<uint32_t> common_candidates;
            for (uint32_t value : candidate_A_values) {
                if (find(pair_candidates.begin(), pair_candidates.end(), value) != pair_candidates.end()) {
                    common_candidates.push_back(value);
                }
            }
            candidate_A_values = common_candidates;
        }
    }

    return candidate_A_values;
}

// Secondary phase of the attack
vector<uint32_t> secondaryPhase(const vector<uint32_t>& primary_candidates, uint differential) {
    vector<uint32_t> final_candidates;
    
    for (uint32_t A : primary_candidates) {
        uint32_t a0 = (A >> 8) & 0xFF;
        uint32_t a1 = A & 0xFF;
        
        for (uint32_t c0 = 0; c0 <= 0xFF; c0++) {
            for (uint32_t c1 = 0; c1 <= 0xFF; c1++) {
                uint32_t K = (c0 << 24) | ((a0 ^ c0) << 16) | ((a1 ^ c1) << 8) | c1;
                bool valid = true;
                
                for (int i = 0; i < num_plaintexts && valid; i++) {
                    uint32_t Y0 = getRightHalf(ciphertext0[i]);
                    uint32_t Y1 = getRightHalf(ciphertext1[i]);
                    uint32_t L_prime = getLeftHalf(ciphertext1[i]) ^ getLeftHalf(ciphertext0[i]);
                    uint32_t Z_prime = L_prime ^ differential;
                    
                    uint32_t Z0 = f(Y0 ^ K);
                    uint32_t Z1 = f(Y1 ^ K);
                    
                    if ((Z0 ^ Z1) != Z_prime) {
                        valid = false;
                        break;
                    }
                }
                
                if (valid) {
                    final_candidates.push_back(K);
                }
            }
        }
    }
    
    return final_candidates;
}

vector<uint32_t> crackHighestRound(uint differential) {
    cout << "  Using output differential of 0x" << hex << differential << dec << "\n";
    cout << "  Cracking using two-phase attack...\n";

    vector<uint32_t> primary_candidates = primaryPhase(differential);
    cout << "  Primary phase found " << primary_candidates.size() << " candidates\n";
    
    vector<uint32_t> final_candidates = secondaryPhase(primary_candidates, differential);
    cout << "  Secondary phase found " << final_candidates.size() << " candidates\n";
    
    return final_candidates;
}

unordered_map<ull, vector<vector<ull>>> cache;
void generatePlaintextCiphertextPairs(ull inputDiff) {
    if(cache.find(inputDiff) != cache.end()){
        for(int i=0; i<12; i++){
            plaintext0[i] = cache[inputDiff][0][i];
            plaintext1[i] = cache[inputDiff][1][i];
            ciphertext0[i] = cache[inputDiff][2][i];
            ciphertext1[i] = cache[inputDiff][3][i];
        }
        return;
    }
    cout << "Generating " << num_plaintexts << " plaintext-ciphertext pairs\n";
    cout << "Using input differential 0x" << hex << inputDiff << dec << "\n";

    srand(time(NULL));

    for (int i = 0; i < num_plaintexts; i++) {
        plaintext0[i] = (rand() & 0xFFFFULL) << 48;
        plaintext0[i] += (rand() & 0xFFFFULL) << 32;
        plaintext0[i] += (rand() & 0xFFFFULL) << 16;
        plaintext0[i] += (rand() & 0xFFFFULL);
        plaintext1[i] = plaintext0[i] ^ inputDiff;
    }

    cout << "\nGenerated plaintext0 and plaintext1 pairs (in hex):\n";
    cout << "Plaintext0: ";
    for (int i = 0; i < num_plaintexts; i++) {
        cout << hex << plaintext0[i] << (i < num_plaintexts - 1 ? ", " : "\n");
    }

    cout << "Plaintext1: ";
    for (int i = 0; i < num_plaintexts; i++) {
        cout << hex << plaintext1[i] << (i < num_plaintexts - 1 ? ", " : "\n");
    }

    cout << "\nEnter the corresponding ciphertexts (comma-separated, in hex):\n";
    string input;
    getline(cin, input);

    stringstream ss(input);
    string token;
    int index = 0;

    while (getline(ss, token, ',')) {
        token.erase(remove_if(token.begin(), token.end(), ::isspace), token.end());
        if (token.empty()) continue;

        unsigned long long cipherText = stoull(token, nullptr, 16);
        if (index < num_plaintexts) {
            ciphertext0[index] = cipherText;
        } else {
            ciphertext1[index - num_plaintexts] = cipherText;
        }
        index++;
    }
    vector<ull> temp;
    for(int i=0; i<12; i++){
        temp.push_back(plaintext0[i]);
    }
    cache[inputDiff].push_back(temp);
    temp.clear();
    for(int i=0; i<12; i++){
        temp.push_back(plaintext1[i]);
    }
    cache[inputDiff].push_back(temp);
    temp.clear();
    for(int i=0; i<12; i++){
        temp.push_back(ciphertext0[i]);
    }
    cache[inputDiff].push_back(temp);
    temp.clear();
    for(int i=0; i<12; i++){
        temp.push_back(ciphertext1[i]);
    }
    cache[inputDiff].push_back(temp);
    temp.clear();

    cout << "\nCiphertext0: ";
    for (int i = 0; i < num_plaintexts; i++) {
        cout << hex << ciphertext0[i] << (i < num_plaintexts - 1 ? ", " : "\n");
    }

    cout << "Ciphertext1: ";
    for (int i = 0; i < num_plaintexts; i++) {
        cout << hex << ciphertext1[i] << (i < num_plaintexts - 1 ? ", " : "\n");
    }
}

void decryptLastOperation() {
    for(int i = 0; i < num_plaintexts; i++) {
        uint cipherLeft0 = getLeftHalf(ciphertext0[i]);
        uint cipherRight0 = getRightHalf(ciphertext0[i]) ^ cipherLeft0;
        uint cipherLeft1 = getLeftHalf(ciphertext1[i]);
        uint cipherRight1 = getRightHalf(ciphertext1[i]) ^ cipherLeft1; 
        
        ciphertext0[i] = getCombinedHalves(cipherLeft0, cipherRight0);   
        ciphertext1[i] = getCombinedHalves(cipherLeft1, cipherRight1);
    }   
}

void decryptHighestRound(uint crackedKey) {
    for(int i = 0; i < num_plaintexts; i++) {
        uint cipherLeft0 = getRightHalf(ciphertext0[i]);
        uint cipherLeft1 = getRightHalf(ciphertext1[i]);
        
        uint cipherRight0 = f(cipherLeft0 ^ crackedKey) ^ getLeftHalf(ciphertext0[i]);
        uint cipherRight1 = f(cipherLeft1 ^ crackedKey) ^ getLeftHalf(ciphertext1[i]);
        
        ciphertext0[i] = getCombinedHalves(cipherLeft0, cipherRight0);
        ciphertext1[i] = getCombinedHalves(cipherLeft1, cipherRight1);     
    }
}

int main(int argc, char **argv) {
    cout << "Differential Cryptanalysis of FEAL-4 (Two-Phase Attack)\n\n";

    if (argc == 1) {
        num_plaintexts = 12;
    } else if (argc == 2) {
        num_plaintexts = atoi(argv[1]);
    } else {
        cout << "Usage: " << argv[0] << " [Number of chosen plaintexts]\n";
        return 0;
    }

    uint startTime = time(NULL);

    // Round 4
    cout << "Round 4: To find K3\n\n";
    generatePlaintextCiphertextPairs(0x8080000080800000ULL);
    decryptLastOperation();

    uint roundStartTime = time(NULL);
    vector<uint32_t> candidates3 = crackHighestRound(0x02000000U);
    
    cout << "  Found " << candidates3.size() << " candidates for K3\n";
    for (uint32_t candidate : candidates3) {
        cout << "    Candidate K3: 0x" << hex << candidate << dec << "\n";
    }
    uint roundEndTime = time(NULL);
    cout << "  Time to crack round #4 = " << int(roundEndTime - roundStartTime) << " seconds\n\n";

    // Iterate over all candidates for K3
    for (uint32_t crackedKey3 : candidates3) {
        cout << "Testing K3 = 0x" << hex << crackedKey3 << "\n";

        // Round 3
        cout << "Round 3: To find K2\n";
        generatePlaintextCiphertextPairs(0x0000000080800000ULL);
        decryptLastOperation();
        decryptHighestRound(crackedKey3);

        roundStartTime = time(NULL);
        vector<uint32_t> candidates2 = crackHighestRound(0x02000000U);
        if (candidates2.empty()) {
            cout << "  Failed to find K2 for K3 = 0x" << hex << crackedKey3 << "\n";
            continue;
        }
        cout << "  Found " << candidates2.size() << " candidates for K2\n";
        for (uint32_t candidate : candidates2) {
            cout << "    Candidate K2: 0x" << hex << candidate << dec << "\n";
        }
        roundEndTime = time(NULL);
        cout << "  Time to crack round #3 = " << int(roundEndTime - roundStartTime) << " seconds\n\n";

        // Iterate over all candidates for K2
        for (uint32_t crackedKey2 : candidates2) {
            cout << "Testing K2 = 0x" << hex << crackedKey2 << " with K3 = 0x" << crackedKey3 << "\n";

            // Round 2
            cout << "Round 2: To find K1\n";
            generatePlaintextCiphertextPairs(0x0000000002000000LL);
            decryptLastOperation();
            decryptHighestRound(crackedKey3);
            decryptHighestRound(crackedKey2);

            roundStartTime = time(NULL);
            vector<uint32_t> candidates1 = crackHighestRound(0x02000000U);
            if (candidates1.empty()) {
                cout << "  Failed to find K1 for K2 = 0x" << hex << crackedKey2 << " and K3 = 0x" << crackedKey3 << "\n";
                continue;
            }
            cout << "  Found " << candidates1.size() << " candidates for K1\n";
            for (uint32_t candidate : candidates1) {
                cout << "    Candidate K1: 0x" << hex << candidate << dec << "\n";
            }
            roundEndTime = time(NULL);
            cout << "  Time to crack round #2 = " << int(roundEndTime - roundStartTime) << " seconds\n\n";

            // Iterate over all candidates for K1
            for (uint32_t crackedKey1 : candidates1) {
                cout << "Testing K1 = 0x" << hex << crackedKey1 << " with K2 = 0x" << crackedKey2 << " and K3 = 0x" << crackedKey3 << "\n";

                // Round 1
                cout << "Round 1: To find K0\n";
                generatePlaintextCiphertextPairs(0x0000000002000000LL);
                decryptLastOperation();
                decryptHighestRound(crackedKey3);
                decryptHighestRound(crackedKey2);
                decryptHighestRound(crackedKey1);

                for(ull guessK0 = 0; guessK0 < 0xFFFFFFFFL; guessK0++)
                {
                    unsigned long guessK4 = 0;
                    unsigned long guessK5 = 0;
                    int c;
                    for(c = 0; c < 12; c++)
                    {
                            unsigned long plainLeft0 = getLeftHalf(plaintext0[c]);
                            unsigned long plainRight0 = getRightHalf(plaintext0[c]);
                            unsigned long cipherLeft0 = getLeftHalf(ciphertext0[c]);
                            unsigned long cipherRight0 = getRightHalf(ciphertext0[c]);
                            
                            unsigned long tempy0 = f(cipherRight0 ^ guessK0) ^ cipherLeft0;
                            if (guessK4 == 0)
                            {
                            guessK4 = tempy0 ^ plainLeft0;
                            guessK5 = tempy0 ^ cipherRight0 ^ plainRight0;
                            }
                            else if (((tempy0 ^ plainLeft0) != guessK4) || ((tempy0 ^ cipherRight0 ^ plainRight0) != guessK5))
                            {
                                guessK4 = 0;
                                guessK5 = 0;
                                break; 	 
                            }
                    }
                    if (guessK4 != 0)
                    {

                        ull crackedSubkey0 = guessK0;
                        ull crackedSubkey4 = guessK4;
                        ull crackedSubkey5 = guessK5;
                        
                        ofstream fileOut("keys.txt", ofstream::app); // Open in append mode
                        
                        fileOut << hex << guessK0 << "," << crackedKey1 << "," << crackedKey2 <<"," << crackedKey3 << "," <<guessK4 << "," << guessK5 << endl;
                        fileOut.close();
                        cout  << "found subkeys : " << guessK0 << " " << guessK4 << " " << guessK5;
                    
                    }	  
                }
            }
        }
    }

    cout << "Exhausted all candidates without recovering a valid full key.\n";
    uint endTime = time(NULL);
    cout << "\nTotal attack time: " << int(endTime - startTime) << " seconds\n";
    return 0;
}