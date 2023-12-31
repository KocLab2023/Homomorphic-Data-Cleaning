#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <gmp.h>
#include <ctime>
#include <typeinfo>


#include "paillier.h"
#include "soci.h"

using namespace std;
using namespace phe;
using namespace soci;

#define KEY_LEN_BIT 512
#define SIGMA_LEN_BIT 128
#define ROW 70000 // 70000 for dataset1, 17396 for dataset2
#define COL 4 // 4 for dataset1, 2 for dataset2
#define SEL_DATASET 1   // 1 for dataset1, 2 for dataset2


class ciphertext {
public:
    mpz_t ct;
    ciphertext(const mpz_t& value) {
        mpz_init_set(ct, value);
    }

    ciphertext(const ciphertext& other) {
        mpz_init_set(ct, other.ct);
    }

    ciphertext& operator=(const ciphertext& other) {
        if (this != &other) {
            mpz_set(ct, other.ct);
        }
        return *this;
    }

    ~ciphertext() {
        mpz_clear(ct);
    }

// private:
    
};

struct Error_index
{
    vector<ciphertext> uprange;
    vector<ciphertext> downrange;
};

vector<vector<int>> readdata(const string& filename){
    vector<vector<int>> matrix(ROW, vector<int>(COL));
    ifstream file(filename);

    if (!file.is_open()) {
        cerr << "Could not open the file!" << endl;
        return matrix;
    }

    string line;
    int row = 0;
    while (getline(file, line)) {
        stringstream ss(line);
        for (int col = 0; col < COL; ++col) {
            string val;
            getline(ss, val, ',');
            
            matrix[row][col] = stoi(val);
        }
        ++row;
        if (row>ROW-1){
            break;
        }
    }

    file.close();
    return matrix;

}

vector<ciphertext> encrypt_mat1(const vector<vector<int>>& plaintext, Paillier& pai) {
    vector<ciphertext> ciphertext_vector;
    for (int j = 0; j<COL; ++j){
        for (int i = 0; i < ROW; ++i) {
            mpz_t x,cx;
            mpz_inits(x,cx,NULL);
            mpz_set_si(x, plaintext[i][j]);
            pai.encrypt(cx, x);
            ciphertext ct(cx);
            ciphertext_vector.push_back(ct);
            // ct.~ciphertext();

            mpz_clears(x,NULL);
        }
    }
    // mpz_clears(cx,NULL);
    return ciphertext_vector;
}

vector<ciphertext> encrypt_range(int* plaintext_range, Paillier& pai) {
    vector<ciphertext> ciphertext_range;
    mpz_t x,cx,z0;
    mpz_inits(x,cx,z0,NULL);
    for (int i =0;i<COL*2 ;++i){
        mpz_set_si(x, plaintext_range[i]);
        pai.encrypt(cx, x);
        ciphertext ct(cx);
        ciphertext_range.push_back(ct);
    }
    // pai.decrypt(z0, ciphertext_range[0].ct);
    // gmp_printf("data= %Zd\n", z0);
    return ciphertext_range;   
}

vector<string> transform_keypairs_to_str(Paillier& pai, PaillierThd& cs){
    char* str_g = mpz_get_str(nullptr,10,pai.pubkey.g);
    cout<<"str_g = "<<str_g<<endl;
    char* str_n = mpz_get_str(nullptr,10,pai.pubkey.n);
    cout<<"str_n = "<<str_n<<endl;
    char* str_nsquare = mpz_get_str(nullptr,10,pai.pubkey.nsquare);
    cout<<"str_nsquare = "<<str_nsquare<<endl;
    char* str_cs_sk = mpz_get_str(nullptr,10,cs.psk.sk);
    cout<<"str_cs_sk = "<<str_cs_sk<<endl;
    // char* str_csp_sk = mpz_get_str(nullptr,10,csp.psk.sk);
    // cout<<"str_csp_sk = "<<str_csp_sk<<endl;


    vector<string> cs_keypairs = {str_g, str_n, str_nsquare, str_cs_sk};
    // vector<string> csp_keypairs = {str_g, str_n, str_nsquare, str_csp_sk};

    return cs_keypairs;
}

int write_strings_in_file(string filename, vector<string>& str_vector){
    ofstream file(filename);
    if (file.is_open()) {
        for (const auto&  str : str_vector) {
            file << str << ",\n"; 
        }
        file.close(); 
        std::cout << "All strings successfully stored in file." << std::endl;
    } else {
        std::cout << "Failed to open file." << std::endl;
    }
    return 0;
}

int generate_keypair_files_for_CP_CSP(Paillier& pai, PaillierThd& cp, PaillierThd& csp){
    vector<string> cp_keypairs = transform_keypairs_to_str(pai, cp);
    vector<string> csp_keypairs = transform_keypairs_to_str(pai, csp);

    string cp_filename = "/home/husen/vscode/soci-main/encrypted data and key pairs/cp_keypairs.txt";
    string csp_filename = "/home/husen/vscode/soci-main/encrypted data and key pairs/csp_keypairs.txt";

    write_strings_in_file(cp_filename, cp_keypairs);
    write_strings_in_file(csp_filename, csp_keypairs);
    return 0;
}


vector<string> transform_ciphertexts_to_str(vector<ciphertext>& ciphertext_vector){
    vector<string> ciphertexts_string;
    for(const auto& ct : ciphertext_vector){
        char* str_ct = mpz_get_str(nullptr,10,ct.ct);
        // cout<<str_ct<<endl;
        ciphertexts_string.push_back(str_ct);
    }

    return ciphertexts_string;
}

vector<ciphertext> encrypted_distance(vector<ciphertext>ciphertext_vector, Paillier& pai) {
    vector<ciphertext> distance_vector;
    // ciphertext cc;
    for (int i=0; i<COL; ++i){
        for (int j = 0; j<(ROW-1); ++j){
            mpz_t cz,z0,inv;
            mpz_inits(cz,z0,inv,NULL);
            ciphertext& cx = ciphertext_vector[ROW*i+j];
            ciphertext& cy = ciphertext_vector[ROW*i+j+1];
            
            // pai.decrypt(z0, cx.ct);
            // gmp_printf("data= %Zd\n", z0);
            // pai.decrypt(z0, cy.ct);
            // gmp_printf("data= %Zd\n", z0);

            // mpz_powm(cx.ct,cy.ct,pai.pubkey.n-1,pai.pubkey.nsquare);
            mpz_invert(inv,cy.ct,pai.pubkey.nsquare);
            // pai.decrypt(z0, cx.ct);
            // gmp_printf("data= %Zd\n", z0);

            pai.add(cz,cx.ct,inv);
            ciphertext cc(cz);
            // pai.decrypt(z0, cc.ct);
            // gmp_printf("data= %Zd\n", z0);
            distance_vector.push_back(cc);
        
        
        }
        mpz_t m0,c0;
        mpz_inits(m0,c0,NULL);
        mpz_set_si(m0,0);
        pai.encrypt(c0,m0);
        ciphertext ccc(c0);
        distance_vector.push_back(ccc);
    }
    
    // mpz_clears(cx,NULL);
    return distance_vector;
}




int user_processing_CD_dataset(){
    setrandom();
	Paillier pai;
    pai.keygen(KEY_LEN_BIT);

    int sigma = SIGMA_LEN_BIT;
	PaillierThd cp;
	PaillierThd csp;
	ThirdKeyGen tkg;
	tkg.thdkeygen(pai, sigma, &cp, &csp);

    // transform mpz numbers into str, then sort them in two files for CP and CSP...
    generate_keypair_files_for_CP_CSP(pai,cp,csp);


	clock_t start_time;
	clock_t end_time;

    start_time = clock();
    string filename = "/home/husen/vscode/soci-main/Data-Sets/Cardiovascular-Disease-Data-Set.csv"; 
    vector<vector<int>> data = readdata(filename);
    end_time = clock();
    printf("read data time is  ------  %f s\n", ((double)(end_time - start_time)) / 1  / CLOCKS_PER_SEC);

    // 对数据进行加密
    start_time = clock();
    vector<ciphertext> ciphertext_vector = encrypt_mat1(data, pai);
    end_time = clock();
    printf("encrypt data time is  ------  %f s\n", ((double)(end_time - start_time)) / 1  / CLOCKS_PER_SEC);

    start_time = clock();
    int plaintext_range[8]={0,300,0,400,0,300,0,200};
    vector<ciphertext> ciphertext_range = encrypt_range(plaintext_range, pai);
    end_time = clock();
    printf("encrypt range time is  ------  %f s\n", ((double)(end_time - start_time)) / 1  / CLOCKS_PER_SEC);

    //ciphertext_vector,,ciphertext_range  
    vector<string> ciphertexts_string = transform_ciphertexts_to_str(ciphertext_vector);
    string ciphertexts_filename = "/home/husen/vscode/soci-main/encrypted data and key pairs/encrypted_CD_dataset.txt";
    write_strings_in_file(ciphertexts_filename, ciphertexts_string);

    vector<string> cipher_range_string = transform_ciphertexts_to_str(ciphertext_range);
    string cipher_range_filename = "/home/husen/vscode/soci-main/encrypted data and key pairs/encrypted_range_for_CD_dataset.txt";
    write_strings_in_file(cipher_range_filename, cipher_range_string);

    return 0;
}

int user_processing_GeoLife_dataset(){
    setrandom();
	Paillier pai;
    pai.keygen(KEY_LEN_BIT);

    int sigma = SIGMA_LEN_BIT;
	PaillierThd cp;
	PaillierThd csp;
	ThirdKeyGen tkg;
	tkg.thdkeygen(pai, sigma, &cp, &csp);

    // transform mpz numbers into str, then sort them in two files for CP and CSP...
    generate_keypair_files_for_CP_CSP(pai,cp,csp);


	clock_t start_time;
	clock_t end_time;

    start_time = clock();
    string filename = "/home/husen/vscode/soci-main/Data-Sets/GeoLife-GPS-Trajectories-Data-Set.csv"; ///home/husen/vscode/soci-main/
    vector<vector<int>> data = readdata(filename);
    end_time = clock();
    printf("read data time is  ------  %f s\n", ((double)(end_time - start_time)) / 1  / CLOCKS_PER_SEC);

    // 对数据进行加密
    start_time = clock();
    vector<ciphertext> ciphertext_vector = encrypt_mat1(data, pai);
    vector<ciphertext> ciphertext_dv = encrypted_distance(ciphertext_vector, pai);
    end_time = clock();
    printf("encrypt data time is  ------  %f s\n", ((double)(end_time - start_time)) / 1  / CLOCKS_PER_SEC);

    start_time = clock();
    int plaintext_range[8]={0,10000,0,10000};
    vector<ciphertext> ciphertext_range = encrypt_range(plaintext_range, pai);
    end_time = clock();
    printf("encrypt range time is  ------  %f s\n", ((double)(end_time - start_time)) / 1  / CLOCKS_PER_SEC);

    //ciphertext_vector,,ciphertext_range  
    vector<string> ciphertexts_string = transform_ciphertexts_to_str(ciphertext_dv);
    string ciphertexts_filename = "/home/husen/vscode/soci-main/encrypted data and key pairs/encrypted_GeoLife_dataset.txt";
    write_strings_in_file(ciphertexts_filename, ciphertexts_string);

    vector<string> cipher_range_string = transform_ciphertexts_to_str(ciphertext_range);
    string cipher_range_filename = "/home/husen/vscode/soci-main/encrypted data and key pairs/encrypted_range_for_GeoLife_dataset(0.01).txt";
    write_strings_in_file(cipher_range_filename, cipher_range_string);

    return 0;
}

int main() {
    if (SEL_DATASET ==1){
        user_processing_CD_dataset();
    }
    else if (SEL_DATASET == 2){
        user_processing_GeoLife_dataset();
    }
    else {
        cout<<"error select of dataset"<< endl;
    }

    
        
    return 0;
}

// sort pai
    // char* str_g = mpz_get_str(nullptr,10,pai.pubkey.g);
    // cout<<"str_g = "<<str_g<<endl;
    // char* str_n = mpz_get_str(nullptr,10,pai.pubkey.n);
    // cout<<"str_n = "<<str_n<<endl;
    // char* str_nsquare = mpz_get_str(nullptr,10,pai.pubkey.nsquare);
    // cout<<"str_nsquare = "<<str_nsquare<<endl;
    // char* str_sk = mpz_get_str(nullptr,10,cp.psk.sk);
    // cout<<"str_sk = "<<str_sk<<endl;


    // mpz_t mpz_g;
    // mpz_init_set_str(mpz_g,str_g,10);
    // mpz_t mpz_n;
    // mpz_init_set_str(mpz_n,str_n,10);
    // mpz_t mpz_nsquare;
    // mpz_init_set_str(mpz_nsquare,str_nsquare,10);
    // mpz_t mpz_cs_sk;
    // mpz_init_set_str(mpz_cs_sk,str_sk,10);


    // PaillierKey pai_pub{mpz_g, mpz_n, mpz_nsquare};
    

    // char* str_lambda = mpz_get_str(nullptr,10,pai.prikey.lambda);
    // cout<<"str_lambda = "<<str_lambda<<endl;
    
    // mpz_t mpz_lambda;
    // mpz_init_set_str(mpz_lambda,str_lambda,10);

    // PaillierPrivateKey pai_pri;
    // PaillierPrivateKey pai_pri(mpz_n, mpz_lambda);
    // Paillier pai_re(pai_pub, pai_pri);

    // PaillierThdPrivateKey cs_psk;
    // PaillierThdPrivateKey* cs_psk = NULL;
    // cs_psk = PaillierThdPrivateKey(mpz_cs_sk, mpz_n, mpz_nsquare);

    // PaillierThd cs_read(cs_psk, pai_pub);