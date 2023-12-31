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

vector<string> read_strings_in_file(string filename){
    ifstream file(filename); 
        if (file.is_open()) {
            string line;
            vector<string> read_strings;

            while (getline(file, line)) {

                if (!line.empty() && line.back() == ',') {
                    line.pop_back();
                }
                if (!line.empty() && line.back() == '\n') {
                    line.pop_back(); 
                }
                read_strings.push_back(line); 
            }

            // std::cout << "Read strings from file:" << std::endl;
            // for (const auto& s : read_strings) {
            //     std::cout << s << std::endl; 
            // }
            return read_strings;
        } else {
            std::cout << "Failed to open file." << std::endl;
            vector<string> empty_strings;
            return empty_strings;
        }
    
}

// read mpz numbers from str file....
PaillierThd transform_str_to_server_keypair(vector<string>& cs_keypairs){
    setrandom();
    mpz_t mpz_g, mpz_n, mpz_nsquare, mpz_cs_sk;
    string str_g = cs_keypairs.at(0);
    string str_n = cs_keypairs.at(1);
    string str_nsq = cs_keypairs.at(2);
    string str_sk = cs_keypairs.at(3);
    
    mpz_init_set_str(mpz_g,str_g.c_str(),10);
    mpz_init_set_str(mpz_n,str_n.c_str(),10);
    mpz_init_set_str(mpz_nsquare,str_nsq.c_str(),10);
    mpz_init_set_str(mpz_cs_sk,str_sk.c_str(),10);


    // PaillierThdPrivateKey* cp_psk = NULL;
    // cp_psk = new PaillierThdPrivateKey(mpz_cp_sk, mpz_n, mpz_nsquare);
    

    PaillierThdPrivateKey cs_psk;
    cs_psk = PaillierThdPrivateKey(mpz_cs_sk, mpz_n, mpz_nsquare);

    PaillierKey pubkey{mpz_g, mpz_n, mpz_nsquare};
    

    PaillierThd cs_read(cs_psk, pubkey);
    return cs_read;
}    

vector<ciphertext> transform_str_to_ciphertext_vector(vector<string>& string_vector){
    vector<ciphertext> ciphertexts_vector;
    mpz_t mpz_temp;
    for (const auto& str : string_vector){
        mpz_init_set_str(mpz_temp,str.c_str(),10);
        ciphertext cc(mpz_temp);
        ciphertexts_vector.push_back(cc);
    }

    return ciphertexts_vector;
} 

Error_index data_cleaning(vector<ciphertext>ciphertext_vector, vector<ciphertext>range,PaillierThd& cp, PaillierThd& csp){
    // setrandom();
    Error_index error_index_vector;
    // vector<ciphertext> error_index_vector0, error_index_vector1;
    seccomp sc;
    mpz_t cz0,cz1,z0,z1,cd_sq;
    mpz_inits(cz0,cz1,z0,z1,cd_sq,NULL);
    for (int j = 0; j<COL; ++j){
        ciphertext& ct_range0 = range[j*2];
        ciphertext& ct_range1 = range[j*2+1];
        for (int i = 0; i < ROW; ++i) {
            ciphertext& ct_data = ciphertext_vector[j*ROW+i];
            
            sc.scmp(cz0, ct_data.ct,ct_range0.ct, cp, csp);
            
            ciphertext ct0(cz0);
            error_index_vector.downrange.push_back(ct0);

            sc.scmp(cz1, ct_range1.ct, ct_data.ct, cp, csp);
            
            ciphertext ct1(cz1);
            error_index_vector.uprange.push_back(ct1);
        }
    }
    mpz_clears(cz0,cz1,z0,z1,NULL);

    return error_index_vector;
}

Error_index data_cleaning2(vector<ciphertext>ciphertext_vector, vector<ciphertext>range, PaillierThd& cp, PaillierThd& csp){
    Error_index error_index_vector;
    // vector<ciphertext> error_index_vector0, error_index_vector1;
    seccomp sc;
    mpz_t cz0,cz1,z0,z1,cd_sq;
    mpz_inits(cz0,cz1,z0,z1,cd_sq,NULL);
    for (int j = 0; j<COL; ++j){
        ciphertext& ct_range0 = range[j*2];
        ciphertext& ct_range1 = range[j*2+1];
        for (int i = 0; i < ROW; ++i) {
            ciphertext& ct_data = ciphertext_vector[j*ROW+i];
            // pai.decrypt(z0, ct_data.ct);
            // gmp_printf("data= %Zd\n", z0);
            
            sc.smul(cd_sq,ct_data.ct,ct_data.ct,cp,csp);
            ciphertext cc(cd_sq);
            // pai.decrypt(z0, cc.ct);
            // gmp_printf("data**2= %Zd\n", z0);

            sc.scmp(cz0, cc.ct,ct_range0.ct, cp, csp);
            // pai.decrypt(z0, cz0);
            // gmp_printf("out of range0? %Zd\n", z0);
            ciphertext ct0(cz0);
            error_index_vector.downrange.push_back(ct0);

            sc.scmp(cz1, ct_range1.ct, cc.ct, cp, csp);
            // pai.decrypt(z1, cz1);
            // gmp_printf("out of range1? %Zd\n", z1);
            ciphertext ct1(cz1);
            error_index_vector.uprange.push_back(ct1);
        }
    }
    mpz_clears(cz0,cz1,z0,z1,NULL);

    return error_index_vector;
}


vector<int> obtain_error_id(Error_index error_index_vector, Paillier& pai){
    vector<int> error_data_index;
    mpz_t z0,z1;
    mpz_inits(z0,z1,NULL);
    for (int i =0; i<ROW*COL;++i){
        ciphertext& ct_res0 = error_index_vector.downrange[i];
        ciphertext& ct_res1 = error_index_vector.uprange[i];
        pai.decrypt(z0, ct_res0.ct);
        pai.decrypt(z1, ct_res1.ct);

        if (mpz_cmp_ui(z0,0)==1){
            error_data_index.push_back(i);
        }
        if(mpz_cmp_ui(z1,0)==1){
            error_data_index.push_back(i);
        }
        
    }
    mpz_clears(z0,z1,NULL);
    return error_data_index;
}
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

int write_strings_in_file(string filename, vector<string>& str_vector){
    ofstream file(filename);
    if (file.is_open()) {
        for (const auto&  str : str_vector) {
            file << str << ",\n"; 
        }
        file.close();
        std::cout << "All keypairs successfully stored in file." << std::endl;
    } else {
        std::cout << "Failed to open file." << std::endl;
    }
    return 0;
}

Error_index cloud_server_receive_keypairs_ciphertexts_CD_dataset(){

    string cp_filename = "/home/husen/vscode/soci-main/encrypted data and key pairs/cp_keypairs.txt";
    string csp_filename = "/home/husen/vscode/soci-main/encrypted data and key pairs/csp_keypairs.txt";
    vector<string> cp_keypairs = read_strings_in_file(cp_filename);
    vector<string> csp_keypairs = read_strings_in_file(csp_filename);
    PaillierThd cp = transform_str_to_server_keypair(cp_keypairs);
    PaillierThd csp = transform_str_to_server_keypair(csp_keypairs);

    string CD_filename = "/home/husen/vscode/soci-main/encrypted data and key pairs/encrypted_CD_dataset.txt";
    vector<string> ciphertext_string_vector = read_strings_in_file(CD_filename);
    vector<ciphertext> ciphertexts_vector = transform_str_to_ciphertext_vector(ciphertext_string_vector);

    string CD_range_filename = "/home/husen/vscode/soci-main/encrypted data and key pairs/encrypted_range_for_CD_dataset.txt";
    vector<string> cipher_range_string_vector = read_strings_in_file(CD_range_filename);
    vector<ciphertext> cipher_ranges_vector = transform_str_to_ciphertext_vector(cipher_range_string_vector);
    

    clock_t start_time;
	clock_t end_time;


    start_time = clock();
    Error_index error_index_vector =  data_cleaning(ciphertexts_vector, cipher_ranges_vector, cp, csp);
    end_time = clock();
    printf("data cleaning time is  ------  %f s\n", ((double)(end_time - start_time)) / 1  / CLOCKS_PER_SEC);

    return error_index_vector;
}

Error_index cloud_server_receive_keypairs_ciphertexts_GeoLife_dataset(){

    string cp_filename = "/home/husen/vscode/soci-main/encrypted data and key pairs/cp_keypairs.txt";
    string csp_filename = "/home/husen/vscode/soci-main/encrypted data and key pairs/csp_keypairs.txt";
    vector<string> cp_keypairs = read_strings_in_file(cp_filename);
    vector<string> csp_keypairs = read_strings_in_file(csp_filename);
    PaillierThd cp = transform_str_to_server_keypair(cp_keypairs);
    PaillierThd csp = transform_str_to_server_keypair(csp_keypairs);

    string GeoLife_filename = "/home/husen/vscode/soci-main/encrypted data and key pairs/encrypted_GeoLife_dataset.txt";
    vector<string> ciphertext_string_vector = read_strings_in_file(GeoLife_filename);
    vector<ciphertext> ciphertexts_vector = transform_str_to_ciphertext_vector(ciphertext_string_vector);

    string GeoLife_range_filename = "/home/husen/vscode/soci-main/encrypted data and key pairs/encrypted_range_for_GeoLife_dataset(0.01).txt";
    vector<string> cipher_range_string_vector = read_strings_in_file(GeoLife_range_filename);
    vector<ciphertext> cipher_ranges_vector = transform_str_to_ciphertext_vector(cipher_range_string_vector);
    

    clock_t start_time;
	clock_t end_time;


    start_time = clock();
    Error_index error_index_vector =  data_cleaning2(ciphertexts_vector, cipher_ranges_vector, cp, csp);
    end_time = clock();
    printf("data cleaning time is  ------  %f s\n", ((double)(end_time - start_time)) / 1  / CLOCKS_PER_SEC);

    return error_index_vector;
}

int user_print_errors(Error_index& error_index_vector){
    setrandom();
	Paillier pai;
    pai.keygen(KEY_LEN_BIT);

    clock_t start_time;
	clock_t end_time;

    string filename = "/home/husen/vscode/soci-main/Data-Sets/Cardiovascular-Disease-Data-Set.csv"; 
    vector<vector<int>> data = readdata(filename);

    start_time = clock();
    vector<int>error_data_index = obtain_error_id(error_index_vector,pai);
    end_time = clock();
    printf("obtian error index time is  ------  %f s\n", ((double)(end_time - start_time)) / 1  / CLOCKS_PER_SEC);

    printf("-----------------\n");

    if (SEL_DATASET ==1){
        for(const auto& value : error_data_index){
        cout<<"find the error data in Column  "<< (value+ROW)/ROW <<"  Line  "<< (value+1)%ROW<<". The error number is "
        << data[(value+1)%ROW-1][(value+ROW)/ROW-1] <<endl;
    }
    }
    else if (SEL_DATASET == 2){
        for(const auto& value : error_data_index){
        cout<<"find the error data in Column  "<< (value+ROW)/ROW <<"  Line  "<< (value+1)%ROW <<endl;
    }
    }
    else {
        cout<<"error select of dataset"<< endl;
    }

    
    return 0;
}

int main(){
    if (SEL_DATASET ==1){
        Error_index error_index_vector = cloud_server_receive_keypairs_ciphertexts_CD_dataset();
        user_print_errors(error_index_vector);
    }
    else if (SEL_DATASET == 2){
        Error_index error_index_vector = cloud_server_receive_keypairs_ciphertexts_GeoLife_dataset();
        user_print_errors(error_index_vector);
    }
    else {
        cout<<"error select of dataset"<< endl;
    }
    
    return 0;
}