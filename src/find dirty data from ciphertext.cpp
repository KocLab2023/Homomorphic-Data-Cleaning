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
#define ROW 700 // 70000 for dataset1, 17396 for dataset2
#define COL 4 // 4 for dataset1, 2 for dataset2
#define SEL_DATASET 1   // 1 for dataset1, 2 for dataset2


class ciphertext {
public:
    mpz_t ct;
    // 使用mpz_t变量初始化
    ciphertext(const mpz_t& value) {
        // 将mpz_t变量复制到类的成员变量
        mpz_init_set(ct, value);
    }

    // 拷贝构造函数
    ciphertext(const ciphertext& other) {
        mpz_init_set(ct, other.ct);
    }

    // 赋值运算符
    ciphertext& operator=(const ciphertext& other) {
        if (this != &other) {
            mpz_set(ct, other.ct);
        }
        return *this;
    }

    // 析构函数
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
        // 使用字符串流解析每一行
        stringstream ss(line);
        for (int col = 0; col < COL; ++col) {
            string val;
            // 使用逗号作为分隔符
            getline(ss, val, ',');
            // 将字符串转换为整数
            matrix[row][col] = stoi(val);
        }
        ++row;
        if (row>ROW-1){
            break;
        }
    }

    // 关闭文件
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

Error_index data_cleaning(vector<ciphertext>ciphertext_vector, vector<ciphertext>range,Paillier& pai,PaillierThd& cp, PaillierThd& csp){
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
            // pai.decrypt(z0, ct_range0.ct);
            // gmp_printf("range0= %Zd\n", z0);
            // pai.decrypt(z0, ct_range1.ct);
            // gmp_printf("range1= %Zd\n", z0);
            sc.scmp(cz0, ct_data.ct,ct_range0.ct, cp, csp);
            // pai.decrypt(z0, cz0);
            // gmp_printf("out of range0? %Zd\n", z0);
            ciphertext ct0(cz0);
            error_index_vector.downrange.push_back(ct0);

            sc.scmp(cz1, ct_range1.ct, ct_data.ct, cp, csp);
            // pai.decrypt(z1, cz1);
            // gmp_printf("out of range1? %Zd\n", z1);
            ciphertext ct1(cz1);
            error_index_vector.uprange.push_back(ct1);
        }
    }
    mpz_clears(cz0,cz1,z0,z1,NULL);

    return error_index_vector;
}

Error_index data_cleaning2(vector<ciphertext>ciphertext_vector, vector<ciphertext>range,Paillier& pai,PaillierThd& cp, PaillierThd& csp){
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
        // gmp_printf("out of range0? %Zd\n", z0);
        // gmp_printf("out of range1? %Zd\n", z1);
    }
    mpz_clears(z0,z1,NULL);
    return error_data_index;
}




int datasset1_cleaning(){
    // 定义70000行4列的矩阵
    setrandom();
	Paillier pai;
    pai.keygen(KEY_LEN_BIT);

    int sigma = SIGMA_LEN_BIT;
	PaillierThd cp;
	PaillierThd csp;
	ThirdKeyGen tkg;
	tkg.thdkeygen(pai, sigma, &cp, &csp);

	clock_t start_time;
	clock_t end_time;

    mpz_t z;
    mpz_inits(z,NULL);

    start_time = clock();
    string filename = "/home/husen/vscode/soci-main/dataset/data1.csv"; ///home/husen/vscode/soci-main/
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

    // ciphertext& ct_range = ciphertext_range[7];
    // pai.decrypt(z, ct_range.ct);
    // gmp_printf("dec res %Zd\n", z);
    start_time = clock();
    Error_index error_index_vector =  data_cleaning(ciphertext_vector, ciphertext_range, pai, cp, csp);
    end_time = clock();
    printf("data cleaning time is  ------  %f s\n", ((double)(end_time - start_time)) / 1  / CLOCKS_PER_SEC);

    start_time = clock();
    vector<int>error_data_index = obtain_error_id(error_index_vector,pai);
    end_time = clock();
    printf("obtian error index time is  ------  %f s\n", ((double)(end_time - start_time)) / 1  / CLOCKS_PER_SEC);

    printf("-----------------\n");
    for(const auto& value : error_data_index){
        cout<<"find the error data in Column  "<< (value+ROW)/ROW <<"  Line  "<< (value+1)%ROW<<". The error number is "
        << data[(value+1)%ROW-1][(value+ROW)/ROW-1] <<endl;
    }

    return 0;
}


int datasset2_cleaning(){
    // 定义70000行4列的矩阵
    setrandom();
	Paillier pai;
    pai.keygen(KEY_LEN_BIT);

    int sigma = SIGMA_LEN_BIT;
	PaillierThd cp;
	PaillierThd csp;
	ThirdKeyGen tkg;
	tkg.thdkeygen(pai, sigma, &cp, &csp);

	clock_t start_time;
	clock_t end_time;

    mpz_t z;
    mpz_inits(z,NULL);

    start_time = clock();
    string filename = "/home/husen/vscode/soci-main/dataset/data2.csv"; ///home/husen/vscode/soci-main/
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
    int plaintext_range[8]={0,100,0,100};
    vector<ciphertext> ciphertext_range = encrypt_range(plaintext_range, pai);
    end_time = clock();
    printf("encrypt range time is  ------  %f s\n", ((double)(end_time - start_time)) / 1  / CLOCKS_PER_SEC);

    
    start_time = clock();
    Error_index error_index_vector =  data_cleaning2(ciphertext_dv, ciphertext_range, pai, cp, csp);
    end_time = clock();
    printf("data cleaning time is  ------  %f s\n", ((double)(end_time - start_time)) / 1  / CLOCKS_PER_SEC);

    start_time = clock();
    vector<int>error_data_index = obtain_error_id(error_index_vector,pai);
    end_time = clock();
    printf("obtian error index time is  ------  %f s\n", ((double)(end_time - start_time)) / 1  / CLOCKS_PER_SEC);

    printf("-----------------\n");
    for(const auto& value : error_data_index){
        cout<<"find suspected error location in Column  "<< (value+ROW)/ROW <<"  Line  "<< (value+1)%ROW <<endl;
    }

    return 0;
}

int main() {
    if (SEL_DATASET ==1){
        datasset1_cleaning();
    }
    else if (SEL_DATASET == 2){
        datasset2_cleaning();
    }
    else {
        cout<<"error select of dataset"<< endl;
    }

    
        
    return 0;
}
