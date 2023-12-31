This is the code of paper "Homomorphic Data Cleaning in Privacy-Preserving Machine Learning".

The encrypted data and cloud servers key pairs can be found in https://www.dropbox.com/scl/fo/b8t2rhbupq2a9cvrxssyt/h?rlkey=eq3k8zgxumnwr2bkdtjbzgt43&dl=0

/src/Encrypt.cpp ---- The user (data owner) generates the Paillier key pairs, encrypts the dataset  and the range values. The user (data owner) generates the key pairs for cloud server CP and CSP. The user (data owner) writes the ciphertexts and key pairs to ".txt" files.

/src/Find-Potential-Errors.cpp ---- Take the encrypted data, encrypted range values, CP key pairs and CSP key pairs from the ".txt" files. The two cloud servers, CP and CSP performs cleaning process, then return the index of potential errors in ciphertext format. The user (data owner) decrypts the index information and prints the result...

/src/Find-Dirty-Data.cpp ---- Contains the whole data cleaning process in this ".cpp" file. Process steps: Read plaintext data (data owner)--> encrypt data set (data owner)--> find potential errors in encrypted data (CP and CSP)--> return the ciphertext result (CP and CSP)--> print the index of potential errors (data owner)
