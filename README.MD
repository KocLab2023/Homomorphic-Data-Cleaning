This is the code of paper "Homomorphic Data Cleaning in Privacy-Preserving Machine Learning".

/src/encrypt dataset.cpp ---- The user (data owner) generate the Paillier key pairs, encrypt the dataset and range values. The user (data owner) generate the key pairs for cloud server CP and CSP. The user (data owner) write the ciphertexts and key pairs to ".txt" files.

/src/find potential errors from ciphertexts.cpp ---- take the encrypted data, encrypted range values, CP key pairs and CSP key pairs from the ".txt" files. The two cloud server CP and CSP performs cleaning process, then returns the index of potential errors in ciphertext format. The user (data owner) decrypt the index information, print the result...

/src/find potential errors from ciphertexts.cpp ---- Contains the whole data cleaning process in this ".cpp" file.
