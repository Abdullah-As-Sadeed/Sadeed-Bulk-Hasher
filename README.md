# Sadeed-Bulk-Hasher
Calculates MD5, SHA1, SHA224, SHA256, SHA384, SHA512, and SHA3 hash values of files in a given directory and its subdirectories and saves them in a file. Works on Linux.

## Compilation
Use GCC (the GNU Compiler Collection) and remember to link against the OpenSSL library.  
```
gcc ./Sadeed_Bulk_Hasher.cpp -o ./Sadeed_Bulk_Hasher -lssl -lcrypto
```

## Usage
Give the path of the target directory as an argument. Make sure the program or the current user has sufficient permission to read the directory and its subdirectories and files.
```
./Sadeed_Bulk_Hasher /path-of-the-target-directory
```

A text file named **Hash_Values.txt** will be generated in the directory in which the program is running. So, make sure the program or the current user has sufficient permission to do so. The file will be written with the calculated hash values.  
If it already exists, a confirmation prompt will appear asking whether to overwrite the file or not.
