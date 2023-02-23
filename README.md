# IDA Xorstr Decryption Plugin
Attempts to decrypt obfuscated strings in x64 windows binaries using https://github.com/JustasMasiulis/xorstr
Only tested on a few projects, can be hit or miss
Tested on IDA 8

![alt text](ida64_MSVbv5Z2qg.png)
![alt text](ida64_66Zji9Qx9W.png)

## Usage
1. Put xorstr_decrypt.py into <IDA_DIR>/plugins/
2. Open a binary, load the plguin. Any decrypted strings will be shown in the console