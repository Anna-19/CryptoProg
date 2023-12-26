#pragma once
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <cryptopp/aes.h>
#include <cryptopp/base64.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include "cryptopp/modes.h"
#include <iostream>
#include <string>
#include <fstream>
using namespace std;
using namespace CryptoPP;

class AlgorithmAES
{
private:
  string filePath_in;
  string filePath_out;
  string psw;
  string filePath_Iv;
  string salt = "stvjgfdgkihyojnv";
public:
  AlgorithmAES() = delete;
  AlgorithmAES(const string& filePath_in, const string& filePath_out, const string& Pass);
  AlgorithmAES(const string& filePath_in, const string& filePath_out, const string& Pass, const string & iv);
  void encodeAES (AlgorithmAES enc);
  void decodeAES (AlgorithmAES dec);
};
