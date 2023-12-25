#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <vector>
#include <iostream>
#include <string>
#include <fstream>
using namespace std;

string read_file(string way){
    ifstream file(way);
    string line;
    string entry;
    if (file.peek() == EOF){
        throw runtime_error("Файл пустой");
    }
    while (getline(file, line)){
        entry += line;
    }
    file.close();
    return entry;
}

int main (){
    CryptoPP::SHA1 hash; // создание хэш-объекта
    string path = "text.txt"; // Путь до файла
    string FileContent;
    try {
        FileContent = read_file(path);
    } catch (const runtime_error& e) {
        cout << "Error: " << e.what() << endl;
        return 1;
    }

    cout << "Содержимое файла: " << FileContent << endl; // содержимое файла

    CryptoPP::FileSource(path.c_str(), true, new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::FileSink(cout), true)));
    cout <<"\n"<< endl;
    return 0;
}