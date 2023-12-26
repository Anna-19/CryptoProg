#include "AES.h"

int main ()
{
    bool is_running = true;
    string operation_mode;
    string input_file, output_file, iv_file, password;
    cout << " 1 - шифрование \"AES\"" << endl;
    cout << " 2- расшифрование \"AES\"" << endl;
    do {
        cout << "Выбирете режим работы: ";
        cin >> operation_mode;
        if (operation_mode == "1") {
            cout << "Укажите путь до файла: ";
            cin >> input_file;
            cout << "Укажите путь до файла, где будет сохраняться результат: ";
            cin >> output_file;
            cout << "Укажите пароль: ";
            cin >> password;
            try {
                AlgorithmAES enc(input_file, output_file, password);
                enc.encodeAES(enc);
            }  catch (const CryptoPP::Exception & ex) {
                cerr << ex.what() << endl;
            }
        }
        if (operation_mode == "2") {
            cout << "Укажите путь до файла: ";
            cin >> input_file;
            cout << "Укажите путь до файла, где будет сохраняться результат: ";
            cin >> output_file;
            cout << "Укажите путь до файла, в котором находится вектор инициализации: ";
            cin >> iv_file;
            cout << "Укажите пароль: ";
            cin >> password;
            try {
                AlgorithmAES dec(input_file, output_file, password, iv_file);
                dec.decodeAES(dec);
            } catch (const CryptoPP::Exception & ex) {
                cerr << ex.what() << endl;
            } catch (const string & error) {
                cerr << error << endl;
            }
        }
        if (operation_mode == "exit") {
            is_running = false;
            break;
        }
    } while (is_running != false);

    return 0;
}
