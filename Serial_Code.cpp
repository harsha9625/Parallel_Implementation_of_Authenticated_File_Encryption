#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <memory>
#include <omp.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

// --- Encryption Constants ---
const int AES_KEY_SIZE = 32;
const int AES_IV_SIZE = 12;
const int SALT_LEN = 16;
const int TAG_LEN = 16;
const int PBKDF2_ROUNDS = 600000;
const int IO_BUFFER = 4096;

struct TimeStats
{
    double key_time;
    double file_time;
    double total_time;
};

// --- Smart Pointer for OpenSSL Context ---
struct CipherCtxDeleter
{
    void operator()(EVP_CIPHER_CTX *ctx) const
    {
        EVP_CIPHER_CTX_free(ctx);
    }
};
using CipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter>;

// --- Function Declarations ---
void throw_ssl_error();
std::string input_password(bool ask_twice);
void create_key_material(const std::string &pwd, const unsigned char *salt, unsigned char *key, unsigned char *iv);
TimeStats encrypt_data(const std::string &inFile, const std::string &outFile, const std::string &pwd);
TimeStats decrypt_data(const std::string &inFile, const std::string &outFile, const std::string &pwd);

// --- Main Entry Point ---
int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        std::cerr << "Usage: " << argv[0] << " <encrypt|decrypt> <input_file> <output_file>\n";
        return 1;
    }

    std::string mode = argv[1];
    std::string input_path = argv[2];
    std::string output_path = argv[3];

    try
    {
        if (mode == "encrypt")
        {
            std::string password = input_password(true);
            if (password.empty())
            {
                std::cerr << "Error: Passwords do not match or are empty.\n";
                return 1;
            }

            TimeStats stats = encrypt_data(input_path, output_path, password);
            std::cout << "\n=== Encryption Stats ===\n";
            std::cout << "Key Derivation: " << stats.key_time << " s\n";
            std::cout << "Encryption Time: " << stats.file_time << " s\n";
            std::cout << "Total Time: " << stats.total_time << " s\n";
        }
        else if (mode == "decrypt")
        {
            std::string password = input_password(false);
            if (password.empty())
            {
                std::cerr << "Error: Password cannot be empty.\n";
                return 1;
            }

            TimeStats stats = decrypt_data(input_path, output_path, password);
            std::cout << "\n=== Decryption Stats ===\n";
            std::cout << "Key Derivation: " << stats.key_time << " s\n";
            std::cout << "Decryption Time: " << stats.file_time << " s\n";
            std::cout << "Total Time: " << stats.total_time << " s\n";
        }
        else
        {
            std::cerr << "Error: Invalid mode. Use 'encrypt' or 'decrypt'.\n";
            return 1;
        }
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Error: " << ex.what() << "\n";
        if (mode == "decrypt")
            remove(output_path.c_str());
        return 1;
    }

    return 0;
}

// --- Error Handling ---
void throw_ssl_error()
{
    char err_msg[256];
    ERR_error_string_n(ERR_get_error(), err_msg, sizeof(err_msg));
    throw std::runtime_error("OpenSSL Failure: " + std::string(err_msg));
}

// --- Password Input ---
std::string input_password(bool ask_twice)
{
    std::string pwd;

#ifdef _WIN32
    std::cout << "Enter password: ";
    char ch;
    while ((ch = _getch()) != '\r')
    {
        if (ch == '\b' && !pwd.empty())
        {
            pwd.pop_back();
            std::cout << "\b \b";
        }
        else if (ch != '\b')
        {
            pwd.push_back(ch);
            std::cout << '*';
        }
    }
    std::cout << '\n';
#else
    termios oldt, newt;
    std::cout << "Enter password: ";
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    std::getline(std::cin, pwd);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << '\n';
#endif

    if (ask_twice)
    {
        std::string confirm_pwd;

#ifdef _WIN32
        std::cout << "Confirm password: ";
        char ch2;
        while ((ch2 = _getch()) != '\r')
        {
            if (ch2 == '\b' && !confirm_pwd.empty())
            {
                confirm_pwd.pop_back();
                std::cout << "\b \b";
            }
            else if (ch2 != '\b')
            {
                confirm_pwd.push_back(ch2);
                std::cout << '*';
            }
        }
        std::cout << '\n';
#else
        termios oldt2, newt2;
        std::cout << "Confirm password: ";
        tcgetattr(STDIN_FILENO, &oldt2);
        newt2 = oldt2;
        newt2.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &newt2);
        std::getline(std::cin, confirm_pwd);
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt2);
        std::cout << '\n';
#endif

        if (pwd != confirm_pwd)
            return "";
    }
    return pwd;
}

// --- Key Derivation ---
void create_key_material(const std::string &pwd, const unsigned char *salt, unsigned char *key, unsigned char *iv)
{
    std::vector<unsigned char> buffer(AES_KEY_SIZE + AES_IV_SIZE);
    if (!PKCS5_PBKDF2_HMAC(pwd.c_str(), pwd.size(), salt, SALT_LEN,
                           PBKDF2_ROUNDS, EVP_sha256(), buffer.size(), buffer.data()))
        throw_ssl_error();

    memcpy(key, buffer.data(), AES_KEY_SIZE);
    memcpy(iv, buffer.data() + AES_KEY_SIZE, AES_IV_SIZE);
}

// --- Encryption ---
TimeStats encrypt_data(const std::string &inFile, const std::string &outFile, const std::string &pwd)
{
    double start_time = omp_get_wtime();
    TimeStats t = {0, 0, 0};

    std::ifstream fin(inFile, std::ios::binary);
    if (!fin)
        throw std::runtime_error("Cannot open input file: " + inFile);

    std::ofstream fout(outFile, std::ios::binary);
    if (!fout)
        throw std::runtime_error("Cannot create output file: " + outFile);

    std::vector<unsigned char> salt(SALT_LEN);
    if (!RAND_bytes(salt.data(), SALT_LEN))
        throw_ssl_error();
    fout.write((char *)salt.data(), SALT_LEN);

    unsigned char key[AES_KEY_SIZE];
    unsigned char iv[AES_IV_SIZE];

    std::cout << "Generating encryption key...\n";
    double key_start = omp_get_wtime();
    create_key_material(pwd, salt.data(), key, iv);
    double key_end = omp_get_wtime();
    t.key_time = key_end - key_start;

    CipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx)
        throw_ssl_error();

    if (!EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr))
        throw_ssl_error();
    if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, AES_IV_SIZE, nullptr))
        throw_ssl_error();
    if (!EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key, iv))
        throw_ssl_error();

    std::vector<unsigned char> in_buf(IO_BUFFER);
    std::vector<unsigned char> out_buf(IO_BUFFER + EVP_MAX_BLOCK_LENGTH);
    int len;

    double file_start = omp_get_wtime();
    while (fin.read((char *)in_buf.data(), in_buf.size()) || fin.gcount())
    {
        if (!EVP_EncryptUpdate(ctx.get(), out_buf.data(), &len, in_buf.data(), fin.gcount()))
            throw_ssl_error();
        fout.write((char *)out_buf.data(), len);
    }

    if (!EVP_EncryptFinal_ex(ctx.get(), out_buf.data(), &len))
        throw_ssl_error();
    fout.write((char *)out_buf.data(), len);

    std::vector<unsigned char> tag(TAG_LEN);
    if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag.data()))
        throw_ssl_error();
    fout.write((char *)tag.data(), TAG_LEN);

    double file_end = omp_get_wtime();
    t.file_time = file_end - file_start;
    t.total_time = omp_get_wtime() - start_time;

    std::cout << "Encryption complete.\n";
    return t;
}

// --- Decryption ---
TimeStats decrypt_data(const std::string &inFile, const std::string &outFile, const std::string &pwd)
{
    double start_time = omp_get_wtime();
    TimeStats t = {0, 0, 0};

    std::ifstream fin(inFile, std::ios::binary);
    if (!fin)
        throw std::runtime_error("Cannot open input file: " + inFile);

    fin.seekg(0, std::ios::end);
    size_t total_size = fin.tellg();
    fin.seekg(0, std::ios::beg);

    if (total_size < SALT_LEN + TAG_LEN)
        throw std::runtime_error("Invalid encrypted file.");

    std::vector<unsigned char> salt(SALT_LEN);
    fin.read((char *)salt.data(), SALT_LEN);

    std::vector<unsigned char> tag(TAG_LEN);
    fin.seekg(total_size - TAG_LEN, std::ios::beg);
    fin.read((char *)tag.data(), TAG_LEN);

    fin.seekg(SALT_LEN, std::ios::beg);
    size_t data_size = total_size - SALT_LEN - TAG_LEN;

    unsigned char key[AES_KEY_SIZE];
    unsigned char iv[AES_IV_SIZE];

    std::cout << "Deriving decryption key...\n";
    double key_start = omp_get_wtime();
    create_key_material(pwd, salt.data(), key, iv);
    double key_end = omp_get_wtime();
    t.key_time = key_end - key_start;

    std::ofstream fout(outFile, std::ios::binary);
    if (!fout)
        throw std::runtime_error("Cannot create output file: " + outFile);

    CipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx)
        throw_ssl_error();

    if (!EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr))
        throw_ssl_error();
    if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, AES_IV_SIZE, nullptr))
        throw_ssl_error();
    if (!EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key, iv))
        throw_ssl_error();

    std::vector<unsigned char> in_buf(IO_BUFFER);
    std::vector<unsigned char> out_buf(IO_BUFFER);
    int len;

    double file_start = omp_get_wtime();
    while (data_size > 0)
    {
        int chunk = (data_size < IO_BUFFER) ? data_size : IO_BUFFER;
        fin.read((char *)in_buf.data(), chunk);
        if (!EVP_DecryptUpdate(ctx.get(), out_buf.data(), &len, in_buf.data(), fin.gcount()))
            throw std::runtime_error("Decryption error: wrong password or corrupt file.");
        fout.write((char *)out_buf.data(), len);
        data_size -= chunk;
    }

    if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag.data()))
        throw_ssl_error();

    if (EVP_DecryptFinal_ex(ctx.get(), out_buf.data(), &len) <= 0)
        throw std::runtime_error("Authentication failed: incorrect password or modified file.");

    fout.write((char *)out_buf.data(), len);

    double file_end = omp_get_wtime();
    t.file_time = file_end - file_start;
    t.total_time = omp_get_wtime() - start_time;

    std::cout << "Decryption complete.\n";
    return t;
}
