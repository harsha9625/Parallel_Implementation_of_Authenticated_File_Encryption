#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <memory>
#include <atomic>
#include <omp.h>

// OpenSSL Headers
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

// Platform-specific headers for get_password
#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

// --- Constants ---
const int KEY_SIZE = 32;
const int IV_SIZE = 12;
const int SALT_SIZE = 16;
const int TAG_SIZE = 16;
const int PBKDF2_ITERATIONS = 600000;
// Use a larger buffer for pipelining to be effective
const int BUFFER_SIZE = 1024 * 1024 * 4; // 4MB

// --- Shared State for Pipeline ---
enum class BufferState
{
    Empty,
    Full,
    Done
};

// --- Custom Deleter for RAII ---
struct EvpCipherCtxDeleter
{
    void operator()(EVP_CIPHER_CTX *ptr) const { EVP_CIPHER_CTX_free(ptr); }
};
using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;

// --- Function Prototypes ---
void handle_openssl_errors();
std::string get_password(bool confirm);
void derive_key(const std::string &password, const unsigned char *salt, unsigned char *key, unsigned char *iv);
bool encrypt_file(const std::string &inputFile, const std::string &outputFile, const std::string &password);
bool decrypt_file(const std::string &inputFile, const std::string &outputFile, const std::string &password);

// --- Main Function ---
int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        std::cerr << "Usage: " << argv[0] << " <encrypt|decrypt> <input_file> <output_file>" << std::endl;
        return 1;
    }

    std::string mode = argv[1];
    std::string inputFile = argv[2];
    std::string outputFile = argv[3];

    bool is_encrypt_mode;
    if (mode == "encrypt")
        is_encrypt_mode = true;
    else if (mode == "decrypt")
        is_encrypt_mode = false;
    else
    {
        std::cerr << "Error: Invalid mode. Use 'encrypt' or 'decrypt'." << std::endl;
        return 1;
    }

    std::string password = get_password(is_encrypt_mode);
    if (password.empty())
    {
        std::cerr << "Error: Password cannot be empty or confirmation failed." << std::endl;
        return 1;
    }

    double start_time = omp_get_wtime();
    bool success = false;

    try
    {
        if (is_encrypt_mode)
        {
            success = encrypt_file(inputFile, outputFile, password);
        }
        else
        {
            success = decrypt_file(inputFile, outputFile, password);
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "An error occurred: " << e.what() << std::endl;
        success = false;
    }

    double end_time = omp_get_wtime();

    if (success)
    {
        std::cout << "\nOperation successful." << std::endl;
        std::cout << "Total time taken: " << (end_time - start_time) << " seconds." << std::endl;
    }
    else
    {
        std::cout << "\nOperation failed." << std::endl;
        // The functions themselves should clean up failed output files.
    }

    return success ? 0 : 1;
}

// --- Pipeline Functions ---

bool encrypt_file(const std::string &inputFile, const std::string &outputFile, const std::string &password)
{
    std::vector<unsigned char> buffer1(BUFFER_SIZE), buffer2(BUFFER_SIZE);
    std::atomic<BufferState> state1(BufferState::Empty), state2(BufferState::Empty);
    std::atomic<size_t> bytes_in_buffer1(0), bytes_in_buffer2(0);
    std::atomic<bool> error_flag(false);

#pragma omp parallel num_threads(2)
    {
        try
        {
            if (omp_get_thread_num() == 0)
            { // --- READER THREAD ---
                std::ifstream in(inputFile, std::ios::binary);
                if (!in)
                    throw std::runtime_error("Reader thread cannot open input file.");

                while (true)
                {
                    // Fill buffer 1
                    while (state1.load(std::memory_order_acquire) != BufferState::Empty)
                    {
                        if (error_flag)
                            throw std::runtime_error("");
                    } // Busy-wait
                    in.read((char *)buffer1.data(), buffer1.size());
                    bytes_in_buffer1.store(in.gcount(), std::memory_order_release);
                    state1.store(in.eof() ? BufferState::Done : BufferState::Full, std::memory_order_release);
                    if (in.eof())
                        break;

                    // Fill buffer 2
                    while (state2.load(std::memory_order_acquire) != BufferState::Empty)
                    {
                        if (error_flag)
                            throw std::runtime_error("");
                    } // Busy-wait
                    in.read((char *)buffer2.data(), buffer2.size());
                    bytes_in_buffer2.store(in.gcount(), std::memory_order_release);
                    state2.store(in.eof() ? BufferState::Done : BufferState::Full, std::memory_order_release);
                    if (in.eof())
                        break;
                }
            }
            else
            { // --- PROCESSOR THREAD ---
                std::ofstream out(outputFile, std::ios::binary);
                if (!out)
                    throw std::runtime_error("Processor thread cannot create output file.");

                unsigned char key[KEY_SIZE], iv[IV_SIZE];
                std::vector<unsigned char> salt(SALT_SIZE);
                if (!RAND_bytes(salt.data(), salt.size()))
                    handle_openssl_errors();

                derive_key(password, salt.data(), key, iv); // The slow part
                out.write((char *)salt.data(), salt.size());

                EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
                if (!ctx)
                    handle_openssl_errors();
                if (1 != EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), NULL, NULL, NULL))
                    handle_openssl_errors();
                if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL))
                    handle_openssl_errors();
                if (1 != EVP_EncryptInit_ex(ctx.get(), NULL, NULL, key, iv))
                    handle_openssl_errors();

                std::vector<unsigned char> out_buf(BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);
                int len;

                while (true)
                {
                    // Process buffer 1
                    while (state1.load(std::memory_order_acquire) == BufferState::Empty)
                    {
                        if (error_flag)
                            throw std::runtime_error("");
                    } // Busy-wait
                    size_t bytes = bytes_in_buffer1.load(std::memory_order_acquire);
                    if (bytes > 0)
                    {
                        if (1 != EVP_EncryptUpdate(ctx.get(), out_buf.data(), &len, buffer1.data(), bytes))
                            handle_openssl_errors();
                        out.write((char *)out_buf.data(), len);
                    }
                    bool done = (state1.load(std::memory_order_acquire) == BufferState::Done);
                    state1.store(BufferState::Empty, std::memory_order_release);
                    if (done)
                        break;

                    // Process buffer 2
                    while (state2.load(std::memory_order_acquire) == BufferState::Empty)
                    {
                        if (error_flag)
                            throw std::runtime_error("");
                    } // Busy-wait
                    bytes = bytes_in_buffer2.load(std::memory_order_acquire);
                    if (bytes > 0)
                    {
                        if (1 != EVP_EncryptUpdate(ctx.get(), out_buf.data(), &len, buffer2.data(), bytes))
                            handle_openssl_errors();
                        out.write((char *)out_buf.data(), len);
                    }
                    done = (state2.load(std::memory_order_acquire) == BufferState::Done);
                    state2.store(BufferState::Empty, std::memory_order_release);
                    if (done)
                        break;
                }

                if (1 != EVP_EncryptFinal_ex(ctx.get(), out_buf.data(), &len))
                    handle_openssl_errors();
                out.write((char *)out_buf.data(), len);

                std::vector<unsigned char> tag(TAG_SIZE);
                if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag.data()))
                    handle_openssl_errors();
                out.write((char *)tag.data(), tag.size());
            }
        }
        catch (...)
        {
            error_flag.store(true, std::memory_order_release);
        }
    }

    if (error_flag)
    {
        remove(outputFile.c_str());
        return false;
    }
    return true;
}

bool decrypt_file(const std::string &inputFile, const std::string &outputFile, const std::string &password)
{
    std::vector<unsigned char> buffer1(BUFFER_SIZE), buffer2(BUFFER_SIZE);
    std::atomic<BufferState> state1(BufferState::Empty), state2(BufferState::Empty);
    std::atomic<size_t> bytes_in_buffer1(0), bytes_in_buffer2(0);
    std::atomic<bool> error_flag(false);

#pragma omp parallel num_threads(2)
    {
        try
        {
            if (omp_get_thread_num() == 0)
            { // --- READER THREAD ---
                std::ifstream in(inputFile, std::ios::binary);
                if (!in)
                    throw std::runtime_error("Reader thread cannot open input file.");

                // The reader skips the salt at the beginning.
                in.seekg(SALT_SIZE, std::ios::beg);

                while (true)
                {
                    // Fill buffer 1
                    while (state1.load(std::memory_order_acquire) != BufferState::Empty)
                    {
                        if (error_flag)
                            throw std::runtime_error("");
                    }
                    in.read((char *)buffer1.data(), buffer1.size());
                    bytes_in_buffer1.store(in.gcount(), std::memory_order_release);
                    // The reader doesn't know about the tag, so it will read until the end of the file.
                    state1.store(in.eof() ? BufferState::Done : BufferState::Full, std::memory_order_release);
                    if (in.eof())
                        break;

                    // Fill buffer 2
                    while (state2.load(std::memory_order_acquire) != BufferState::Empty)
                    {
                        if (error_flag)
                            throw std::runtime_error("");
                    }
                    in.read((char *)buffer2.data(), buffer2.size());
                    bytes_in_buffer2.store(in.gcount(), std::memory_order_release);
                    state2.store(in.eof() ? BufferState::Done : BufferState::Full, std::memory_order_release);
                    if (in.eof())
                        break;
                }
            }
            else
            {                                                  // --- PROCESSOR THREAD ---
                std::ifstream in(inputFile, std::ios::binary); // Processor needs its own handle to read salt/tag
                if (!in)
                    throw std::runtime_error("Processor thread cannot open input file.");

                in.seekg(0, std::ios::end);
                size_t file_size = in.tellg();
                if (file_size < SALT_SIZE + TAG_SIZE)
                    throw std::runtime_error("Input file too small.");

                // Read salt from start
                std::vector<unsigned char> salt(SALT_SIZE);
                in.seekg(0, std::ios::beg);
                in.read((char *)salt.data(), salt.size());

                // Read tag from end
                std::vector<unsigned char> tag(TAG_SIZE);
                in.seekg(file_size - TAG_SIZE, std::ios::beg);
                in.read((char *)tag.data(), tag.size());

                std::ofstream out(outputFile, std::ios::binary);
                if (!out)
                    throw std::runtime_error("Processor thread cannot create output file.");

                unsigned char key[KEY_SIZE], iv[IV_SIZE];
                derive_key(password, salt.data(), key, iv);

                EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
                if (!ctx)
                    handle_openssl_errors();
                if (1 != EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), NULL, NULL, NULL))
                    handle_openssl_errors();
                if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL))
                    handle_openssl_errors();
                if (1 != EVP_DecryptInit_ex(ctx.get(), NULL, NULL, key, iv))
                    handle_openssl_errors();

                std::vector<unsigned char> out_buf(BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);
                int len;
                size_t total_bytes_to_process = file_size - SALT_SIZE - TAG_SIZE;

                while (total_bytes_to_process > 0)
                {
                    // Process buffer 1
                    while (state1.load(std::memory_order_acquire) == BufferState::Empty)
                    {
                        if (error_flag)
                            throw std::runtime_error("");
                    }
                    size_t bytes_from_reader = bytes_in_buffer1.load(std::memory_order_acquire);
                    size_t bytes_to_process = std::min(bytes_from_reader, total_bytes_to_process);

                    if (bytes_to_process > 0)
                    {
                        if (1 != EVP_DecryptUpdate(ctx.get(), out_buf.data(), &len, buffer1.data(), bytes_to_process))
                            handle_openssl_errors();
                        out.write((char *)out_buf.data(), len);
                        total_bytes_to_process -= bytes_to_process;
                    }
                    bool done = (state1.load(std::memory_order_acquire) == BufferState::Done);
                    state1.store(BufferState::Empty, std::memory_order_release);
                    if (done)
                        break;

                    // Process buffer 2
                    while (state2.load(std::memory_order_acquire) == BufferState::Empty)
                    {
                        if (error_flag)
                            throw std::runtime_error("");
                    }
                    bytes_from_reader = bytes_in_buffer2.load(std::memory_order_acquire);
                    bytes_to_process = std::min(bytes_from_reader, total_bytes_to_process);

                    if (bytes_to_process > 0)
                    {
                        if (1 != EVP_DecryptUpdate(ctx.get(), out_buf.data(), &len, buffer2.data(), bytes_to_process))
                            handle_openssl_errors();
                        out.write((char *)out_buf.data(), len);
                        total_bytes_to_process -= bytes_to_process;
                    }
                    done = (state2.load(std::memory_order_acquire) == BufferState::Done);
                    state2.store(BufferState::Empty, std::memory_order_release);
                    if (done)
                        break;
                }

                // Final authentication check
                if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag.data()))
                    handle_openssl_errors();

                if (EVP_DecryptFinal_ex(ctx.get(), out_buf.data(), &len) <= 0)
                {
                    throw std::runtime_error("Authentication failed. Wrong password or tampered file.");
                }
                out.write((char *)out_buf.data(), len);
            }
        }
        catch (...)
        {
            error_flag.store(true, std::memory_order_release);
        }
    }

    if (error_flag)
    {
        remove(outputFile.c_str());
        return false;
    }
    return true;
}

// --- Helper Functions (Identical to previous versions) ---
void handle_openssl_errors()
{
    char err_buf[256];
    ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
    throw std::runtime_error(std::string("OpenSSL Error: ") + err_buf);
}
std::string get_password(bool confirm)
{
    std::string password;
#ifdef _WIN32
    std::cout << "Enter password: ";
    char ch;
    while ((ch = _getch()) != '\r')
    {
        if (ch == '\b')
        {
            if (!password.empty())
            {
                password.pop_back();
                std::cout << "\b \b";
            }
        }
        else
        {
            password.push_back(ch);
            std::cout << '*';
        }
    }
    std::cout << std::endl;
#else
    termios oldt, newt;
    std::cout << "Enter password: ";
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    std::getline(std::cin, password);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << std::endl;
#endif
    if (confirm)
    {
        std::string password_confirm;
#ifdef _WIN32
        std::cout << "Confirm password: ";
        char ch_confirm;
        while ((ch_confirm = _getch()) != '\r')
        {
            if (ch_confirm == '\b')
            {
                if (!password_confirm.empty())
                {
                    password_confirm.pop_back();
                    std::cout << "\b \b";
                }
            }
            else
            {
                password_confirm.push_back(ch_confirm);
                std::cout << '*';
            }
        }
        std::cout << std::endl;
#else
        termios oldt_confirm, newt_confirm;
        std::cout << "Confirm password: ";
        tcgetattr(STDIN_FILENO, &oldt_confirm);
        newt_confirm = oldt_confirm;
        newt_confirm.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &newt_confirm);
        std::getline(std::cin, password_confirm);
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt_confirm);
        std::cout << std::endl;
#endif
        if (password != password_confirm)
            return "";
    }
    return password;
}
void derive_key(const std::string &password, const unsigned char *salt, unsigned char *key, unsigned char *iv)
{
    std::vector<unsigned char> derived_material(KEY_SIZE + IV_SIZE);
    if (!PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                           salt, SALT_SIZE, PBKDF2_ITERATIONS, EVP_sha256(),
                           derived_material.size(), derived_material.data()))
    {
        handle_openssl_errors();
    }
    memcpy(key, derived_material.data(), KEY_SIZE);
    memcpy(iv, derived_material.data() + KEY_SIZE, IV_SIZE);
}
