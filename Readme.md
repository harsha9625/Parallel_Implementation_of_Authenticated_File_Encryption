Parallel File Encryptor Project (CSS 311)
This project contains two C++ implementations for a secure file encryptor:
Serial Version: A standard, single-threaded program.
Parallel Version: A faster, two-thread pipeline version using OpenMP.
Both versions use the same strong cryptography (AES-256-GCM) and are fully compatible with each other. You can encrypt a file with the parallel version and decrypt it with the serial version, and vice-versa.
Requirements
Before you can compile the code, you will need a few things:
A C++ compiler (like g++)
The OpenMP library (usually included with g++)
The OpenSSL development libraries (libssl-dev)
On an Ubuntu or Debian-based VM, you can install everything you need with this command:
sudo apt update
sudo apt install build-essential libssl-dev

Part 1: Serial Version
This is the baseline implementation that runs in a single thread.
Code File: serial_student_version.cpp
How to Compile
Open your terminal and run the following command to compile the serial version:
g++ -std=c++17 -Wall serial_student_version.cpp -o serial_encryptor -lssl -lcrypto

This will create an executable file named serial_encryptor.
How to Run
Use the program from your terminal with the following format:
./serial_encryptor <mode> <input_file> <output_file>

To Encrypt:
./serial_encryptor encrypt my_document.txt secret_data.enc

It will ask you to enter and confirm a password.
To Decrypt:
./serial_encryptor decrypt secret_data.enc my_document_restored.txt

It will ask for your password to unlock the file.
Part 2: Parallel Version (Pipeline)
This is the high-speed version that uses a two-thread pipeline (one thread for reading, one for encrypting) to speed up the process on large files.
Code File: parallel_student_version.cpp
How to Compile
The compile command is similar, but we must add the -fopenmp flag to enable OpenMP:
g++ -std=c++17 -Wall -fopenmp parallel_student_version.cpp -o parallel_encryptor -lssl -lcrypto

This will create an executable file named parallel_encryptor.
How to Run
The commands are identical to the serial version.
To Encrypt:
./parallel_encryptor encrypt my_large_video.mp4 secret_video.enc

It will ask you to enter and confirm a password.
To Decrypt:
./parallel_encryptor decrypt secret_video.enc my_video_restored.mp4

It will ask for your password to unlock the file.
How to Test and Verify
Here is a simple test to prove that everything works correctly.
1. Create a test file:
echo "This is my secret project file. I hope this works!" > original.txt

2. Encrypt the file (you can use either program):
./parallel_encryptor encrypt original.txt secret.enc

When prompted, enter a password, for example: test123
3. Decrypt the file to a new file:
./parallel_encryptor decrypt secret.enc restored.txt

When prompted, enter the same password: test123
4. Verify the contents:
Use the diff command to check if the original and restored files are identical.
diff original.txt restored.txt

If the command produces no output, it means the files are a perfect match and the encryption/decryption was a success!
5. Test a bad password (Optional):
Try to decrypt the file again, but this time, enter the wrong password.
./parallel_encryptor decrypt secret.enc bad_file.txt

Enter a password like wrongpassword.
The program will stop and print an error message like: "Authentication failed! Wrong password or file is corrupt." It will also delete bad_file.txt to prevent you from using a corrupted file.
