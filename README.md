# PasswdCLI
PasswdCLI is a simple command-line password manager. It's written in C and structured to work on Windows/Linux systems. Any advices for improvements/errors are well accepted.

DISCLAIMER

This program was created using my knowledge about C, cryptography and OS's. I'm not a professional programmer and the program may contains bugs and errors.
Feel free to analise, compile, test and valutate everything. Any advices are very well accepted.
Use it at your own risk.
This program uses AES cryptography to encrypt your passwords in a file named "password.dat".

This program will require you a startup password (which will be used to create a unique hash saved in "master.dat" used to verify if the startup password is correct) that you can create by your own, but remember it! In fact you have 6 attempts to type the correct password at the start of the program, otherwise the whole database will be deleted and everything will start again from zero.

Both "password.dat" and "master.dat" are set in read only mode. It works on Linux and I'm trying to figure out how to make it work properly even on Windows.

To compile the program you will need libsodium library (their website: https://libsodium.gitbook.io/doc).
For Windows users I recommend to compile using Visual Studio or MINGW64.

The exe's were compiled and tested on my own machine (I have a dual-boot Windows 11 and Linux Mint).
When you download the linux version you have to allow execution with the command: chmod +x '/path/to/file' and then execute with the command './file'.

On Mint I gave this command: gcc -o PasswdCLI_linux_x64 PasswdCLI.c -Wall -Wextra -pedantic -lsodium -O2 -static

On Windows I used Visual Studio Community with static compilation.

This program is distributed under the GNU GPL v3.0 license.
