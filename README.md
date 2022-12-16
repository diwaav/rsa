# Assignment 6 - Public Key Cryptography 
This program uses three executable files to (1) generate keys, then (2) encrypt a 
message so that only the intended end user can decrypt it, and then (3) to decrypt a 
valid file.

## Building
Build the program with "make" or "make all" such as:
```
$ make
```
You can check the formatting using:
```
$ make format
```
Remember to clean up afterwards so there are no object files or executables left over:
```
$ make clean
```

## Running
Run the program using the following
For encrypting a file:
```
$ ./encrypt
```
For decrypting a file:
```
$ ./decrypt
```
For generating keys:
```
$ ./keygen
```

They take in commands such as
For encrypt:
```
-h help, displays the program synopsis and usage
-i input file (default is stdin)
-o output file (default is stdout)
-n specifies the file containing the public key (default is rsa.pub)
-v verbose printing
```
For decrypt:
```
-h help, displays the program synopsis and usage
-i input file (default is stdin)
-o output file (default is stdout)
-n specifies the file containing the private key (default is rsa.priv)
-v verbose printing
```
For keygen:
```
-h help, displays the program synopsis and usage
-b specifies the minimum number of bits needed for the public key n (default is 256)
-i specifies the number of Miller-Rabin iterations for testing primes (default is 50)
-n specifies the public key file (default is rsa.pub)
-d specified the private key file (default is rsa.priv)
-s specifies the random seed for the random state initiation (default is time(NULL))
-v verbose printing
```
For example, you can run ./keygen to generate the keys
and then ./encrypt -i example.txt -o encrypted.out to encrypt a file with the message

## Possible Errors
There are no memory leaks detected by valgrind and no bugs/errors found in scan-build.

