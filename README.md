# SPECK-cipher
C implementation of NSA's SPECK block cipher.

## DISCLAIMER
*THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED*

This project was started to study the SPECK lightweight block cipher outlined in the NSA paper available (included in this repo), also hosted: https://eprint.iacr.org/2013/404.pdf.

I make no guarantees as to the correctness of this implementation.  This code should not be used for any purpose other than study.

## Implementation

This program implements the SPECK cipher with a 128-bit key size and a 128-bit block size.  It was designed and compiled for x86_64 Linux.

## Files
 o Makefile:            Makefile for this project.
 o speck.c:             The main c program that implements the cipher.
 o test_vectors.c:      Utility code to produce example binary input files.
 o key_128.key:         Example key value (from NSA paper test vectors).
 o vect_cipher128.hex:  Enciphered 128-bit binary test vector.
 o vect_plain128.hex:   Plain text 128-bit binary test vector.
 o NSA SIMON-SPECK 404.pdf: NSA paper outlining the SIMON&SPECK block cipher.

## Useage

To compile all, type "make."

### SPECK
./speck [-h] -k keyfile [-e|-d] -i infile -o outfile [-x]

flags specify:
        -h              print this screen, then exit.
        -k keyfile      A 128-bit key in the format 0...0 (32 hex chars, no leading 0x).
                        note this is a text file, not a binary file.
        -e              encrypt the input file.
        -d              decrypt the input file.
        -i              input file path.
        -o              output file path.
        -x              perform key pre-expansion (vice on the fly).
 ### TESTVECT
 ./testvect             There are no input options for this program, but it will produce
                        vect_cipher128.hex and vect_plain128.hex in the directory where it is
                        run.
                        
### Example Useage

./speck -k key_128.key -e -i vect_plain128.hex -o output.enc | Encrypts 'vect_plain128.hex' and stores in output.enc

./speck -k key_128.key -d -i output.enc -o plain_vect.hex | Decrypts 'output.enc' and stores in plain_vect.hex

./speck -k key_128.key -d -i output.enc -o plain_vect.hex -x | Same as above with key pre-expansion.
 
 ## Known Issues
  o Program only reads/writes a 128-bit block size.  This may lead to null bytes at the end of some files.
  o Makes no attempt to correct endedness related issues on file reads/writes.  Encrypted files may not be portable across systems.
  o Only implements 128-bit keysize / blocksize.
