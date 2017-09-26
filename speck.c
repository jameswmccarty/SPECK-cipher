#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <x86intrin.h>

#define ROR _lrotr /* in x86intrin.h */
#define ROL _lrotl /* in x86intrin.h */
#define R(x, y, k) (x = ROR(x, 8), x += y, x ^= k, y = ROL(y, 3), y ^= x) /* encryption round */
#define D(x, y, k) (y ^= x, y = ROR(y, 3), x ^= k, x -= y, x = ROL(x, 8)) /* inverse round */
#define ROUNDS 32

typedef struct {
	char *keyfilename; /* location of key file */
	char *infilename; /* input plain/cipher text */
	char *outfilename; /* output plain/cipher text */
	/* flags for program control */
	int expand; /* perform key pre-expansion Yes = 1; No = 0*/
	int encrypt; /* Encryption = 1; Decryption = 0 */
} ctrl_struct; /* storage structure for program options */


/* ******************************************
 * given a 128-bit key, extend it for       *
 * 32 rounds and save in a buffer for later *
 * use   .                                  *
 ********************************************/
void key_extend(uint64_t kb[static 2*ROUNDS], 
	 			uint64_t const K[static 2]) 
{
	uint64_t i, a, b;
	b = K[1], a = K[0];
	for (i = 0; i<ROUNDS; i++) {
		kb[i*2] = b;
		kb[i*2+1] = a;
		R(b, a, i); /* key expansion uses encryption round */
   }
} /* end of key extend */


/**************************************************** 
 * provided a file name and a 128-bit buffer        *
 * read the hexidecimal key and store it in the     *
 * buffer.  uses fscanf, will not report failure    *
 * if EOF is reached before full number of digits   *
 * are read.                                        *
 *                                                  *
 * Expected format: 0x00...0 with 32 hex characters *
 *
 ****************************************************/
void load_key_file(char * inpt, uint64_t K[static 2])
{
	FILE * keyfile;
	uint64_t x, y;
	keyfile = fopen(inpt, "r");
	

	if (keyfile == NULL) {
		printf("ERROR: Key file %s could not be opened.\n", inpt);
		exit (EXIT_FAILURE);
	}
	
	/* read 128 bit key from file */
	if(1 != fscanf(keyfile, "%16lx", &x)) {
		printf("ERROR in reading key from %s.\n", inpt);
		printf("Expected format: 00...0 with 32 hex characters.\n");
		exit(EXIT_FAILURE);
	}

	if(1 != fscanf(keyfile, "%16lx", &y)) {
		printf("ERROR in reading key from %s.\n", inpt);
		printf("Expected format: 00...0 with 32 hex characters.\n");
		exit(EXIT_FAILURE);
	}

	K[0] = y;
	K[1] = x;

	(void) fclose(keyfile);
}

/*******************************************
 * encrypt a block with a key and perform  *
 * the key expansion in place (slower).    *
 ******************************************/
void encrypt_ext(uint64_t const pt[static 2],
             uint64_t ct[static 2],
             uint64_t const K[static 2])
{
   uint64_t y = pt[0], x = pt[1], b = K[1], a = K[0], i=0;
   
   for (i = 0; i < ROUNDS; i++) {
	  R(x, y, a);
      R(b, a, i);
   }

   ct[0] = y;
   ct[1] = x;
} /* end encrypt_ext */

/*******************************************
 * encrypt a block with an expanded key    *
 ******************************************/
void encrypt(uint64_t const pt[static 2],
             uint64_t ct[static 2],
             uint64_t K[static ROUNDS*2])
{
   uint64_t y = pt[0], x = pt[1], i;
   
   for (i = 0; i < ROUNDS; i++) {
	  R(x, y, K[i*2+1]);
   }

   ct[0] = y;
   ct[1] = x;
} /* end encrypt */


/*******************************************
 * decrypt a block with an expanded key    *
 ******************************************/
void decrypt(uint64_t const ct[static 2],
             uint64_t pt[static 2],
             uint64_t K[static ROUNDS*2])
{
   uint64_t y = ct[0], x = ct[1];
   int i;
   
   for (i = ROUNDS - 1; i >= 0; i--) {
	  D(x, y, K[i*2+1]);
   }

   pt[0] = y;
   pt[1] = x;
} /* end decrypt */

/*******************************************
 * decrypt a block with a key and perform  *
 * the key expansion in place (slower).    *
 ******************************************/
void decrypt_ext(uint64_t const ct[static 2],
             uint64_t pt[static 2],
             uint64_t const K[static 2])
{
   uint64_t y = ct[0], x = ct[1], b = K[1], a = K[0];
   uint64_t Kext[ROUNDS*2];
   int i;

   for (i = 0; i<ROUNDS; i++) {
     Kext[i*2] = b;
     Kext[i*2+1] = a;
     R(b, a, i);

   }
   
   for (i = ROUNDS - 1; i >= 0; i--) {
	  D(x, y, Kext[i*2+1]);
   }

   pt[0] = y;
   pt[1] = x;
} /* end decrypt_ext */


/**********************************
 * how-to for this program        *
 **********************************/
void print_usage(char **argv)
{
	printf ("SPECK cipher 128 / 128 implementation.\n\n"); 
	printf ("usage:\n");
	printf ("%s [-h] -k keyfile [-e|-d] -i infile -o outfile [-x]\n\n", argv[0]);
	printf ("flags specify:\n");

	printf ("\t-h\t\tprint this screen, then exit.\n");
	printf ("\t-k keyfile\tA 128-bit key in the format 0...0 (32 hex chars, no leading 0x).\n");
	printf ("\t\t\tnote this is a text file, not a binary file.\n");
	printf ("\t-e \t\tencrypt the input file.\n");
	printf ("\t-d \t\tdecrypt the input file.\n");
	printf ("\t-i \t\tinput file path.\n");
	printf ("\t-o \t\toutput file path.\n");
	printf ("\t-x \t\tperform key pre-expansion (vice on the fly).\n\n");
	fflush (stdout);
}

/************************************
 * populate control structure with  *
 * user input. perform basic sanity *
 * check when finished              *
 **********************************/
void parse_args (int argc, char **argv, ctrl_struct *options)
{
  	int i = 1;
  	while (i < argc)
	{
		if (!strcmp (argv[i], "-h"))
		{
			print_usage (argv);
			exit (EXIT_SUCCESS);
		}
		else if (!strcmp (argv[i], "-k"))
		{
	  		options->keyfilename = argv[i + 1];
	  		i += 2;
		}
		else if (!strcmp (argv[i], "-e"))
		{
	  		options->encrypt = 1;
	  		i += 1;
		}
		else if (!strcmp (argv[i], "-d"))
		{
	  		options->encrypt = 0;
	  		i += 1;
		}
		else if (!strcmp (argv[i], "-i"))
		{
	  		options->infilename = argv[i + 1];;
	  		i += 2;
		}
		else if (!strcmp (argv[i], "-o"))
		{
	  		options->outfilename = argv[i + 1];;
	  		i += 2;
		}
		else if (!strcmp (argv[i], "-x"))
		{
	  		options->expand = 1;
	  		i += 1;
		}
	}

	/* make sure all expected files were passed */
	if(options->keyfilename == NULL) {
		printf("Error - missing keyfile parameter.\n");
		print_usage (argv);
		exit(EXIT_FAILURE);
	}
	if(options->infilename == NULL) {
		printf("Error - missing input file parameter.\n");
		print_usage (argv);
		exit(EXIT_FAILURE);
	}
	if(options->outfilename == NULL) {
		printf("Error - missing output file parameter.\n");
		print_usage (argv);
		exit(EXIT_FAILURE);
	}
		
}

int main(int argc, char **argv) 
{
	uint64_t fileKey[2]; /* hold key from input file */
	uint64_t ct[2]; /* will always be results buffer */
	uint64_t pt[2]; /* will always be input buffer */
    	uint64_t Kext[ROUNDS*2]; /* holds extended key */
	ctrl_struct options; /* program flow control */
	int readblocks = 1; /* true if still input left to read */
	int readstatus;
	FILE * in = NULL;
	FILE * out = NULL;

	/* initialize options */
	options.keyfilename = NULL;
	options.infilename = NULL; 
	options.outfilename = NULL;
	options.expand  = 0;  /* perform key pre-expansion Yes = 1; No = 0*/
	options.encrypt = 1; /* Encryption = 1; Decryption = 0 */
	/* Read arguments from the user */
	parse_args(argc, argv, &options);

	/* Load the KEY and report what we got */
	load_key_file(options.keyfilename, &fileKey[0]);
	printf("Found keyfile %s, loaded key:\n", options.keyfilename);
	printf("0x%0lx ", fileKey[1]);
   	printf("0x%0lx\n", fileKey[0]);

	/* Expand the key if option given */
	if(options.expand) {
		printf("Performing key extension...\n");
		key_extend(&Kext[0], &fileKey[0]);
	} else {
		printf("Key expansion will be performed on the fly.\n");
	}

	/* open input and output streams */
	if((in = fopen(options.infilename, "rb")) == NULL)
	{
		printf ("Error opening input file %s.\n", options.infilename);
		exit(EXIT_FAILURE);
	}
	if((out = fopen(options.outfilename, "wb")) == NULL)
	{
		printf ("Error opening output file %s.\n", options.outfilename);
		exit(EXIT_FAILURE);
	}

	/* read a 128-byte block from our input file         *
	 * encrypt or decrypt the block with the in place    *
     	 * or expanded key, then write it to the output file *
	 * loop until EOF or an error.                       *
	 *                                                   */
	while(readblocks) 
	{
		
		/* zero input buffer */
		pt[0] = 0;
		pt[1] = 0;
		/* read an input block */
		/* two 64 bit chucks per block */
		/* read in byte size increments */
		readstatus = fread(&pt[0],1,sizeof(uint64_t)*2,in);
		if(readstatus == 0) 
		{
			/* reached EOF */
			break;
		} else if(readstatus < 0) {
			/* some error occured */
			printf("Invalid file read. Quitting.\n");
			exit(EXIT_FAILURE);
		} else if(readstatus < sizeof(uint64_t)*2) {
			/* something to write out, but on last block */
			readblocks = 0;
		} /* readstatus must have been 2...keep going */

		/*printf("0x%0lx ", pt[1]);
   		printf("0x%0lx\n", pt[0]);*/

		/* encrypting? */
		if(options.encrypt)
		{
			/* printf("Encrypting block.\n");*/
			/* extended? */
			if(options.expand) {
				encrypt(&pt[0], &ct[0], &Kext[0]);
			} else { /* on the fly */
				encrypt_ext(&pt[0], &ct[0], &fileKey[0]);
			}
		} else { /* decryption round */
			/* extended? */
			/* printf("Decrypting block.\n");*/
			if(options.expand) {
				decrypt(&pt[0], &ct[0], &Kext[0]);
			} else { /* on the fly */
				decrypt_ext(&pt[0], &ct[0], &fileKey[0]);
			}
		} /* result should now be stored in ct buffer */

		/* write block to output file */
		/* printf("0x%0lx ", ct[1]); */
		/* printf("0x%0lx\n", ct[0]); */
		fwrite(&ct[0],sizeof(uint64_t),1,out); /* two 64 bit chucks */
		fwrite(&ct[1],sizeof(uint64_t),1,out); /* to make output block */
	} /* end while loop */

	/* done with everything */
	fclose(in);
	fclose(out);
	printf("Done.\n");	

	/* Below this line - Test vectors from the NSA paper */
	/* and early testing code */
	/* uint64_t const K[2]  = {0x0706050403020100, 0x0f0e0d0c0b0a0908};*/ /* 128-bit key */
	/* uint64_t const pt[2] = {0x7469206564616d20, 0x6c61766975716520};*/ /* plaintext vector */
    	/* uint64_t const rt[2] = {0x7860fedf5c570d18, 0xa65d985179783265};*/ /* enciphered text vector */	
   	
    	/*encrypt_ext(&pt[0], &ct[0], &K[0]);
	printf("0x%0lx ", ct[1]);
	printf("0x%0lx\n", ct[0]);

	decrypt_ext(&rt[0], &ct[0], &K[0]);
	printf("0x%0lx ", ct[1]);
	printf("0x%0lx\n", ct[0]);

	key_extend(&Kext[0], &K[0]);
   
	encrypt(&pt[0], &ct[0], &Kext[0]);
	printf("0x%0lx ", ct[1]);
	printf("0x%0lx\n", ct[0]);
   
	decrypt(&rt[0], &ct[0], &Kext[0]);
	printf("0x%0lx ", ct[1]);
	printf("0x%0lx\n", ct[0]);*/

	return 0;
} /* end of main */
