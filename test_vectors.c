#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

/* this program writes out the NSA test vectors
 * to a binary file with fwrite so that you can
 * get them in a format native to your CPU and
 * avoid any endedness issues in testing */

int main() {
	
	uint64_t const pt[2] = {0x7469206564616d20, 0x6c61766975716520}; /* plaintext vector */
	uint64_t const ct[2] = {0x7860fedf5c570d18, 0xa65d985179783265}; /* enciphered text vector */
	FILE *out;

	if((out = fopen("vect_plain128.hex", "wb")) == NULL)
	{
		printf ("Error opening output file vect_plain128.hex.\n");
		exit(EXIT_FAILURE);
	}
	fwrite(&pt[0],sizeof(uint64_t),1,out); /* two 64 bit chucks */
	fwrite(&pt[1],sizeof(uint64_t),1,out); /* to make output block */
	fclose(out);

	if((out = fopen("vect_cipher128.hex", "wb")) == NULL)
	{
		printf ("Error opening output file vect_cipher128.hex.\n");
		exit(EXIT_FAILURE);
	}
	fwrite(&ct[0],sizeof(uint64_t),1,out); /* two 64 bit chucks */
	fwrite(&ct[1],sizeof(uint64_t),1,out); /* to make output block */
	fclose(out);

	return 0;
}	
