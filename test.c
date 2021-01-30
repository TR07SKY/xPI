#include <stdio.h>

#include "xpi.h"
#include "utils/uint256.h"

#define BEGIN(a)            ((char*)&(a))
#define END(a)              ((char*)&((&(a))[1]))

int main(void)
{
	int nNonce   = 1780527;
	int nVersion = 5015641;
	uint256 hash = hash_M7M_v2(BEGIN(nVersion), END(nNonce), nNonce);

	printf("%s\n", hash.GetHex().c_str()); /* HEX print */
	//printf("%s\n", blakeHash.GetHex().c_str());
	/*printf("%u\n", hash); *//* "PURE" print */

	return 0;
}
