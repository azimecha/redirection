#include <ImportHelper.h>
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

// does not actually set anything - haven't found information on how to implement it
BOOL Impl_SetThreadStackGuarantee(PULONG pnStackSizeBytes) {
	if (pnStackSizeBytes == NULL) {
		CbLastWinAPIError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	// GuaranteedStackBytes is not even in the TEB in XP, be very conservative
	*pnStackSizeBytes = 512;
	return TRUE;
}
