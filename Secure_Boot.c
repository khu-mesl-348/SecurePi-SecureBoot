// Basic Header //
#include <stdio.h>
#include <string.h>

// FIFO Header -> Share SRK PW //
#include <sys/types.h>
#include <sys/stat.h>

// TPM Header //
#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tspi.h>
#include <tss/tss_error.h>
#include <trousers/trousers.h>

// OpenSSL Header -> For SHA //
#include <openssl/sha.h>

// Define Value
#define SIGN_KEY_UUID {0, 0, 0, 0, 0, {0, 0, 0, 1, 1}}
#define DBG(message, tResult) printf("(Line%d, %s) %s returned 0x%08x. %s.\n\n",__LINE__ ,__func__ , message, tResult, (char *)Trspi_Error_String(tResult));
#define DEBUG 1

char get_plain(unsigned char ch) {
	ch = ch % 26;
	return (char)(97 + (ch) % 26);
}

void createSRK(unsigned char* xor_result, unsigned char* SRK_PASSWD) {
	int i;
	for (i = 0; i < 20; i++)
		SRK_PASSWD[i] = get_plain(xor_result[i]);
}

int get_hash_value(unsigned char* xor_result) {
	FILE *fp;
	int i, j;
	char buf[256];

	// SHA1 Value
	SHA_CTX sha1;
	char sha1_result[3][SHA_DIGEST_LENGTH];

	// SecurePi Serial Number Value
	char serial[16+1];

	// Hash u-boot.bin
	for (i = 0; i < 3; i++)
		memset(sha1_result[i], 0, sizeof(sha1_result[i]));
	memset(buf, 0, sizeof(buf));
	memset(serial, 0, sizeof(serial));

	if (!(fp = fopen("/boot/u-boot.bin", "rb"))) {
		printf("/boot/u-boot.bin Open Fail\n");
		return 1;
	}

	SHA1_Init(&sha1);
	while ((i = fread(buf, 1, sizeof(buf), fp)) > 0)
		SHA1_Update(&sha1, buf, i);
	SHA1_Final(sha1_result[0], &sha1);

	fclose(fp);

	// Hash image.fit
	memset(buf, 0, sizeof(buf));

	if (!(fp = fopen("/boot/image.fit", "rb"))) {
		printf("/boot/image.fit Open Fail\n");
		return 1;
	}

	SHA1_Init(&sha1);
	while ((i = fread(buf, 1, sizeof(buf), fp)) > 0)
		SHA1_Update(&sha1, buf, i);
	SHA1_Final(sha1_result[1], &sha1);

	fclose(fp);

	// Hash SecurePi Serial Number
	memset(buf, 0, sizeof(buf));

	if (!(fp = fopen("/proc/cpuinfo", "r"))) {
		printf("/proc/cpuinfo Open Fail\n");
		return 1;
	}

	SHA1_Init(&sha1);
	
	while (fgets(buf, 256, fp))
		if (strncmp(buf, "Serial", 6) == 0)
			strcpy(serial, strchr(buf, ':') + 2);

	SHA1_Update(&sha1, buf, i);
	SHA1_Final(sha1_result[2], &sha1);

	fclose(fp);

	for (i = 0; i < 3; i++)
		for (j = 0; j < 20; j++)
			xor_result[j] = xor_result[j] ^ sha1_result[i][j];

	return 0;
}

int verify_Bootloader_Signature(unsigned char* xor_result) {
	TSS_HCONTEXT hContext;
	TSS_RESULT result;
	TSS_HKEY hSRK, hSigning_Key;
	TSS_HPOLICY hSRKPolicy, hNVPolicy;
	TSS_UUID MY_UUID = SIGN_KEY_UUID;
	TSS_UUID SRK_UUID = TSS_UUID_SRK;
	TSS_FLAG initFlags = TSS_KEY_TYPE_SIGNING | TSS_KEY_SIZE_2048 | TSS_KEY_NO_AUTHORIZATION | TSS_KEY_NOT_MIGRATABLE;
	TSS_HHASH hHash;
	TSS_HNVSTORE hNVStore;
	BYTE *data;
	UINT32 dataLen = 256, srk_authusage;

	result = Tspi_Context_Create(&hContext);
#if DEBUG
	DBG("Create TPM Context\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Context_Connect(hContext, NULL);
#if DEBUG
	DBG("Connect to TPM\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_NV, 0, &hNVStore);
#if DEBUG
	DBG("Create NV Object\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_INDEX, 0, 1);
#if DEBUG
	DBG("Set NV Index\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_PERMISSIONS, 0, TPM_NV_PER_OWNERWRITE);
#if DEBUG
	DBG("Set NV Policy\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_DATASIZE, 0, 0x100);
#if DEBUG
	DBG("Set NV Data Size\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_NV_ReadValue(hNVStore, 0, &dataLen, &data);
#if DEBUG
	DBG("Read Data from NV\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
#if DEBUG
	DBG("Get SRK Handle\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_GetAttribUint32(hSRK, TSS_TSPATTRIB_KEY_INFO, TSS_TSPATTRIB_KEYINFO_AUTHUSAGE, &srk_authusage);
#if DEBUG
	DBG("Get SRK Attribute\n", result);
#endif
	if (result != 0) return 1;

	if (srk_authusage)
	{
		result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSRKPolicy);
#if DEBUG
		DBG("Get SRK Policy\n", result);
#endif
		if (result != 0) return 1;

		result = Tspi_Policy_SetSecret(hSRKPolicy, TSS_SECRET_MODE_PLAIN, 1, "1");
#if DEBUG
		DBG("Set SRK\n", result);
#endif
		if (result != 0) return 1;
	}

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY, initFlags, &hSigning_Key);
#if DEBUG
	DBG("Create RSA Object\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, MY_UUID, &hSigning_Key);
#if DEBUG
	DBG("Load Signing Key\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_HASH, TSS_HASH_SHA1, &hHash);
#if DEBUG
	DBG("Create Hash Object\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Hash_SetHashValue(hHash, sizeof(xor_result), xor_result);
#if DEBUG
	DBG("Set Hash Value\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Hash_VerifySignature(hHash, hSigning_Key, 256, data);
#if DEBUG
	DBG("Verify Signature\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Policy_FlushSecret(hSRKPolicy);
#if DEBUG
	DBG("Flush hSRKPolicy Secret\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Policy_FlushSecret(hNVPolicy);
#if DEBUG
	DBG("Flush hNVPolicy Secret\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Context_FreeMemory(hContext, NULL);
#if DEBUG
	DBG("Tspi Context Free Memory\n", result);
#endif

	result = Tspi_Context_Close(hContext);
#if DEBUG
	DBG("Tspi Context Close\n", result);
#endif

	return 0;
}

int setSRK(unsigned char* xor_result, unsigned char* SRK_PASSWD)
{
	TSS_HTPM hTPM; // TPM value
	TSS_HPOLICY hTPMPolicy, hNewPolicy; // TPM value configure
	TSS_HCONTEXT hContext; // TPM Context
	TSS_RESULT result; // TPM result print using DBG
	TSS_HKEY hSRK; // TPM SRK value
	TSS_UUID SRK_UUID = TSS_UUID_SRK; // TPM SRK save location

	createSRK(xor_result, SRK_PASSWD);
	printf("\n=============\nSRK_PASSWD: %s\n=============\n", SRK_PASSWD);

	result = Tspi_Context_Create(&hContext); // Create TPM Context
#if DEBUG
	DBG("Create TPM Context\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Context_Connect(hContext, NULL); // Connect TPM and TPM Context
#if DEBUG
	DBG("Connect TPM\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Context_GetTpmObject(hContext, &hTPM); // TPM Object configure load
#if DEBUG
	DBG("Load TPM object configure\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_GetPolicyObject(hTPM, TSS_POLICY_USAGE, &hTPMPolicy); // Get TPM configure
#if DEBUG
	DBG("Get TPM configure\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Policy_SetSecret(hTPMPolicy, TSS_SECRET_MODE_PLAIN, 1, "1"); // Set SRK
#if DEBUG
	DBG("Set SRK\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &hNewPolicy); // Create new SRK configure object
#if DEBUG
	DBG("Create New SRK configure object\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Policy_SetSecret(hNewPolicy, TSS_SECRET_MODE_PLAIN, 10, SRK_PASSWD); // Set new SRK Configure
#if DEBUG
	DBG("Set New SRK Configure\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK); // Load TPM SRK
#if DEBUG
	DBG("Load TPM SRK\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_ChangeAuth(hSRK, hTPM, hNewPolicy); // Change New SRK PW
#if DEBUG
	DBG("Change New SRK PW\n", result);
#endif
	if (result != 0) return 1;

	return 0;
}
int main()
{
	unsigned char xor_result[20];
	unsigned char SRK_PASSWD[20];

	if (get_hash_value(xor_result) != 0)
	{
		printf("Hash Fail\n");
		return 1;
	}

	if (setSRK(xor_result, SRK_PASSWD) != 0)
	{
		printf("Set SRK Fali\n");
		return 1;
	}

	if (verify_Bootloader_Signature(xor_result) != 0)
	{
		printf("Verify Signature Fail\n");
		return 1;
	}
	else
		printf("Verify Signature Success\n");

    return 0;
}