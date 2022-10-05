
//
//  PQCgenKAT_sign.c
//
//  Created by Bassham, Lawrence E (Fed) on 8/29/17.
//  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "katrng.h"
#include "api.h"

#define	MAX_MARKER_LEN		50

#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

int		FindMarker(FILE *infile, const char *marker);
int		ReadHex(FILE *infile, unsigned char *A, int Length, char *str);
void	fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L);

char    AlgName[] = "My Alg Name";

#define STR(x)    STR_(x)
#define STR_(x)   #x

int
main()
{
#ifdef ALGNAME
    char                *fn_req, *fn_rsp;
#else
    char                fn_req[32], fn_rsp[32];
#endif
    FILE                *fp_req, *fp_rsp;
    unsigned char       *m, *sm, *m1;
    unsigned long long  mlen, smlen, mlen1;
    int                 count;
    int                 done;
    int                 ret_val;

    /*
     * Temporary buffers made static to save space on constrained
     * systems (e.g. ARM Cortex M4).
     */
    static unsigned char       seed[48];
    static unsigned char       entropy_input[48];
    static unsigned char       msg[3300];
    static unsigned char       pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    
    // Create the REQUEST file
#ifdef ALGNAME
    fn_req = "PQCsignKAT_" STR(ALGNAME) ".req";
#else
    sprintf(fn_req, "PQCsignKAT_%d.req", CRYPTO_SECRETKEYBYTES);
#endif
    if ( (fp_req = fopen(fn_req, "w")) == NULL ) {
        printf("Couldn't open <%s> for write\n", fn_req);
        return KAT_FILE_OPEN_ERROR;
    }
#ifdef ALGNAME
    fn_rsp = "PQCsignKAT_" STR(ALGNAME) ".rsp";
#else
    sprintf(fn_rsp, "PQCsignKAT_%d.rsp", CRYPTO_SECRETKEYBYTES);
#endif
    if ( (fp_rsp = fopen(fn_rsp, "w")) == NULL ) {
        printf("Couldn't open <%s> for write\n", fn_rsp);
        return KAT_FILE_OPEN_ERROR;
    }

    static unsigned char skUnderTest[6][CRYPTO_SECRETKEYBYTES];
    
    strcpy((char *)skUnderTest[0],"592000BDF450431B5F8107F083EBFE43FC9F01FC31791B6103F44001EFFF3CE44146F83089FBBF04F82E85101FFC13FE83180003F3B03FF4433B1C013FF4100204717B0BC07FFFDF86FFF2BE0BE075FC213CEC0E4AEFCEC0139F7DF40EBF14103D0C4104E810BB140201EC7F420010BEFFE0FFF42FBCFFFDC3E000C3E01F46F84083044143144F80FBA0C0FBFEC113DEC0EC31360020FEF800C4F870FAEC204507DE820C50BC0BDEC1EBDFBCFB6F83FC50FA143FF90BA13D003EFE1061FEF7CF7D0812411401BDF41E41F7FF410C107C082081DFF039040F7D07FFC41FBEBD1040C20010FD03DFC3000F4400103CEFB07F181046F3E10200207FE85E45EC0E40FBE07F03EF3F1C623FEC6EC703BE7E07DF05F890BDF00E041BCFC0F3E006FFA0400C0FC304507CF7D007FBB13AFBBFBBF76E3D003101F45239E84F000FF03CF7D23C0BFFF90C4FC6148040FC0F39F7D040FBFE3FEC6FBDE89EC4FC207E14017E0840BA0FEFFA17BF7A182089F3B03CF7DEBCF010000B8FC1F431F91FFE42EC4241EC0EFE080082FFFF00EC10BB03AE3FF3F185F02F04FC0004DC3183001F411420420BBF8707F03B081084E7EFC20081C51450001C1080086E81004181EC5DBB002E85F78F84EBE08407EF42006F811420830010BB0C5F00F8704313AEFC0BDE43EBC13DFBCFF807DFC11481810BDFFB0FEF41002086F45F80F4317F07C0FC0BC07B27F0020BCFF4F7DF400BD0C107AECA13FDC107CFFCE41FFFE81041F48F3B1430FBEC0D42F81FC41FEFFA100042EC0144143081101D83F450B7FF90C0FBB1441F6F84F7F23F082009F80FFE000FC2EBBFFF1420BD246104F040C31770FEEFD1FB08003CF7F1BBF81F84E401BE085EC3F40E86041FFFFC31FC17DF800C20FD1420C3EFFF81F85EC704313F075EFDFFB002044FC0F44EC2E43F44080EFEF8303F0B81FC13C001E840090BDFC2F44FFD0C6FC3100000FC90C0EBF13E07FFFFF00FC2FBD03C0BFFB9F430BEFC1077F83081181F37F39101E790BEFBBFBCF80EC4EFD004FC2042045EC61FB08103DEFF0810BF1C3E83E4113EFBC100EBB03E1C2108FCF8D63DE225D8150A360CF3F2ED0B14001DF42707092CEFF0DCDD01FD0113DC1D0ACB1701102C0EE8BECBDF0FF10D0DFBFB25ED0D00D6F0D6242101F705D8071612D91FE3CE18FA03F4F51F160745F50BEFF1FA09F0FEECF0220DF00C0D0F0417F03009E9F402042B05D213E10800ECDD17DFF1DB1A0F11F8180B0C2AFEF7EFDEF707F70EE7E916080FE9E3FF23011DE2FA0817F8D921DE2EEEFBC9000811EF1229DF1F1B091EFF0CE61E060B10D4ECF4EFF70F2FFE2614F30B0E26DA37F903F8EC051017DD0DF2FBE009FF01F1F327E61EEB25E0F2EADEE8ED0DE502FFF9000AFE08E00CD900251836121FCDF410F9F80DEDBEF8FF0505FAEC2419170D3DFA19E71FE4E8FCFD32D8090929E72126E6E50E08EA1FEFDBDBFF1B0DF50CDBE2F715000FD3F605DC2812331019F9F904FEFA0011CAEC15C8EDF8F10223EBD2F3240D05FD05E1DC07FE08EBC8E40DDB09DC0FDA05E50F2EFD05F3D20CF10BED0D15FD08CB1FEC09F1FD03E90E25E9FAF809F41010DC01E4F4F4E90805DFE4F4D742F20FFE13E3E2DD01F500FFF402EDFDCBF527F8FD00210E0F20F8DA1CF2F5CB04EE01EA01FB0AEA1F0EF8FEA9010D0723E521EE0D1710F7D6CBFE14E41BCEE811140A12430DD7FDF0F2F903FB160EEA01E10FF5DF1812D21DEFFD011409E40128D1050A14E802DDE11014FFCF10F614E7D3D91AEB00F9EFFAFB1616070625C51F");
    // for (int i=0;i<CRYPTO_PUBLICKEYBYTES;i++){
    //     skUnderTest[1][i]=0;
    //     if (i==0){
    //         skUnderTest[1][i]=255;
    //     }
    // }

    // for (int i=0;i<CRYPTO_PUBLICKEYBYTES;i++){
    //     skUnderTest[2][i]=0;
    //     if (i==CRYPTO_PUBLICKEYBYTES-1){
    //         skUnderTest[2][i]=255;
    //     }
    // }

    // for (int i=0;i<CRYPTO_PUBLICKEYBYTES;i++){
    //     skUnderTest[3][i]=255;
    // }

    // for (int i=0;i<CRYPTO_PUBLICKEYBYTES;i++){
    //     skUnderTest[4][i]=255;
    //     if (i==0){
    //         skUnderTest[4][i]=0;
    //     }
    // }

    // for (int i=0;i<CRYPTO_PUBLICKEYBYTES;i++){
    //     skUnderTest[5][i]=255;
    //     if (i==CRYPTO_PUBLICKEYBYTES-1){
    //         skUnderTest[5][i]=0;
    //     }
    // }
    for (int i=0; i<48; i++)
        entropy_input[i] = i;

    randombytes_init(entropy_input, NULL, 256);
    for (int i=0; i<1; i++) {
        fprintf(fp_req, "count = %d\n", i);
        randombytes(seed, 48);
        fprintBstr(fp_req, "seed = ", seed, 48);
        mlen = 33*(i+1);
        fprintf(fp_req, "mlen = %llu\n", mlen);
        randombytes(msg, mlen);
        fprintBstr(fp_req, "msg = ", msg, mlen);
        fprintf(fp_req, "pk =\n");
        fprintf(fp_req, "sk =\n");
        fprintf(fp_req, "smlen =\n");
        fprintf(fp_req, "sm =\n\n");
    }
    fclose(fp_req);
    
    //Create the RESPONSE file based on what's in the REQUEST file
    if ( (fp_req = fopen(fn_req, "r")) == NULL ) {
        printf("Couldn't open <%s> for read\n", fn_req);
        return KAT_FILE_OPEN_ERROR;
    }
    
    fprintf(fp_rsp, "# %s\n\n", CRYPTO_ALGNAME);
    done = 0;
    do {
        if ( FindMarker(fp_req, "count = ") ) {
            if (fscanf(fp_req, "%d", &count) != 1) { abort(); }
        } else {
            done = 1;
            break;
        }
        fprintf(fp_rsp, "count = %d\n", count);
        
        if ( !ReadHex(fp_req, seed, 48, "seed = ") ) {
            printf("ERROR: unable to read 'seed' from <%s>\n", fn_req);
            return KAT_DATA_ERROR;
        }
        fprintBstr(fp_rsp, "seed = ", seed, 48);
        
        randombytes_init(seed, NULL, 256);
        
        if ( FindMarker(fp_req, "mlen = ") ) {
            if (fscanf(fp_req, "%llu", &mlen) != 1) { abort(); }
        } else {
            printf("ERROR: unable to read 'mlen' from <%s>\n", fn_req);
            return KAT_DATA_ERROR;
        }
        fprintf(fp_rsp, "mlen = %llu\n", mlen);
        
        m = (unsigned char *)calloc(mlen, sizeof(unsigned char));
        m1 = (unsigned char *)calloc(mlen, sizeof(unsigned char));
        sm = (unsigned char *)calloc(mlen+CRYPTO_BYTES, sizeof(unsigned char));
        
        if ( !ReadHex(fp_req, m, (int)mlen, "msg = ") ) {
            printf("ERROR: unable to read 'msg' from <%s>\n", fn_req);
            return KAT_DATA_ERROR;
        }
        fprintBstr(fp_rsp, "msg = ", m, mlen);
        
        fprintBstr(fp_rsp, "sk = ", skUnderTest[count], CRYPTO_SECRETKEYBYTES);
        printf("hit\n");
        if ( (ret_val = crypto_sign(sm, &smlen, m, mlen, skUnderTest[count])) != 0) {
            printf("crypto_sign returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }
        printf("hit\n");

        fprintf(fp_rsp, "smlen = %llu\n", smlen);
        fprintBstr(fp_rsp, "sm = ", sm, smlen);
        fprintf(fp_rsp, "\n");
        printf("hit\n");
       
        free(m);
        free(m1);
        free(sm);
        

    } while ( !done );
    
    fclose(fp_req);
    fclose(fp_rsp);

    return KAT_SUCCESS;
}

//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
int
FindMarker(FILE *infile, const char *marker)
{
	char	line[MAX_MARKER_LEN];
	int		i, len;
	int curr_line;

	len = (int)strlen(marker);
	if ( len > MAX_MARKER_LEN-1 )
		len = MAX_MARKER_LEN-1;

	for ( i=0; i<len; i++ )
	  {
	    curr_line = fgetc(infile);
	    line[i] = curr_line;
	    if (curr_line == EOF )
	      return 0;
	  }
	line[len] = '\0';

	while ( 1 ) {
		if ( !strncmp(line, marker, len) )
			return 1;

		for ( i=0; i<len-1; i++ )
			line[i] = line[i+1];
		curr_line = fgetc(infile);
		line[len-1] = curr_line;
		if (curr_line == EOF )
		    return 0;
		line[len] = '\0';
	}

	// shouldn't get here
	return 0;
}

//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
int
ReadHex(FILE *infile, unsigned char *A, int Length, char *str)
{
	int			i, ch, started;
	unsigned char	ich;

	if ( Length == 0 ) {
		A[0] = 0x00;
		return 1;
	}
	memset(A, 0x00, Length);
	started = 0;
	if ( FindMarker(infile, str) )
		while ( (ch = fgetc(infile)) != EOF ) {
			if ( !isxdigit(ch) ) {
				if ( !started ) {
					if ( ch == '\n' )
						break;
					else
						continue;
				}
				else
					break;
			}
			started = 1;
			if ( (ch >= '0') && (ch <= '9') )
				ich = ch - '0';
			else if ( (ch >= 'A') && (ch <= 'F') )
				ich = ch - 'A' + 10;
			else if ( (ch >= 'a') && (ch <= 'f') )
				ich = ch - 'a' + 10;
            else // shouldn't ever get here
                ich = 0;
			
			for ( i=0; i<Length-1; i++ )
				A[i] = (A[i] << 4) | (A[i+1] >> 4);
			A[Length-1] = (A[Length-1] << 4) | ich;
		}
	else
		return 0;

	return 1;
}

void
fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L)
{
	unsigned long long  i;

	fprintf(fp, "%s", S);

	for ( i=0; i<L; i++ )
		fprintf(fp, "%02X", A[i]);

	if ( L == 0 )
		fprintf(fp, "00");

	fprintf(fp, "\n");
}

