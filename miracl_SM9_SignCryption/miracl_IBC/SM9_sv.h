/************************************************************
Note:
Codes here were downloaded from:
http://www.scctc.org.cn/templates/Download/index.aspx?nodeid=71.
The disclaimer was published on the link:
http://www.scctc.org.cn/Upload/accessory/20175/201755105494041082.pdf .
The codes were slightly modified to pass the check of C complier.
*************************************************************/

#ifndef HEADER_SM9_SV_H
#define HEADER_SM9_SV_H

///************************************************************************
//  File name:    SM9_sv.h
//  Version:      SM9_sv_V1.0
//  Date:         Dec 15,2016
//  Description:  implementation of SM9 signature algorithm and verification algorithm
//                all operations based on BN curve line function
//  Function List:
//        1.bytes128_to_ecn2     //convert 128 bytes into ecn2
//        2.zzn12_ElementPrint   //print all element of struct zzn12
//        3.ecn2_Bytes128_Print  //print 128 bytes of ecn2
//        4.LinkCharZzn12        //link two different types(unsigned char and zzn12)to one(unsigned char)
//        5.Test_Point           //test if the given point is on SM9 curve
//        6.Test_Range           //test if the big x belong to the range[1,N-1]
//        7.SM9_Init             //initiate SM9 curve
//        8.SM9_H1               //function H1 in SM9 standard 5.4.2.2
//        9.SM9_H2               //function H2 in SM9 standard 5.4.2.3
//        10.SM9_GenerateSignKey //generate signed private and public key
//        11.SM9_Sign            //SM9 signature algorithm
//        12.SM9_Verify          //SM9 verification
//        13.SM9_SelfCheck()     //SM9 slef-check

//
// Notes:
// This SM9 implementation source code can be used for academic, non-profit making or non-commercial use only.
// This SM9 implementation is created on MIRACL. SM9 implementation source code provider does not provide MIRACL library, MIRACL license or any permission to use MIRACL library. Any commercial use of MIRACL requires a license which may be obtained from Shamus Software Ltd.

//**************************************************************************/

#include <malloc.h>
#include <math.h>
#include "miracl.h"
#include "R-ate.h"

#define BNLEN 32 //BN curve with 256bit is used in SM9 algorithm

#define SM9_ASK_MEMORY_ERR 0x00000001      //申请内存失败
#define SM9_H_OUTRANGE 0x00000002          //签名H不属于[1,N-1]
#define SM9_DATA_MEMCMP_ERR 0x00000003     //数据对比不一致
#define SM9_MEMBER_ERR 0x00000004          //群的阶错误
#define SM9_MY_ECAP_12A_ERR 0x00000005     //R-ate对计算出现错误
#define SM9_S_NOT_VALID_G1 0x00000006      //S不属于群G1
#define SM9_G1BASEPOINT_SET_ERR 0x00000007 //G1基点设置错误
#define SM9_G2BASEPOINT_SET_ERR 0x00000008 //G2基点设置错误
#define SM9_L_error 0x00000009             //参数L错误
#define SM9_GEPUB_ERR 0x0000000A           //生成公钥错误
#define SM9_GEPRI_ERR 0x0000000B           //生成私钥错误
#define SM9_SIGN_ERR 0x0000000C            //签名错误
extern unsigned char dA[32];
extern unsigned char rand[32];
extern unsigned char h[32], S[64],T[64], C[64];
extern unsigned char Ppub[128], dSA[64],skID[128];
extern unsigned char Ppub[128], dSA[64];
extern unsigned char std_h[32];
extern unsigned char std_S[64];
extern unsigned char std_Ppub[128];
extern unsigned char std_dSA[64];
extern unsigned char hid[];
extern unsigned char *IDR;
extern unsigned char *message;



BOOL bytes128_to_ecn2(unsigned char Ppubs[], ecn2 *res);
void zzn12_ElementPrint(zzn12 x);
void ecn2_Bytes128_Print(ecn2 x);
void LinkCharZzn12(unsigned char *message, int len, zzn12 w, unsigned char *Z, int Zlen);
int Test_Point(epoint *point);
int Test_Range(big x);
int SM9_Init();
int SM9_H1(unsigned char Z[], int Zlen, big n, big h1);
int SM9_H2(unsigned char Z[], int Zlen, big n, big h2);
int SM9_GenerateSignKey(unsigned char hid[], unsigned char *ID, int IDlen, big ks, unsigned char Ppubs[], unsigned char dsa[], unsigned char skid[]);
int SM9_Sign(unsigned char hid[], unsigned char *IDR, unsigned char *message, int len, unsigned char rand[],
	unsigned char dsa[], unsigned char Ppub[], unsigned char H[], unsigned char S[]);
int SM9_Verify(unsigned char H[], unsigned char S[], unsigned char hid[],
	unsigned char *IDR, unsigned char *message, int len, unsigned char Ppub[]);
int SM9_SelfCheck();
int Signcrypt(unsigned char hid[], unsigned char *IDR, unsigned char *IDS, int IDlen,
	unsigned char *message, int mlen, unsigned char H[], unsigned char S[], unsigned char T[], unsigned char C[],
	unsigned char skID[], big ks, unsigned char Ppub[]);
int Unsigncrypt(unsigned char hid[], unsigned char *IDR, unsigned char *IDS, int IDlen,
	unsigned char *message, int mlen, unsigned char S[], unsigned char T[], unsigned char C[],
	unsigned char skID[], big ks, unsigned char Ppub[]);

#endif