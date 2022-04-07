/************************************************************
Note:
Codes here were downloaded from:
http://www.scctc.org.cn/templates/Download/index.aspx?nodeid=71.
The disclaimer was published on the link:
http://www.scctc.org.cn/Upload/accessory/20175/201755105494041082.pdf .
The codes were slightly modified to pass the check of C complier.
*************************************************************/

///************************************************************************
//  File name:    SM9_sv.c
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

#include "SM9_sv.h"
#include "kdf.h"

extern miracl *mip;
extern zzn2 X; //Frobniues constant

unsigned char SM9_q[32] = { 0xB6, 0x40, 0x00, 0x00, 0x02, 0xA3, 0xA6, 0xF1, 0xD6, 0x03, 0xAB, 0x4F, 0xF5, 0x8E, 0xC7, 0x45,
0x21, 0xF2, 0x93, 0x4B, 0x1A, 0x7A, 0xEE, 0xDB, 0xE5, 0x6F, 0x9B, 0x27, 0xE3, 0x51, 0x45, 0x7D };
unsigned char SM9_N[32] = { 0xB6, 0x40, 0x00, 0x00, 0x02, 0xA3, 0xA6, 0xF1, 0xD6, 0x03, 0xAB, 0x4F, 0xF5, 0x8E, 0xC7, 0x44,
0x49, 0xF2, 0x93, 0x4B, 0x18, 0xEA, 0x8B, 0xEE, 0xE5, 0x6E, 0xE1, 0x9C, 0xD6, 0x9E, 0xCF, 0x25 };

unsigned char SM9_P1x[32] = { 0x93, 0xDE, 0x05, 0x1D, 0x62, 0xBF, 0x71, 0x8F, 0xF5, 0xED, 0x07, 0x04, 0x48, 0x7D, 0x01, 0xD6,
0xE1, 0xE4, 0x08, 0x69, 0x09, 0xDC, 0x32, 0x80, 0xE8, 0xC4, 0xE4, 0x81, 0x7C, 0x66, 0xDD, 0xDD };
unsigned char SM9_P1y[32] = { 0x21, 0xFE, 0x8D, 0xDA, 0x4F, 0x21, 0xE6, 0x07, 0x63, 0x10, 0x65, 0x12, 0x5C, 0x39, 0x5B, 0xBC,
0x1C, 0x1C, 0x00, 0xCB, 0xFA, 0x60, 0x24, 0x35, 0x0C, 0x46, 0x4C, 0xD7, 0x0A, 0x3E, 0xA6, 0x16 };

unsigned char SM9_P2[128] = { 0x85, 0xAE, 0xF3, 0xD0, 0x78, 0x64, 0x0C, 0x98, 0x59, 0x7B, 0x60, 0x27, 0xB4, 0x41, 0xA0, 0x1F,
0xF1, 0xDD, 0x2C, 0x19, 0x0F, 0x5E, 0x93, 0xC4, 0x54, 0x80, 0x6C, 0x11, 0xD8, 0x80, 0x61, 0x41,
0x37, 0x22, 0x75, 0x52, 0x92, 0x13, 0x0B, 0x08, 0xD2, 0xAA, 0xB9, 0x7F, 0xD3, 0x4E, 0xC1, 0x20,
0xEE, 0x26, 0x59, 0x48, 0xD1, 0x9C, 0x17, 0xAB, 0xF9, 0xB7, 0x21, 0x3B, 0xAF, 0x82, 0xD6, 0x5B,
0x17, 0x50, 0x9B, 0x09, 0x2E, 0x84, 0x5C, 0x12, 0x66, 0xBA, 0x0D, 0x26, 0x2C, 0xBE, 0xE6, 0xED,
0x07, 0x36, 0xA9, 0x6F, 0xA3, 0x47, 0xC8, 0xBD, 0x85, 0x6D, 0xC7, 0x6B, 0x84, 0xEB, 0xEB, 0x96,
0xA7, 0xCF, 0x28, 0xD5, 0x19, 0xBE, 0x3D, 0xA6, 0x5F, 0x31, 0x70, 0x15, 0x3D, 0x27, 0x8F, 0xF2,
0x47, 0xEF, 0xBA, 0x98, 0xA7, 0x1A, 0x08, 0x11, 0x62, 0x15, 0xBB, 0xA5, 0xC9, 0x99, 0xA7, 0xC7 };

unsigned char SM9_t[32] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x00, 0x58, 0xF9, 0x8A };
unsigned char SM9_a[32] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char SM9_b[32] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 };

epoint *P1, *t, *s;
ecn2 P2,skIDr;
big N; //order of group, N(t)
big para_a, para_b, para_t, para_q;

/****************************************************************
Function:       bytes128_to_ecn2
Description:    convert 128 bytes into ecn2
Calls:          MIRACL functions
Called By:      SM9_Init
Input:          Ppubs[]
Output:         ecn2 *res
Return:         FALSE: execution error
TRUE: execute correctly
Others:
****************************************************************/
BOOL bytes128_to_ecn2(unsigned char Ppubs[], ecn2 *res)
{
	zzn2 x, y;
	big a, b;
	ecn2 r;
	r.x.a = mirvar(0);
	r.x.b = mirvar(0);
	r.y.a = mirvar(0);
	r.y.b = mirvar(0);
	r.z.a = mirvar(0);
	r.z.b = mirvar(0);
	r.marker = MR_EPOINT_INFINITY;

	x.a = mirvar(0);
	x.b = mirvar(0);
	y.a = mirvar(0);
	y.b = mirvar(0);
	a = mirvar(0);
	b = mirvar(0);

	bytes_to_big(BNLEN, Ppubs, b);
	bytes_to_big(BNLEN, Ppubs + BNLEN, a);
	zzn2_from_bigs(a, b, &x);
	bytes_to_big(BNLEN, Ppubs + BNLEN * 2, b);
	bytes_to_big(BNLEN, Ppubs + BNLEN * 3, a);
	zzn2_from_bigs(a, b, &y);

	return ecn2_set(&x, &y, res);
}

/****************************************************************
Function:       zzn12_ElementPrint
Description:    print all element of struct zzn12
Calls:          MIRACL functions
Called By:      SM9_Sign,SM9_Verify
Input:          zzn12 x
Output:         NULL
Return:         NULL
Others:
****************************************************************/
void zzn12_ElementPrint(zzn12 x)
{
	big tmp;
	tmp = mirvar(0);

	redc(x.c.b.b, tmp);
	cotnum(tmp, stdout);
	redc(x.c.b.a, tmp);
	cotnum(tmp, stdout);
	redc(x.c.a.b, tmp);
	cotnum(tmp, stdout);
	redc(x.c.a.a, tmp);
	cotnum(tmp, stdout);
	redc(x.b.b.b, tmp);
	cotnum(tmp, stdout);
	redc(x.b.b.a, tmp);
	cotnum(tmp, stdout);
	redc(x.b.a.b, tmp);
	cotnum(tmp, stdout);
	redc(x.b.a.a, tmp);
	cotnum(tmp, stdout);
	redc(x.a.b.b, tmp);
	cotnum(tmp, stdout);
	redc(x.a.b.a, tmp);
	cotnum(tmp, stdout);
	redc(x.a.a.b, tmp);
	cotnum(tmp, stdout);
	redc(x.a.a.a, tmp);
	cotnum(tmp, stdout);
}

/****************************************************************
Function:       ecn2_Bytes128_Print
Description:    print 128 bytes of ecn2
Calls:          MIRACL functions
Called By:      SM9_Sign,SM9_Verify
Input:          ecn2 x
Output:         NULL
Return:         NULL
Others:
****************************************************************/
void ecn2_Bytes128_Print(ecn2 x)
{
	big tmp;
	tmp = mirvar(0);

	redc(x.x.b, tmp);
	cotnum(tmp, stdout);
	redc(x.x.a, tmp);
	cotnum(tmp, stdout);
	redc(x.y.b, tmp);
	cotnum(tmp, stdout);
	redc(x.y.a, tmp);
	cotnum(tmp, stdout);
}

/****************************************************************
Function:       LinkCharZzn12
Description:    link two different types(unsigned char and zzn12)to one(unsigned char)
Calls:          MIRACL functions
Called By:      SM9_Sign,SM9_Verify
Input:          message:
len:    length of message
w:      zzn12 element
Output:         
Z:      the characters array stored message and w
Zlen:   length of Z
Return:         NULL
Others:
****************************************************************/
void LinkCharZzn12(unsigned char *message, int len, zzn12 w, unsigned char *Z, int Zlen)
{
	big tmp;

	tmp = mirvar(0);

	memcpy(Z, message, len);
	redc(w.c.b.b, tmp);
	big_to_bytes(BNLEN, tmp, Z + len, 1);
	redc(w.c.b.a, tmp);
	big_to_bytes(BNLEN, tmp, Z + len + BNLEN, 1);
	redc(w.c.a.b, tmp);
	big_to_bytes(BNLEN, tmp, Z + len + BNLEN * 2, 1);
	redc(w.c.a.a, tmp);
	big_to_bytes(BNLEN, tmp, Z + len + BNLEN * 3, 1);
	redc(w.b.b.b, tmp);
	big_to_bytes(BNLEN, tmp, Z + len + BNLEN * 4, 1);
	redc(w.b.b.a, tmp);
	big_to_bytes(BNLEN, tmp, Z + len + BNLEN * 5, 1);
	redc(w.b.a.b, tmp);
	big_to_bytes(BNLEN, tmp, Z + len + BNLEN * 6, 1);
	redc(w.b.a.a, tmp);
	big_to_bytes(BNLEN, tmp, Z + len + BNLEN * 7, 1);
	redc(w.a.b.b, tmp);
	big_to_bytes(BNLEN, tmp, Z + len + BNLEN * 8, 1);
	redc(w.a.b.a, tmp);
	big_to_bytes(BNLEN, tmp, Z + len + BNLEN * 9, 1);
	redc(w.a.a.b, tmp);
	big_to_bytes(BNLEN, tmp, Z + len + BNLEN * 10, 1);
	redc(w.a.a.a, tmp);
	big_to_bytes(BNLEN, tmp, Z + len + BNLEN * 11, 1);
}

/****************************************************************
Function:       Test_Point
Description:    test if the given point is on SM9 curve
Calls:
Called By:      SM9_Verify
Input:          point
Output:         null
Return:         0: success
1: not a valid point on curve
Others:
****************************************************************/
int Test_Point(epoint *point)
{
	big x, y, x_3, tmp;
	epoint *buf;

	x = mirvar(0);
	y = mirvar(0);
	x_3 = mirvar(0);
	tmp = mirvar(0);
	buf = epoint_init();

	//test if y^2=x^3+b
	epoint_get(point, x, y);
	power(x, 3, para_q, x_3); //x_3=x^3 mod p
	multiply(x, para_a, x);
	divide(x, para_q, tmp);
	add(x_3, x, x); //x=x^3+ax+b
	add(x, para_b, x);
	divide(x, para_q, tmp); //x=x^3+ax+b mod p
	power(y, 2, para_q, y); //y=y^2 mod p
	if (mr_compare(x, y) != 0)
		return 1;

	//test infinity
	ecurve_mult(N, point, buf);
	if (point_at_infinity(buf) == FALSE)
		return 1;

	return 0;
}

/****************************************************************
Function:       Test_Range
Description:    test if the big x belong to the range[1,n-1]
Calls:
Called By:      SM9_Verify
Input:          big x    ///a miracl data type
Output:         null
Return:         0: success
1: x==n,fail
Others:
****************************************************************/
int Test_Range(big x)
{
	big one, decr_n;

	one = mirvar(0);
	decr_n = mirvar(0);

	convert(1, one);
	decr(N, 1, decr_n);

	if ((mr_compare(x, one) < 0) | (mr_compare(x, decr_n) > 0))
		return 1;
	return 0;
}

/****************************************************************
Function:       SM9_Init
Description:    Initiate SM9 curve
Calls:          MIRACL functions
Called By:      SM9_SelfCheck
Input:          null
Output:         null
Return:         0: success;
7: base point P1 error
8: base point P2 error
Others:
****************************************************************/
int SM9_Init()
{
	big P1_x, P1_y;

	mip = mirsys(1000, 16);
	;
	mip->IOBASE = 16;

	para_q = mirvar(0);
	N = mirvar(0);
	P1_x = mirvar(0);
	P1_y = mirvar(0);
	para_a = mirvar(0);
	para_b = mirvar(0);
	para_t = mirvar(0);
	X.a = mirvar(0);
	X.b = mirvar(0);
	P2.x.a = mirvar(0);
	P2.x.b = mirvar(0);
	P2.y.a = mirvar(0);
	P2.y.b = mirvar(0);
	P2.z.a = mirvar(0);
	P2.z.b = mirvar(0);
	P2.marker = MR_EPOINT_INFINITY;

	P1 = epoint_init();
	bytes_to_big(BNLEN, SM9_q, para_q);
	bytes_to_big(BNLEN, SM9_P1x, P1_x);
	bytes_to_big(BNLEN, SM9_P1y, P1_y);
	bytes_to_big(BNLEN, SM9_a, para_a);
	bytes_to_big(BNLEN, SM9_b, para_b);
	bytes_to_big(BNLEN, SM9_N, N);
	bytes_to_big(BNLEN, SM9_t, para_t);

	mip->TWIST = MR_SEXTIC_M;
	ecurve_init(para_a, para_b, para_q, MR_PROJECTIVE); //Initialises GF(q) elliptic curve
														//MR_PROJECTIVE specifying projective coordinates

	if (!epoint_set(P1_x, P1_y, 0, P1))
		return SM9_G1BASEPOINT_SET_ERR;

	if (!(bytes128_to_ecn2(SM9_P2, &P2)))
		return SM9_G2BASEPOINT_SET_ERR;

	set_frobenius_constant(&X);

	return 0;
}

/****************************************************************
Function:       SM9_H1
Description:    function H1 in SM9 standard 5.4.2.2
Calls:          MIRACL functions,SM3_KDF
Called By:      SM9_Verify
Input:          Z:
Zlen:the length of Z
n:Frobniues constant X
Output:         h1=H1(Z,Zlen)
Return:         0: success;
1: asking for memory error
Others:
****************************************************************/
int SM9_H1(unsigned char Z[], int Zlen, big n, big h1)
{
	int hlen, i, ZHlen;
	big hh, i256, tmp, n1;
	unsigned char *ZH = NULL, *ha = NULL;

	hh = mirvar(0);
	i256 = mirvar(0);
	tmp = mirvar(0);
	n1 = mirvar(0);
	convert(1, i256);
	ZHlen = Zlen + 1;

	hlen = (int)ceil((5.0 * logb2(n)) / 32.0);
	decr(n, 1, n1);//减法
	ZH = (char *)malloc(sizeof(char) * (ZHlen + 1));
	if (ZH == NULL)
		return SM9_ASK_MEMORY_ERR;
	memcpy(ZH + 1, Z, Zlen);
	ZH[0] = 0x01;
	ha = (char *)malloc(sizeof(char) * (hlen + 1));
	if (ha == NULL)
		return SM9_ASK_MEMORY_ERR;
	SM3_KDF(ZH, ZHlen, hlen, ha);

	for (i = hlen - 1; i >= 0; i--) //key[???С]
	{
		premult(i256, ha[i], tmp);
		add(hh, tmp, hh);//hh=tmp+hh
		premult(i256, 256, i256);
		divide(i256, n1, tmp);
		divide(hh, n1, tmp);
	}
	incr(hh, 1, h1);
	free(ZH);
	free(ha);
	return 0;
}
/****************************************************************
Function:       SM9_H2
Description:    function H2 in SM9 standard 5.4.2.3
Calls:          MIRACL functions,SM3_KDF
Called By:      SM9_Sign,SM9_Verify
Input:          Z:
Zlen:the length of Z
n:Frobniues constant X
Output:         h2=H2(Z,Zlen)
Return:         0: success;
1: asking for memory error
Others:
****************************************************************/
int SM9_H2(unsigned char Z[], int Zlen, big n, big h2)
{
	int hlen, ZHlen, i;
	big hh, i256, tmp, n1;
	unsigned char *ZH = NULL, *ha = NULL;

	hh = mirvar(0);
	i256 = mirvar(0);
	tmp = mirvar(0);
	n1 = mirvar(0);
	convert(1, i256);
	ZHlen = Zlen + 1;

	hlen = (int)ceil((5.0 * logb2(n)) / 32.0);
	decr(n, 1, n1);
	ZH = (char *)malloc(sizeof(char) * (ZHlen + 1));
	if (ZH == NULL)
		return SM9_ASK_MEMORY_ERR;
	memcpy(ZH + 1, Z, Zlen);
	ZH[0] = 0x02;
	ha = (char *)malloc(sizeof(char) * (hlen + 1));
	if (ha == NULL)
		return SM9_ASK_MEMORY_ERR;
	SM3_KDF(ZH, ZHlen, hlen, ha);

	for (i = hlen - 1; i >= 0; i--) //key[???С]
	{
		premult(i256, ha[i], tmp);
		add(hh, tmp, hh);
		premult(i256, 256, i256);
		divide(i256, n1, tmp);
		divide(hh, n1, tmp);
	}
	incr(hh, 1, h2);
	free(ZH);
	free(ha);
	return 0;
}

/****************************************************************
Function:       SM9_GenerateSignKey
Description:    Generate Signed key
Calls:          MIRACL functions,SM9_H1,xgcd,ecn2_Bytes128_Print
Called By:      SM9_SelfCheck
Input:          
1	hid:0x01
2	ID:identification
3	IDlen:the length of ID
4	ks:master private key used to generate signature public key and private key
Output:         
1	Ppub:signature public key
2	dSA: signature private key
Return:         0: success;
1: asking for memory error
Others:
****************************************************************/
int SM9_GenerateSignKey(unsigned char hid[], unsigned char *ID, int IDlen, big ks, 
	unsigned char Ppubs[], unsigned char dsa[], unsigned char skid[])
{
	big h1, t1, t2, rem, xdSA, ydSA, tmp;
	unsigned char *Z = NULL;
	int Zlen = IDlen + 1, buf;
	ecn2 Ppub; //in G2
	epoint *dSA; //in G1

	h1 = mirvar(0);
	t1 = mirvar(0);
	t2 = mirvar(0);
	rem = mirvar(0);
	tmp = mirvar(0);
	xdSA = mirvar(0);
	ydSA = mirvar(0);
	dSA = epoint_init();
	Ppub.x.a = mirvar(0);
	Ppub.x.b = mirvar(0);
	Ppub.y.a = mirvar(0);
	Ppub.y.b = mirvar(0);
	Ppub.z.a = mirvar(0);
	Ppub.z.b = mirvar(0);
	Ppub.marker = MR_EPOINT_INFINITY;
	skIDr.x.a = mirvar(0);
	skIDr.x.b = mirvar(0);
	skIDr.y.a = mirvar(0);
	skIDr.y.b = mirvar(0);
	skIDr.z.a = mirvar(0);
	skIDr.z.b = mirvar(0);
	skIDr.marker = MR_EPOINT_INFINITY;

	Z = (char *)malloc(sizeof(char) * (Zlen + 1));
	if (!(Z))
		return 1;
	memcpy(Z, ID, IDlen);//Z=ID 字符串拷贝
	memcpy(Z + IDlen, hid, 1); //将hid追加到ID后
	buf = SM9_H1(Z, Zlen, N, h1);//h1哈希，得到buf=H1(IDR||hid,N)
	cotnum(h1, stdout);
	if (buf != 0)
		return buf;
	add(h1, ks, t1);         //t1=H1(IDR||hid,N)+ks
	xgcd(t1, N, t1, t1, t1); //t1=t1(-1)
	multiply(ks, t1, t2);
	divide(t2, N, rem); //t2=ks*t1(-1)

	ecn2_copy(&P2, &skIDr);
	ecn2_mul(t2, &skIDr); //skID=[ks]P2
	printf("\n*********************The signed key skIDr= (xskID, yskID): *********************\n");
	ecn2_Bytes128_Print(skIDr);//输出解密私钥

	//Ppub=[ks]P2
	ecn2_copy(&P2, &Ppub);
	ecn2_mul(ks, &Ppub);

	redc(skIDr.x.b, tmp);
	big_to_bytes(BNLEN, tmp, skid, 1);
	redc(skIDr.x.a, tmp);
	big_to_bytes(BNLEN, tmp, skid + BNLEN, 1);
	redc(skIDr.y.b, tmp);
	big_to_bytes(BNLEN, tmp, skid + BNLEN * 2, 1);
	redc(skIDr.y.a, tmp);
	big_to_bytes(BNLEN, tmp, skid + BNLEN * 3, 1);
	printf("\n**********************PublicKey Ppubs=[ks]P2: *************************\n");
	ecn2_Bytes128_Print(Ppub);//输出主公钥

	redc(Ppub.x.b, tmp);
	big_to_bytes(BNLEN, tmp, Ppubs, 1);
	redc(Ppub.x.a, tmp);
	big_to_bytes(BNLEN, tmp, Ppubs + BNLEN, 1);
	redc(Ppub.y.b, tmp);
	big_to_bytes(BNLEN, tmp, Ppubs + BNLEN * 2, 1);
	redc(Ppub.y.a, tmp);
	big_to_bytes(BNLEN, tmp, Ppubs + BNLEN * 3, 1);

	free(Z);
	return 0;
}

///****************************************************************
//Function:       SM9_Sign
//Description:    SM9 signature algorithm
//Calls:          MIRACL functions,zzn12_init(),ecap(),member(),zzn12_ElementPrint(),
//zzn12_pow(),LinkCharZzn12(),SM9_H2()
//Called By:      SM9_SelfCheck()
//Input:
//hid:0x01
//IDR          //identification of userA
//message      //the message to be signed
//len          //the length of message
//rand         //a random number K lies in [1,N-1]
//dSA          //signature private key
//Ppubs        //signature public key
//Output:         H,S        //signature result
//Return:         0: success
//1: asking for memory error
//4: element is out of order q
//5: R-ate calculation error
//9: parameter L error
//Others:
//****************************************************************/
//int SM9_Sign(unsigned char hid[], unsigned char *IDR, unsigned char *message, int len, unsigned char rand[],
//	unsigned char dsa[], unsigned char Ppub[], unsigned char H[], unsigned char S[], unsigned char skID[], big ks)
//{
//	big h1, r, h, l, xdSA, ydSA,xQB,yQB;
//	big xS, yS, tmp, zero;
//	zzn12 g, w;
//	epoint *s, *dSA,*QB;
//	ecn2 Ppubs;
//	ecn2 skIDs;
//	int Zlen, Zlen1, buf;
//	unsigned char *Z = NULL;
//	unsigned char *Z1 = NULL;
//
//	//initiate
//	h1 = mirvar(0);
//	r = mirvar(0);
//	h = mirvar(0);
//	l = mirvar(0);
//	tmp = mirvar(0);
//	zero = mirvar(0);
//	xS = mirvar(0);
//	yS = mirvar(0);
//	xdSA = mirvar(0);
//	ydSA = mirvar(0);
//	s = epoint_init();
//	dSA = epoint_init();
//	Ppubs.x.a = mirvar(0);
//	Ppubs.x.b = mirvar(0);
//	Ppubs.y.a = mirvar(0);
//	Ppubs.y.b = mirvar(0);
//	Ppubs.z.a = mirvar(0);
//	Ppubs.z.b = mirvar(0);
//
//	skIDs.x.a = mirvar(0);
//	skIDs.x.b = mirvar(0);
//	skIDs.y.a = mirvar(0);
//	skIDs.y.b = mirvar(0);
//	skIDs.z.a = mirvar(0);
//	skIDs.z.b = mirvar(0);
//	skIDs.marker = MR_EPOINT_INFINITY;
//	zzn12_init(&g);
//	zzn12_init(&w);
//
//	bytes_to_big(BNLEN, rand, r);
//	bytes_to_big(BNLEN, dsa, xdSA);
//	bytes_to_big(BNLEN, dsa + BNLEN, ydSA);
//	epoint_set(xdSA, ydSA, 0, dSA);
//	bytes128_to_ecn2(Ppub, &Ppubs);
//	bytes128_to_ecn2(Ppub, &skIDs);
//
//	//Step1:g = e(P1, Ppub-s)
//	if (!ecap(Ppubs, P1, para_t, X, &g))
//		return SM9_MY_ECAP_12A_ERR;
//	//test if a ZZn12 element is of order q
//	if (!member(g, para_t, X))
//		return SM9_MEMBER_ERR;
//
//	printf("\n***********************g=e(P1,Ppubs):****************************\n");
//	zzn12_ElementPrint(g);//打印g中所有元素
//
//	//Step2:calculate w=g(r)
//	printf("\n***********************randnum r:********************************\n");
//	cotnum(r, stdout);
//	w = zzn12_pow(g, r);//w=g^r
//	printf("\n***************************w=gr:**********************************\n");
//	zzn12_ElementPrint(w);
//
//	//Step3:calculate h=H2(M||w,N)
//	Zlen = len + 32 * 12;
//	Z = (char *)malloc(sizeof(char) * (Zlen + 1));
//	if (Z == NULL)
//		return SM9_ASK_MEMORY_ERR;
//
//	LinkCharZzn12(message, len, w, Z, Zlen);//Z=M||message
//	buf = SM9_H2(Z, Zlen, N, h);
//	if (buf != 0)
//		return buf;
//	printf("\n****************************h:*************************************\n");
//	cotnum(h, stdout);
//
//	//Step4:l=(r-h)mod N
//	subtract(r, h, l);
//	divide(l, N, tmp);
//	while (mr_compare(l, zero) < 0)
//		add(l, N, l);
//	if (mr_compare(l, zero) == 0)
//		return SM9_L_error;
//	printf("\n**************************l=(r-h)mod N:****************************\n");
//	cotnum(l, stdout);
//
//	//Step5:S=[l]dSA=(xS,yS)
//	ecurve_mult(l, dSA, s);
//	epoint_get(s, xS, yS);
//	printf("\n**************************S=[l]dSA=(xS,yS):*************************\n");
//	cotnum(xS, stdout);
//	cotnum(yS, stdout);
//
//	big_to_bytes(32, h, H, 1);
//	big_to_bytes(32, xS, S, 1);
//	big_to_bytes(32, yS, S + 32, 1);
//
//	free(Z);
//	free(Z1);
//	return 0;
//}
///****************************************************************
//Function:       SM9_Verify
//Description:    SM9 signature verification algorithm
//Calls:          MIRACL functions,zzn12_init(),Test_Range(),Test_Point(),
//ecap(),member(),zzn12_ElementPrint(),SM9_H1(),SM9_H2()
//Called By:      SM9_SelfCheck()
//Input:
//H,S          //signature result used to be verified
//hid          //identification
//IDA          //identification of userA
//message      //the message to be signed
//len          //the length of message
//Ppubs        //signature public key
//Output:         NULL
//Return:         0: success
//1: asking for memory error
//2: H is not in the range[1,N-1]
//6: S is not on the SM9 curve
//4: element is out of order q
//5: R-ate calculation error
//3: h2!=h,comparison error
//Others:
//****************************************************************/
//int SM9_Verify(unsigned char H[], unsigned char S[], unsigned char hid[], unsigned char *IDR, unsigned char *message, int len,
//	unsigned char Ppub[])
//{
//	big h, xS, yS, h1, h2;
//	epoint *S1;
//	zzn12 g, t, u, w;
//	ecn2 P, Ppubs;
//	int Zlen1, Zlen2, buf;
//	unsigned char *Z1 = NULL, *Z2 = NULL;
//
//	h = mirvar(0);
//	h1 = mirvar(0);
//	h2 = mirvar(0);
//	xS = mirvar(0);
//	yS = mirvar(0);
//	P.x.a = mirvar(0);
//	P.x.b = mirvar(0);
//	P.y.a = mirvar(0);
//	P.y.b = mirvar(0);
//	P.z.a = mirvar(0);
//	P.z.b = mirvar(0);
//	P.marker = MR_EPOINT_INFINITY;
//	Ppubs.x.a = mirvar(0);
//	Ppubs.x.b = mirvar(0);
//	Ppubs.y.a = mirvar(0);
//	Ppubs.y.b = mirvar(0);
//	Ppubs.z.a = mirvar(0);
//	Ppubs.z.b = mirvar(0);
//	Ppubs.marker = MR_EPOINT_INFINITY;
//	S1 = epoint_init();
//	zzn12_init(&g), zzn12_init(&t);
//	zzn12_init(&u);
//	zzn12_init(&w);
//
//	bytes_to_big(BNLEN, H, h);
//	bytes_to_big(BNLEN, S, xS);
//	bytes_to_big(BNLEN, S + BNLEN, yS);
//	bytes128_to_ecn2(Ppub, &Ppubs);
//
//	//Step 1:test if h in the rangge [1,N-1]
//	if (Test_Range(h))
//		return SM9_H_OUTRANGE;
//
//	//Step 2:test if S is on G1
//	epoint_set(xS, yS, 0, S1);
//	if (Test_Point(S1))
//		return SM9_S_NOT_VALID_G1;
//
//	//Step3:g = e(P1, Ppub-s)
//	if (!ecap(Ppubs, P1, para_t, X, &g))
//		return SM9_MY_ECAP_12A_ERR;
//	//test if a ZZn12 element is of order q
//	if (!member(g, para_t, X))
//		return SM9_MEMBER_ERR;
//
//	printf("\n***********************g=e(P1,Ppubs): ****************************\n");
//	zzn12_ElementPrint(g);
//
//	//Step4:calculate t=g(h)
//	t = zzn12_pow(g, h);
//	printf("\n***************************w=gh: **********************************\n");
//	zzn12_ElementPrint(t);
//
//	//Step5:calculate h1=H1(IDR||hid,N)
//	Zlen1 = strlen(IDR) + 1;
//	Z1 = (char *)malloc(sizeof(char) * (Zlen1 + 1));
//	if (Z1 == NULL)
//		return SM9_ASK_MEMORY_ERR;
//
//	memcpy(Z1, IDR, strlen(IDR));
//	memcpy(Z1 + strlen(IDR), hid, 1);
//	buf = SM9_H1(Z1, Zlen1, N, h1);
//	if (buf != 0)
//		return buf;
//	printf("\n****************************h1: **********************************\n");
//	cotnum(h1, stdout);
//
//	//Step6:P=[h1]P2+Ppubs
//	ecn2_copy(&P2, &P);
//	ecn2_mul(h1, &P);
//	ecn2_add(&Ppubs, &P);
//
//	//Step7:u=e(S1,P)
//	if (!ecap(P, S1, para_t, X, &u))
//		return SM9_MY_ECAP_12A_ERR;
//	//test if a ZZn12 element is of order q
//	if (!member(u, para_t, X))
//		return SM9_MEMBER_ERR;
//	printf("\n************************** u=e(S1,P): *****************************\n");
//	zzn12_ElementPrint(u);
//
//	//Step8:w=u*t
//	zzn12_mul(u, t, &w);
//	printf("\n*************************  w=u*t: **********************************\n");
//	zzn12_ElementPrint(w);
//
//	//Step9:h2=H2(M||w,N)
//	Zlen2 = len + 32 * 12;
//	Z2 = (char *)malloc(sizeof(char) * (Zlen2 + 1));
//	if (Z2 == NULL)
//		return SM9_ASK_MEMORY_ERR;
//
//	LinkCharZzn12(message, len, w, Z2, Zlen2);
//	buf = SM9_H2(Z2, Zlen2, N, h2);
//	if (buf != 0)
//		return buf;
//	printf("\n**************************** h2: ***********************************\n");
//	cotnum(h2, stdout);
//
//	free(Z1);
//	free(Z2);
//	if (mr_compare(h2, h) != 0)
//		return SM9_DATA_MEMCMP_ERR;
//
//	return 0;
//}


/****************************************************************
Function:Signcrypt
Description: SM9 encryption algorithm Calls:
Called By:
Input:MIRACL functions,zzn12_init(),ecap(),member(),zzn12_ElementPrint(), zzn12_pow(),LinkCharZzn12(),SM3_KDF(),SM9_Enc_MAC(),SM4_Block_Encrypt() SM9_SelfCheck()
hid:0x03 IDB
message len
rand EncID
k1_len k2_len Ppubs
Output: Return:
0: success 1: asking for memory error 2: element is out of order q 3: R-ate calculation error A: K1 equals 0
Others:
****************************************************************/
int Signcrypt(unsigned char hid[], unsigned char *IDR, unsigned char *IDS, int IDlen, 
	unsigned char *message, int mlen,unsigned char H[], unsigned char S[], unsigned char T[], unsigned char C[],
	unsigned char skID[], big ks, unsigned char Ppub[])
{
	printf("-----------------------------------begin----------------------------\n");
	big h1, r, h, l, xQB, yQB,x,y,t1,t2,rem,C2_b;
	big xS, yS, xT, yT, tmp, zero;
	zzn12 g, w;
	epoint  *dSA, *QB,*skID_s,*P_temp;//skIDs:发送者私钥 s:签名
	ecn2 Ppube;
	ecn2 skIDs;
	int Zlen,Zlens=IDlen+1, buf,klen;//Zlens为IDS字符串长度
	unsigned char *Z = NULL,*Z1 = NULL,*C2 = NULL, *K = NULL;

	//initiate
	h1 = mirvar(0);
	x = mirvar(0);
	y = mirvar(0);
	r = mirvar(0);
	h = mirvar(0);
	l = mirvar(0);
	t1 = mirvar(0); 
	t2  = mirvar(0);
	rem = mirvar(0);
	tmp = mirvar(0);
	zero = mirvar(0);
	xS = mirvar(0);
	yS = mirvar(0);
	xT = mirvar(0);
	yT = mirvar(0);
	xQB = mirvar(0);
	yQB = mirvar(0);
	C2_b = mirvar(0);
	s = epoint_init();
	t = epoint_init();
	dSA = epoint_init();
	QB = epoint_init();
	P_temp = epoint_init();
	skID_s = epoint_init();
	Ppube.x.a = mirvar(0);
	Ppube.x.b = mirvar(0);
	Ppube.y.a = mirvar(0);
	Ppube.y.b = mirvar(0);
	Ppube.z.a = mirvar(0);
	Ppube.z.b = mirvar(0);
	Ppube.marker = MR_EPOINT_INFINITY;

	skIDs.x.a = mirvar(0);
	skIDs.x.b = mirvar(0);
	skIDs.y.a = mirvar(0);
	skIDs.y.b = mirvar(0);
	skIDs.z.a = mirvar(0);
	skIDs.z.b = mirvar(0);
	skIDs.marker = MR_EPOINT_INFINITY;

	bytes128_to_ecn2(Ppub, &Ppube);

	zzn12_init(&g);
	zzn12_init(&w);
	bytes_to_big(BNLEN, Ppub, x); 
	bytes_to_big(BNLEN, Ppub + BNLEN, y);
	//Ppub=[ks]P2
	ecn2_copy(&P2, &Ppube);
	ecn2_mul(ks, &Ppube);
	//计算skIDs
	Z1 = (char *)malloc(sizeof(char) * (Zlens + 1));
	if (!(Z1))
		return 1;
	memcpy(Z1, IDS, IDlen);//Z=ID 字符串拷贝
	memcpy(Z1 + IDlen, hid, 1); //将hid追加到ID后

	buf = SM9_H1(Z1, Zlens, N, h1);//h1哈希，得到buf=H1(IDR||hid,N)
	if (buf != 0)
		return buf;
	add(h1, ks, t1);         //t1=H1(IDS||hid,N)+ks
	xgcd(t1, N, t1, t1, t1); //t1=t1(-1)
	multiply(ks, t1, t2);
	divide(t2, N, rem); //t2=ks*t1(-1)

	ecn2_copy(&P2, &skIDs);
	ecn2_mul(t2, &skIDs); //skID=[ks]P2
	printf("\n*********************The encrypted private  key skIDs = (xskID, yskID): *********************\n");
	ecn2_Bytes128_Print(skIDs);//输出加密私钥
	free(Z1);

	
	//A0:  计算g=e(P1,Ppub)
	printf("\n================testppub=====================\n");
	ecn2_Bytes128_Print(Ppube);

	if (!ecap(Ppube, P1, para_t, X, &g)) 
		return SM9_MY_ECAP_12A_ERR;
	//test if a ZZn12 element is of order q 
	if(!member(g, para_t, X)) 
		return SM9_MEMBER_ERR; 
	printf("\n***********************g=e(P1,Ppub):****************************\n"); 
	zzn12_ElementPrint(g);

	//A1: calculate QB=（H1(idR||hid,N))P1+[ks]p1
	Zlen = strlen(IDR) + 1;
	Z = (char *)malloc(sizeof(char)*(Zlen + 1));
	if (Z == NULL) 
		return SM9_ASK_MEMORY_ERR;
	memcpy(Z, IDR, strlen(IDR)); //字符串拷贝
	memcpy(Z + strlen(IDR), hid, 1); //将hid追加到ID 后
	buf = SM9_H1(Z, Zlen, N, h); //h1哈希，得到buf=h=H1(IDR||hid,N)
	//if (buf)
	//	return buf;
	ecurve_mult(h, P1, QB); //QB=[h]P1
	ecurve_mult(ks, P1, P_temp);//P_temp=[ks]P1
	ecurve_add(P_temp, QB);//QB=（H1(idR||hid,N))P1+[ks]p1
	printf("\n*******************QB=（H1(idR||hid,N))P1+[ks]p1*****************\n");
	epoint_get(QB, xQB, yQB);
	cotnum(xQB, stdout);
	cotnum(yQB, stdout);
	free(Z);

	//A2: randnom
	bytes_to_big(BNLEN, rand, r); 
	bigrand(N, r);
	printf("\n***********************randnum r:********************************\n"); 
	cotnum(r, stdout);
	
	//A3: w=g^r
	w = zzn12_pow(g, r);
	printf("\n***************************w=g^r:**********************************\n"); 
	zzn12_ElementPrint(w);
	
	//A4: calculate h=H2(M||w,N)
	Zlen = mlen + 32 * 12;
	Z = (char *)malloc(sizeof(char) * (Zlen + 1));
	if (Z == NULL)
		return SM9_ASK_MEMORY_ERR;

	LinkCharZzn12(message, mlen, w, Z, Zlen);//Z=w||message
	buf = SM9_H2(Z, Zlen, N, h);
	if (buf != 0)
		return buf;
	printf("\n****************************h:*************************************\n");
	cotnum(h, stdout);

	//A5: l=(r-h)mod N
	subtract(r, h, l);
	divide(l, N, tmp);
	while (mr_compare(l, zero) < 0)
		add(l, N, l);
	if (mr_compare(l, zero) == 0)
		return SM9_L_error;
	printf("\n**************************l=(r-h)mod N:****************************\n");
	cotnum(l, stdout);
	
	//A6: 计算G1中元素S=[l][t2]p1
	ecurve_mult(t2, P1, s);//s= [t2]P1
	ecurve_mult(l, s, s);//s= l*[t2]P1
	epoint_get(s, xS, yS);
	printf("\n**************************S=[l]dSA=(xS,yS):*************************\n");
	cotnum(xS, stdout);
	cotnum(yS, stdout);
	big_to_bytes(32, xS, S, 1);
	big_to_bytes(32, yS, S + 32, 1);
	
	//A7: 计算G1中元素T = rQ
	ecurve_mult(r, QB, t);//s= l*[t2]P1
	epoint_get(t, xT, yT);
	big_to_bytes(32, xT, T, 1);
	big_to_bytes(32, yT, T + 32, 1);
	printf("\n**************************T = [r]Q=(xT,yT):*************************\n");
	cotnum(xT, stdout);
	cotnum(yT, stdout);
	free(Z);

	//A8: 计算比特串 c XOR H3(T||w||IDR)
	klen= mlen+32; 
	Zlen=strlen(IDR) + BNLEN*14; 
	Z=(char *)malloc(sizeof(char)*(Zlen+1)); 
	K=(char *)malloc(sizeof(char)*(klen+1)); 
	C2=(char *)malloc(sizeof(char)*(mlen+1)); 
	if(Z==NULL|| K==NULL|| C2==NULL) 
		return SM9_ASK_MEMORY_ERR;
	LinkCharZzn12(t, BNLEN * 2, w, Z, (Zlen - strlen(IDR))); 
	memcpy(Z + BNLEN * 14, IDR, strlen(IDR)); 
	SM3_KDF(Z, Zlen, klen, K); 
	printf("\n*****************K=KDF(T||w||IDR),klen):***********************\n"); 
	for (int i = 0; i<klen; i++) 
		printf("%02x", K[i]);
	printf("\n   calculate C2=M^K1   \n");


	printf("\n*****************c XOR H3(T||w||IDR) :***********************\n");
	for (int i = 0; i<mlen; i++) {
		int j = 0;
		if (K[i] == 0) j = j + 1;
		C2[i] = message[i] ^ K[i];
	}
	for (int i = 0; i < strlen(message); i++)
	{
		printf("%02x", message[i]);
	}
	printf("\n");
	//C = (char *)malloc(sizeof(char)*(mlen + 1));
	memcpy(C,C2,strlen(message));
	for (int i = 0; i < strlen(message); i++)
	{
		printf("%02x", C[i]);
	}

	free(Z); 
	free(K); 
	free(C2);
//	free(C);
	return 0;

}


int Unsigncrypt(unsigned char hid[], unsigned char *IDR, unsigned char *IDS, int IDlen,
	unsigned char *message, int mlen,  unsigned char S[], unsigned char T[], unsigned char C[],
	unsigned char skID[], big ks, unsigned char Ppub[])
{
	big h_,h;
	zzn12 g_, w_,w_1, t_, w_fin;			//用于计算w'和t=g^(h')
	ecn2 P,Ppubs;
	int klen,Zlen,buf;
	unsigned char *Z = NULL, *Z1 = NULL, *C2 = NULL, *K = NULL, *M_ = NULL;
	printf("\n--------------------------------begin B------------------------------------\n");
		
	//init
	h = mirvar(0);
	h_ = mirvar(0);
	zzn12_init(&g_);
	zzn12_init(&w_);
	zzn12_init(&w_1);
	zzn12_init(&t_);
	zzn12_init(&w_fin);
	P.x.a = mirvar(0);
	P.x.b = mirvar(0);
	P.y.a = mirvar(0);
	P.y.b = mirvar(0);
	P.z.a = mirvar(0);
	P.z.b = mirvar(0);
	Ppubs.x.a = mirvar(0);
	Ppubs.x.b = mirvar(0);
	Ppubs.y.a = mirvar(0);
	Ppubs.y.b = mirvar(0);
	Ppubs.z.a = mirvar(0);
	Ppubs.z.b = mirvar(0);
	Ppubs.marker = MR_EPOINT_INFINITY;
	P.marker = MR_EPOINT_INFINITY;

	bytes128_to_ecn2(Ppub, &Ppubs);



	//B1: w' = e(T, skIDr)
	if (!ecap(skIDr, t, para_t, X, &w_))
		return SM9_MY_ECAP_12A_ERR;
	printf("\n=====================w' = e(T, skIDr):====================\n");
	zzn12_ElementPrint(w_);

	//B2: M'=c XOR H3(T||w'||IDR)
	klen = mlen + 32;
	Zlen = strlen(IDR) + BNLEN * 14;
	Z = (char *)malloc(sizeof(char)*(Zlen + 1));
	K = (char *)malloc(sizeof(char)*(klen + 1));
	M_ = (char *)malloc(sizeof(char)*(mlen + 1));
	//if (Z == NULL || K == NULL || C2 == NULL)
	//	return SM9_ASK_MEMORY_ERR;
	LinkCharZzn12(t, BNLEN * 2, w_, Z, (Zlen - strlen(IDR)));
	memcpy(Z + BNLEN * 14, IDR, strlen(IDR));
	SM3_KDF(Z, Zlen, klen, K);
	printf("\n=====================K=KDF(T||w||IDR),klen):=====================\n");
	for (int i = 0; i<klen; i++)
		printf("%02x", K[i]);
	//printf("\n   calculate C2=M^K1   \n");


	printf("\n=====================c XOR H3(T||w||IDR) :=====================\n");
	for (int i = 0; i<mlen; i++) {
		int j = 0;
		if (K[i] == 0) j = j + 1;
		M_[i] = C[i] ^ K[i];
	}
	for (int i = 0; i < strlen(M_); i++)
	{
		printf("%02x", M_[i]);
	}
	printf("\n");
	//C = (char *)malloc(sizeof(char)*(mlen + 1));
	//memcpy(C, C2, strlen(message));
	//for (int i = 0; i < strlen(message); i++)
	//{
	//	printf("%02x", C[i]);
	//}
	free(Z);
	free(K);
	

	//B3: h'=H2(M'||w',N)
	Zlen = mlen + 32 * 12;
	Z = (char *)malloc(sizeof(char) * (Zlen + 1));
	if (Z == NULL)
		return SM9_ASK_MEMORY_ERR;
	LinkCharZzn12(M_, mlen, w_, Z, Zlen);//Z=w||message
	buf = SM9_H2(Z, Zlen, N, h_);
	if (buf != 0)
		return buf;
	printf("\n****************************h':*************************************\n");
	cotnum(h_, stdout);
	free(Z);

	//A0:  计算g=e(P1,Ppub)
	printf("\n================testppub=====================\n");
	ecn2_Bytes128_Print(Ppubs);
	if (!ecap(Ppubs, P1, para_t, X, &g_))
		return SM9_MY_ECAP_12A_ERR;
	//test if a ZZn12 element is of order q 
	if (!member(g_, para_t, X))
		return SM9_MEMBER_ERR;
	printf("\n***********************g=e(P1,Ppub):****************************\n");
	zzn12_ElementPrint(g_);

	//B4: 计算GT中元素t=g^(h')
	t_ = zzn12_pow(g_, h_);
	printf("\n***************************t=g^(h'):**********************************\n");
	zzn12_ElementPrint(t_);

	//B5: 计算G2中元素P = H1(IDS||hid,N)+Ppub
	Zlen = strlen(IDS) + 1;
	Z = (char *)malloc(sizeof(char)*(Zlen + 1));
	if (Z == NULL)
		return SM9_ASK_MEMORY_ERR;
	memcpy(Z, IDS, strlen(IDS)); //字符串拷贝
	memcpy(Z + strlen(IDS), hid, 1); //将hid追加到ID 后
	buf = SM9_H1(Z, Zlen, N, h); //h1哈希，得到buf=h=H1(IDS||hid,N)
	 if (buf)
		 	return buf;

	ecn2_copy(&P2, &P);
	ecn2_mul(h, &P); //skID=[H1(IDS||hid,N)]P2
	ecn2_add(&Ppubs, &P);//P = [H1(IDS||hid,N)]P2+Ppub
	printf("\n*******************P = [H1(IDS||hid,N)]P2+Ppub*****************\n");
	ecn2_Bytes128_Print(P);
	free(Z);
	
	//B6: 检验[e(S,P)]t=w'是否成立
	ecap(P, s, para_t, X, &w_1);
	zzn12_mul(w_1,t_,&w_fin);
	printf("\n*******************FINAL-WFIN*****************\n");

	zzn12_ElementPrint(w_fin);
	printf("\n*******************FINAL-W    *****************\n");

	zzn12_ElementPrint(w_);
	free(M_);
	return 0;
}

/****************************************************************
Function:       SM9_SelfCheck
Description:    SM9 self check
Calls:          MIRACL functions,SM9_Init(),SM9_GenerateSignKey(),
SM9_Sign,SM9_Verify
Called By:
Input:
Output:
Return:         0: self-check success
1: asking for memory error
2: H is not in the range[1,N-1]
3: h2!=h,comparison error
4: element is out of order q
5: R-ate calculation error
6: S is not on the SM9 curve
7: base point P1 error
8: base point P2 error
9: parameter L error
A: public key generated error
B: private key generated error
C: signature result error
Others:
****************************************************************/
int SM9_SelfCheck()
{
	//the master private key
	unsigned char dA[32] = { 0x00, 0x01, 0x30, 0xE7, 0x84, 0x59, 0xD7, 0x85, 0x45, 0xCB, 0x54, 0xC5, 0x87, 0xE0, 0x2C, 0xF4,
		0x80, 0xCE, 0x0B, 0x66, 0x34, 0x0F, 0x31, 0x9F, 0x34, 0x8A, 0x1D, 0x5B, 0x1F, 0x2D, 0xC5, 0xF4 };

	unsigned char rand[32] = { 0x00, 0x03, 0x3C, 0x86, 0x16, 0xB0, 0x67, 0x04, 0x81, 0x32, 0x03, 0xDF, 0xD0, 0x09, 0x65, 0x02,
		0x2E, 0xD1, 0x59, 0x75, 0xC6, 0x62, 0x33, 0x7A, 0xED, 0x64, 0x88, 0x35, 0xDC, 0x4B, 0x1C, 0xBE };

	unsigned char h[32], S[64], T[64], C[64]; // Signature
	unsigned char Ppub[128], dSA[64], skID[128];

	//unsigned char std_h[32] = { 0x82, 0x3C, 0x4B, 0x21, 0xE4, 0xBD, 0x2D, 0xFE, 0x1E, 0xD9, 0x2C, 0x60, 0x66, 0x53, 0xE9, 0x96,
	//	0x66, 0x85, 0x63, 0x15, 0x2F, 0xC3, 0x3F, 0x55, 0xD7, 0xBF, 0xBB, 0x9B, 0xD9, 0x70, 0x5A, 0xDB };

	//unsigned char std_S[64] = { 0x73, 0xBF, 0x96, 0x92, 0x3C, 0xE5, 0x8B, 0x6A, 0xD0, 0xE1, 0x3E, 0x96, 0x43, 0xA4, 0x06, 0xD8,
	//	0xEB, 0x98, 0x41, 0x7C, 0x50, 0xEF, 0x1B, 0x29, 0xCE, 0xF9, 0xAD, 0xB4, 0x8B, 0x6D, 0x59, 0x8C,
	//	0x85, 0x67, 0x12, 0xF1, 0xC2, 0xE0, 0x96, 0x8A, 0xB7, 0x76, 0x9F, 0x42, 0xA9, 0x95, 0x86, 0xAE,
	//	0xD1, 0x39, 0xD5, 0xB8, 0xB3, 0xE1, 0x58, 0x91, 0x82, 0x7C, 0xC2, 0xAC, 0xED, 0x9B, 0xAA, 0x05 };

	//unsigned char std_Ppub[128] = { 0x9F, 0x64, 0x08, 0x0B, 0x30, 0x84, 0xF7, 0x33, 0xE4, 0x8A, 0xFF, 0x4B, 0x41, 0xB5, 0x65, 0x01,
	//	0x1C, 0xE0, 0x71, 0x1C, 0x5E, 0x39, 0x2C, 0xFB, 0x0A, 0xB1, 0xB6, 0x79, 0x1B, 0x94, 0xC4, 0x08,
	//	0x29, 0xDB, 0xA1, 0x16, 0x15, 0x2D, 0x1F, 0x78, 0x6C, 0xE8, 0x43, 0xED, 0x24, 0xA3, 0xB5, 0x73,
	//	0x41, 0x4D, 0x21, 0x77, 0x38, 0x6A, 0x92, 0xDD, 0x8F, 0x14, 0xD6, 0x56, 0x96, 0xEA, 0x5E, 0x32,
	//	0x69, 0x85, 0x09, 0x38, 0xAB, 0xEA, 0x01, 0x12, 0xB5, 0x73, 0x29, 0xF4, 0x47, 0xE3, 0xA0, 0xCB,
	//	0xAD, 0x3E, 0x2F, 0xDB, 0x1A, 0x77, 0xF3, 0x35, 0xE8, 0x9E, 0x14, 0x08, 0xD0, 0xEF, 0x1C, 0x25,
	//	0x41, 0xE0, 0x0A, 0x53, 0xDD, 0xA5, 0x32, 0xDA, 0x1A, 0x7C, 0xE0, 0x27, 0xB7, 0xA4, 0x6F, 0x74,
	//	0x10, 0x06, 0xE8, 0x5F, 0x5C, 0xDF, 0xF0, 0x73, 0x0E, 0x75, 0xC0, 0x5F, 0xB4, 0xE3, 0x21, 0x6D };

	//unsigned char std_dSA[64] = { 0xA5, 0x70, 0x2F, 0x05, 0xCF, 0x13, 0x15, 0x30, 0x5E, 0x2D, 0x6E, 0xB6, 0x4B, 0x0D, 0xEB, 0x92,
	//	0x3D, 0xB1, 0xA0, 0xBC, 0xF0, 0xCA, 0xFF, 0x90, 0x52, 0x3A, 0xC8, 0x75, 0x4A, 0xA6, 0x98, 0x20,
	//	0x78, 0x55, 0x9A, 0x84, 0x44, 0x11, 0xF9, 0x82, 0x5C, 0x10, 0x9F, 0x5E, 0xE3, 0xF5, 0x2D, 0x72,
	//	0x0D, 0xD0, 0x17, 0x85, 0x39, 0x2A, 0x72, 0x7B, 0xB1, 0x55, 0x69, 0x52, 0xB2, 0xB0, 0x13, 0xD3 };

	unsigned char hid[] = { 0x01 };
	unsigned char *IDR = "Cuiyan";
	unsigned char *IDS = "Pulang";
	unsigned char *message = "This is a test message"; //the message to be signed
	int mlen = strlen(message), tmp;                 //the length of message
	big ks;

	tmp = SM9_Init();

	if (tmp != 0)
		return tmp;
	ks = mirvar(0);

	//bytes_to_big(32, dA, ks);
	bigrand(N, ks);

	printf("\n***********************  SM9 key Generation    ***************************\n");
	printf("The master private key [ks] : \n");
	cotnum(ks,stdout);
	tmp = SM9_GenerateSignKey(hid, IDR, strlen(IDR), ks,Ppub, dSA,skID);
	if (tmp != 0)
		return tmp;


	//printf("\n**********************  SM9 signature algorithm***************************\n");
	//tmp = SM9_Sign(hid, IDR, message, mlen, rand, dSA, Ppub, h, S,skID,ks);
	//if (tmp != 0)
	//	return tmp;

	//printf("\n*******************  SM9 verification algorithm *************************\n");
	//tmp = SM9_Verify(h, S, hid, IDR, message, mlen, Ppub);
	//if (tmp != 0)
	//	return tmp;
	printf("-----------------------------------------TEST----------------------------------------\n");
	Signcrypt(hid, IDR,IDS, strlen(IDR), message, mlen, h, S,T,C, skID,ks, Ppub);
	Unsigncrypt(hid, IDR, IDS, strlen(IDR), message, mlen, S, T, C, skID, ks, Ppub);
	return 0;
}