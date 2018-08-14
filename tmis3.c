#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include "tmis_enc_denc.h"
#include "/usr/local/include/pbc/pbc.h"  //必须包含头文件pbc.h
#include "/usr/local/include/pbc/pbc_test.h"


#if 1  // 用户登录和密钥协商事件
char secret_key[1024] = "[1431701601476568613993916354570581999234296492200903722689435064403093647543786410908775082711468637043556899660242354405958838182001143332963964057164995, 2090155367049341967001403718508984758041491186470976194749112114432660174858545929700501744055058603817941671083836419094294404012587185432039026958345540]";
char public_key[1024] = "[8779246804865256595845410635551148521227644044548861627285453536743878386166265446937141101008408588690674901331738586548621281816777149434943936565852561, 5462710688655103662240594520449922001027729122965123487994410536107298056563228514615559984791707466524546778752823276552092115399599325705605166751646997]";
char str_id[100] = "123";

/* 修改密码前 
char str_pw[100] = "456";
char str_Bi[1024] = "15BAC940E309C680089916A9ECC4A02B159DE296";
char str_Ci[1024] = "D999D27928FE8D864E8EE575A6EF5A550D8C2A85";

*/

/*
* str_Bi_new = E50D9AFF7F56416C11A563F5056CF9BEB0A0FF4D
* str_Ci_new = E6826FF9CB3BB05D844F86B1D28C28AE2F674B80
*/
char str_pw[100]="123";
char str_Bi[1024] = "E50D9AFF7F56416C11A563F5056CF9BEB0A0FF4D";
char str_Ci[1024] = "E6826FF9CB3BB05D844F86B1D28C28AE2F674B80";


char str_m[30] = "F19DD7CCE10462454C5169A77";
//m_len = 25
char str_b[30] = "F19DD7CCE10462454C5169A77";
//b_len = 25

const char split_char_key_agreement[10]="我"; // "BB";//
const char split_char_communication[10]="AA";
#define len_split_char_key_agreement strlen(split_char_key_agreement)
#define len_split_char_communication strlen(split_char_communication)

void key_agreement_server_do();


/**
 * @brief 将时间戳转化为字符串
 * @param t 时间戳
 * @param str_time 字符串数组
 * @param str_len 字符串数组长度
 * @return  成功返回0；失败返回-1
 */
int time2string(time_t t, char *str_time,int str_len)
{
	if(!str_time) return -1;
	
    struct tm *tm_t;
    tm_t = localtime(&t);
    strftime(str_time,str_len,"%Y%m%d%H%M%S",tm_t);

    return 0;
}

/**
 * @brief 将字符串转化为时间戳
 * @param str_time 字符串数组
 * @param out 时间戳
 * @return  成功返回0；失败返回-1
 */

int string2time(char *str_time,time_t *out)
{
	if(!str_time || !out) return -1;

	struct tm stm;  
  	strptime(str_time, "%Y%m%d%H%M%S",&stm); 
	*out= mktime(&stm);

    return 0;
}



unsigned char bytes_Hi[4096]={0};
unsigned char bytes_Rc[4096]={0};
unsigned char bytes_Li[4096]={0};

void key_agreement_client_do1()
{
//// 1.计算HPWi
	int len1 = strlen(str_pw);
	int len2 = strlen(str_b);
	char *CONSTR =(char *)malloc(sizeof(char) * (len1+len2)+1);
	memset(CONSTR,0,len1+len2+1);
	strncpy(CONSTR,str_pw,len1);
	strncpy(CONSTR+len1,str_b,len2);
	printf("CONSTR = %s\n",CONSTR);
	unsigned char bytes_HPWi[100]={0};
	sha1((unsigned char *)CONSTR, bytes_HPWi); 

//// 2.计算Bi*    (Bi2)
	len1 = strlen(str_id);
	len2 = strlen((char *)bytes_HPWi);
	char *CONSTR2 =(char *)malloc(sizeof(char) * (len1+len2)+1); 
	memset(CONSTR2,0,len1+len2+1);
	memcpy(CONSTR2,str_id,len1);
	memcpy(CONSTR2+len1,bytes_HPWi,len2);

	unsigned char bytes_temp1[1024]={0};
	sha1((unsigned char*)CONSTR2,bytes_temp1);   // h( IDi || HPWi  )
	// 转化成mpz_t类型，然后mod
	char str_temp1[1024]={0};
	bytes2hex(bytes_temp1,strlen((char *)bytes_temp1),str_temp1);
	printf("str_temp1 = %s\n",str_temp1);
	mpz_t mpz_temp1;
	mpz_init_set_str(mpz_temp1,str_temp1,16);
	gmp_printf("mpz_temp1 = %Zd\n",mpz_temp1);

	mpz_t mpz_res,m;
	mpz_init(mpz_res);
	mpz_init_set_str(m,str_m,16);
//	void mpz_mod (mpz t r, mpz t n, mpz t d) [Function]
//**** Set r to n mod d.
	mpz_mod(mpz_res,mpz_temp1,m);
	gmp_printf("mpz_res = %Zd\n",mpz_res);  // h( IDi || HPWi  ) mod m
	// 将mpz_res转化为字符串
//  char * mpz_get_str (char *str, int base, mpz t op);	
	char str_res[1024]={0};
	mpz_get_str(str_res,-16,mpz_res);
	printf("str_res = %s\n",str_res);
	unsigned char bytes_Bi[100]={0};
	sha1((unsigned char *)str_res,bytes_Bi);   //  h ( h( IDi || HPWi  ) mod m )

//// 3.比较Bi和Bi*是否相等
	char str_Bi2[1024]={0};
	bytes2hex(bytes_Bi,strlen((char *)bytes_Bi),str_Bi2);
	if(strcmp(str_Bi2,str_Bi)==0) printf("用户身份验证通过。。。\n");
	else { printf("用户身份验证失败。。。\n"); return; }
	
//// 4.计算Ai
	mpz_t mpz_Ci,mpz_HPWi,mpz_Bi;
	mpz_t mpz_Ai;
	mpz_init(mpz_Ai);
	
	mpz_init_set_str(mpz_Ci,str_Ci,16);
	gmp_printf("mpz_Ci = %Zd\n", mpz_Ci);
	mpz_init_set_str(mpz_Bi,str_Bi,16);
	gmp_printf("mpz_Bi = %Zd\n", mpz_Bi);
	char str_HPWi[1024]={0};
	bytes2hex(bytes_HPWi,strlen((char *)bytes_HPWi),str_HPWi);
	mpz_init_set_str(mpz_HPWi,str_HPWi,16);  // mpz_HPWi
	gmp_printf("mpz_HPWi = %Zd\n", mpz_HPWi);
	mpz_xor(mpz_Ai,mpz_Ci,mpz_HPWi);
	mpz_xor(mpz_Ai,mpz_Ai,mpz_Bi);
	gmp_printf("mpz_Ai = %Zd\n", mpz_Ai);


//// 5.手机端生成参数Rc
	pairing_t pairing;	
	char s[16384];
	FILE *fp = stdin;
	fp = fopen("a.param", "r");
	if (!fp) pbc_die("error opening a.param");
  
	size_t count = fread(s, 1, 16384, fp);
	if (!count) pbc_die("input error");
	fclose(fp);

	if (pairing_init_set_buf(pairing, s, count)) pbc_die("pairing init failed");
	// ======> pairing 初始化完成
	element_t element_P,elemetn_secret_key,element_public_key;  // 这些要定义成全局的
	element_t element_Rc,element_rc,element_k1;
	element_t element_Ai;

	element_init_G1(element_P,pairing);
	element_init_G1(elemetn_secret_key,pairing);
	element_init_G1(element_public_key,pairing);
	element_init_G1(element_Rc,pairing);
	element_init_G1(element_rc,pairing);
	element_init_G1(element_k1,pairing);
	element_init_G1(element_Ai,pairing);
	
	// 参数初始化
	char hash_str[30] = "xiangbin is a good boy!";
    element_from_hash(element_P, hash_str, strlen(hash_str)); 
    element_printf("element_P = %B\n", element_P);  // 赋值：element_P

	element_random(element_rc);    // element_rc
	element_set_str(element_public_key,public_key,10); // element_public_key
	element_set_str(elemetn_secret_key,secret_key,10);// elemetn_secret_key
	element_printf("element_public_key = %B\n", element_public_key);
	// 这里将mpz_Ai转化成element，发现转化不成功，所以做一个转换
//	void element_set_mpz(element_t e, mpz_t z)
//	element_set_mpz(element_ai,mpz_ai);
//	element_printf("element_ai = %B\n", element_ai);
	char str_Ai[1024]={0};
// char * mpz_get_str (char *str, int base, mpz_t op)	
	mpz_get_str (str_Ai, 10, mpz_Ai);  
	element_from_hash(element_Ai, str_Ai, strlen(str_Ai));  
	element_printf("element_Ai = %B\n", element_Ai);

	element_mul(element_Rc,element_rc,element_Ai);
	element_mul(element_Rc,element_Rc,element_P); // 得出element_Rc

//// 5.计算k1
	element_mul(element_k1,element_rc,element_Ai);
	element_mul(element_k1,element_k1,element_public_key);

//// 6.计算Hi
	time_t t1 = time(NULL);
	printf("t1: %ld\n",t1);
	char str_t1[30]={0};
	time2string(t1, str_t1, sizeof(str_t1)/sizeof(char));
	printf("str_time = %s\n",str_t1);

	len1=strlen(str_id);
	len2=strlen(str_Ai);
	int len3=strlen(str_t1);

	char *CONSTR3 = (char *)malloc(sizeof(char)*(len1+len2+len3+1+3*len_split_char_key_agreement));
	memset(CONSTR3,0,len1+len2+len3+1+3*len_split_char_key_agreement);
	strncpy(CONSTR3,str_id,len1);
	strncpy(CONSTR3+len1,split_char_key_agreement,len_split_char_key_agreement);
	strncpy(CONSTR3+len1+len_split_char_key_agreement,str_Ai,len2);
	strncpy(CONSTR3+len1+len_split_char_key_agreement+len2,split_char_key_agreement,len_split_char_key_agreement);
	strncpy(CONSTR3+len1+len_split_char_key_agreement*2+len2,str_t1,len3);
	strncpy(CONSTR3+len1+len_split_char_key_agreement*2+len2+len3,split_char_key_agreement,len_split_char_key_agreement);
	printf("str_Hi = %s\n",CONSTR3);
	printf("str_Hi_len = %ld\n",strlen(CONSTR3));

	// 计算加密密钥
	unsigned char bytes_md5_k1[50]={0};
//	int md5(const  unsigned char* in, unsigned char* out);
//	int element_snprint(char *s, size_t n, element_t e)
	char str_k1[1024]={0};
	element_snprint(str_k1,sizeof(str_k1),element_k1);
	md5((unsigned char *)str_k1,bytes_md5_k1);
////////// 注意：如果使用不可见字符加密，有时候会出错
	char str_md5_k1[50]={0};
	char str_temp[50]={0};
//	int bytes2hex(const unsigned char* in, const int len, char *out);
	bytes2hex(bytes_md5_k1,strlen((char *)bytes_md5_k1),str_temp);
	strncpy(str_md5_k1,str_temp,16);
	printf("str_md5_k1 = %s\n",str_md5_k1);

	//unsigned char bytes_Hi[4096]={0};
	aes_encrypt((unsigned char *)CONSTR3,(unsigned char *)str_md5_k1,bytes_Hi);
//// 7.将Rc转化为字节流传输
	//unsigned char bytes_Rc[4096]={0};
	element_to_bytes(bytes_Rc, element_Rc);
	
	printf("key_agreement:手机端生成并且发送参数。。。\n");



//////////////////////////////////////////////////////////////////
///  服务器干活
	key_agreement_server_do();

///////////////////////////////////////////////////////////////////
	


////// 客户端接着干活
	char str_Li[4096]={0};
	aes_decrypt(bytes_Li,(unsigned char *)str_md5_k1,(unsigned char *)str_Li);
	printf("str_Li = %s\n",str_Li);
//// 1.分割字符串
	char str_IDi[1024]={0}; // 和注册的时候str_id一样
	char str_Rs[1024]={0};
	char str_Ji[1024]={0};
	char str_t2[1024]={0};
	
	char *p = strtok(str_Li,split_char_key_agreement);
	if(p) strcpy(str_IDi,p);
	p = strtok(NULL,split_char_key_agreement);
	if(p) strcpy(str_Rs,p);
	p = strtok(NULL,split_char_key_agreement);
	if(p) strcpy(str_Ji,p);
	p = strtok(NULL,split_char_key_agreement);
	if(p) strcpy(str_t2,p);

	// 比较时间是否超时
	time_t t2;
	time_t t2_2 = time(NULL);
	string2time(str_t2, &t2);
	if(t2_2-t2>120) { printf("超时了。。。\n"); return; }
	else printf("没有超时。。。\n");
	
//// 2. 恢复 Rs
	element_t element_Rs,element_Ji;
	
	element_init_G1(element_Rs,pairing);
	element_init_G1(element_Ji,pairing);
	
	element_set_str(element_Rs,str_Rs,10);
	element_mul(element_Ji,element_rc,element_Ai);
	element_mul(element_Ji,element_Ji,element_Rs);

//// 3. 比较Ji 	
	char str_Ji2[1024]={0};
	element_snprint(str_Ji2,sizeof(str_Ji2),element_Ji);
	if(strcmp(str_Ji2,str_Ji)==0) printf("服务器端验证通过。。。\n");
	else {printf("服务器端验证失败。。。。\n");return;}

///// 4.计算sk
	len1=strlen(str_Ji2);
	len2=strlen(str_t1);
	len3=strlen(str_t2);
	char *CONSTR4 = (char *)malloc(sizeof(char)*(len1+len2+len3+1));
	memset(CONSTR4,0,len1+len2+len3+1);
	strncpy(CONSTR4,str_Ji2,len1);
	strncpy(CONSTR4+len1,str_t1,len2);
	strncpy(CONSTR4+len1+len2,str_t2,len3);
	
	unsigned char bytes_sk[50] = {0}; 
	md5((unsigned char*)CONSTR4, bytes_sk);
	printhex(bytes_sk,16);




//// 释放内存
	free(CONSTR);
	free(CONSTR2);
	free(CONSTR3);
	free(CONSTR4);
	mpz_clear(mpz_temp1);
	mpz_clear(mpz_res);
	mpz_clear(mpz_Ci);
	mpz_clear(mpz_HPWi);
	mpz_clear(mpz_Bi);
	mpz_clear(mpz_Ai);
	element_clear(element_P);
	element_clear(elemetn_secret_key);
	element_clear(element_public_key);
	element_clear(element_Rc);
	element_clear(element_rc);
	element_clear(element_k1);
	element_clear(element_Ai);
	element_clear(element_Rs);
	element_clear(element_Ji);

}

void key_agreement_server_do()
{
	pairing_t pairing;	
	char s[16384];
	FILE *fp = stdin;
	fp = fopen("a.param", "r");
	if (!fp) pbc_die("error opening a.param");
  
	size_t count = fread(s, 1, 16384, fp);
	if (!count) pbc_die("input error");
	fclose(fp);

	if (pairing_init_set_buf(pairing, s, count)) pbc_die("pairing init failed");
	// ======> pairing 初始化完成
	element_t element_P,elemetn_secret_key,element_public_key,element_rs;  // 这些要定义成全局的
	element_t element_Rs,element_Rc,element_k2,element_Ji;
	
	element_init_G1(element_P,pairing);
	element_init_G1(elemetn_secret_key,pairing);
	element_init_G1(element_public_key,pairing);
	element_init_G1(element_Rs,pairing);
	element_init_G1(element_Rc,pairing);
	element_init_G1(element_rs,pairing);
	element_init_G1(element_k2,pairing);
	element_init_G1(element_Ji,pairing);

	// 参数初始化
	char hash_str[30] = "xiangbin is a good boy!";
    element_from_hash(element_P, hash_str, strlen(hash_str)); 
    element_printf("element_P = %B\n", element_P);  // 赋值：element_P

	element_random(element_rs);    // element_rs
	element_set_str(element_public_key,public_key,10); // element_public_key
	element_set_str(elemetn_secret_key,secret_key,10);// elemetn_secret_key

//// 1.计算k2
	element_from_bytes(element_Rc,bytes_Rc);
	element_mul(element_k2,elemetn_secret_key,element_Rc);

//// 2.解密Hi	
	char str_k2[1024]={0};
	element_snprint(str_k2,sizeof(str_k2),element_k2);
	unsigned char bytes_md5_k2[50]={0};
	md5((unsigned char *)str_k2,bytes_md5_k2); // 得到解密密钥 bytes_k2

	char str_md5_k2[50]={0};
	char str_temp[50]={0};
//	int bytes2hex(const unsigned char* in, const int len, char *out);
	bytes2hex(bytes_md5_k2,strlen((char *)bytes_md5_k2),str_temp);
	strncpy(str_md5_k2,str_temp,16);

	char str_Hi[4096]={0};
//	int aes_decrypt(const unsigned char* in, const unsigned char* key, unsigned char* out);
	aes_decrypt(bytes_Hi,(unsigned char *)str_md5_k2,(unsigned char *)str_Hi);
	printf("str_Hi = %s\n",str_Hi);


//// 3.分割字符串
	char str_IDi[1024]={0}; // 和注册的时候str_id一样
	char str_Ai[1024]={0};
	char str_t1[1024]={0};
	
	char *p = strtok(str_Hi,split_char_key_agreement);
	if(p) strcpy(str_IDi,p);
	p=strtok(NULL,split_char_key_agreement);
	if(p) strcpy(str_Ai,p);
	p=strtok(NULL,split_char_key_agreement);
	if(p) strcpy(str_t1,p);
	
	printf("str_IDi = %s\n",str_IDi);
	printf("str_Ai = %s\n",str_Ai);
	printf("str_t1 = %s\n",str_t1);
	
///// 4.比较时间是否超时
	time_t t1;
	time_t t1_2 = time(NULL);
	string2time(str_t1, &t1);
	if(t1_2-t1>120) { printf("超时了。。。\n"); return; }
	else printf("没有超时。。。\n");

///// 5.计算Ai2
	int len1 = strlen(str_IDi);			
	int len2 = strlen(secret_key);		
	char *CONSTR1 =(char *)malloc(sizeof(char) * (len1+len2)+1); // ID || KS
	memset(CONSTR1,0,len1+len2+1);
	strncpy(CONSTR1,str_IDi,len1);
	strncpy(CONSTR1+len1,secret_key,len2);
	printf("CONSTR1 = %s\n",CONSTR1);
	unsigned char bytes_Ai[100]={0};
	sha1((unsigned char *)CONSTR1,bytes_Ai);

	mpz_t mpz_Ai2;
	char str_temp2[1024]={0};
	bytes2hex(bytes_Ai,strlen((char *)bytes_Ai),str_temp2);
	mpz_init_set_str(mpz_Ai2,str_temp2,16);	// mpz_Ai2
	char str_Ai2[1024]={0};
// char * mpz_get_str (char *str, int base, mpz_t op)	
	mpz_get_str (str_Ai2, 10, mpz_Ai2);  
	if(strcmp(str_Ai,str_Ai2)==0) printf("该用户为注册用户。。。\n");
	else { printf("该用户不是注册用户。。。\n");return; }

//// 6.	生成rs
	element_random(element_rs);    // element_rs

//// 7. 计算Rs
	element_mul(element_Rs,element_rs,element_P);
	
//// 8.计算Ji
	element_mul(element_Ji,element_rs,element_Rc);

//// 9.计算 IDi || Rs || Ji || t2
	// str_t2 
	time_t t2 = time(NULL);
	printf("t2: %ld\n",t2);
	char str_t2[30]={0};
	time2string(t2, str_t2, sizeof(str_t2)/sizeof(char));
	printf("str_time = %s\n",str_t2);
	// str_Rs
// int element_snprint(char *s, size_t n, element_t e)
	char str_Rs[1024]={0};
	element_snprint(str_Rs,sizeof(str_Rs),element_Rs);
	// str_Ji
	char str_Ji[1024]={0};
	element_snprint(str_Ji,sizeof(str_Rs),element_Ji);

	// 连接
	len1 = strlen(str_IDi);
	len2 = strlen(str_Rs);
	int len3 = strlen(str_Ji);
	int len4 = strlen(str_t2);
	char *CONSTR2=(char *)malloc(sizeof(char)*(len1+len2+len3+len4+1+4*len_split_char_key_agreement));
	memset(CONSTR2,0,len1+len2+len3+len4+1+4*len_split_char_key_agreement);
	strncpy(CONSTR2,str_IDi,len1);
	strncpy(CONSTR2+len1,split_char_key_agreement,len_split_char_key_agreement);
	strncpy(CONSTR2+len1+len_split_char_key_agreement,str_Rs,len2);
	strncpy(CONSTR2+len1+len_split_char_key_agreement+len2,split_char_key_agreement,len_split_char_key_agreement);
	strncpy(CONSTR2+len1+2*len_split_char_key_agreement+len2,str_Ji,len3);
	strncpy(CONSTR2+len1+2*len_split_char_key_agreement+len2+len3,split_char_key_agreement,len_split_char_key_agreement);
	strncpy(CONSTR2+len1+3*len_split_char_key_agreement+len2+len3,str_t2,len4);
	strncpy(CONSTR2+len1+3*len_split_char_key_agreement+len2+len3+len4,split_char_key_agreement,len_split_char_key_agreement);
	printf("str_Li = %s\n",CONSTR2);

//// 10.计算Li
	//unsigned char bytes_Li[4096]={0};
	aes_encrypt((unsigned char *)CONSTR2,(unsigned char *)str_md5_k2,bytes_Li);
	printf("key_agreement：服务器端计算成功。。。。\n");
	
///// 4.计算sk
	len1=strlen(str_Ji);
	len2=strlen(str_t1);
	len3=strlen(str_t2);
	char *CONSTR4 = (char *)malloc(sizeof(char)*(len1+len2+len3+1));
	memset(CONSTR4,0,len1+len2+len3+1);
	strncpy(CONSTR4,str_Ji,len1);
	strncpy(CONSTR4+len1,str_t1,len2);
	strncpy(CONSTR4+len1+len2,str_t2,len3);
	
	unsigned char bytes_sk[50] = {0}; 
	md5((unsigned char*)CONSTR4, bytes_sk);
	printhex(bytes_sk,16);



//// 释放内存
	element_clear(element_P);
	element_clear(elemetn_secret_key);
	element_clear(element_public_key);
	element_clear(element_Rs);
	element_clear(element_Rc);
	element_clear(element_rs);
	element_clear(element_k2);
	element_clear(element_Ji);
	free(CONSTR1);
	free(CONSTR2);
	free(CONSTR4);
	mpz_clear(mpz_Ai2);

	
}

void key_agreement_client_do2()
{

}



void key_agreement()
{
	key_agreement_client_do1();
}


int main()
{
	key_agreement();
	
	return 0;
}


#endif
