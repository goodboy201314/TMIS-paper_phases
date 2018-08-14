#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include "tmis_enc_denc.h"
#include "/usr/local/include/pbc/pbc.h"  //必须包含头文件pbc.h
#include "/usr/local/include/pbc/pbc_test.h"


#if 0  // 修改密码事件
char secret_key[1024] = "[1431701601476568613993916354570581999234296492200903722689435064403093647543786410908775082711468637043556899660242354405958838182001143332963964057164995, 2090155367049341967001403718508984758041491186470976194749112114432660174858545929700501744055058603817941671083836419094294404012587185432039026958345540]";
char public_key[1024] = "[8779246804865256595845410635551148521227644044548861627285453536743878386166265446937141101008408588690674901331738586548621281816777149434943936565852561, 5462710688655103662240594520449922001027729122965123487994410536107298056563228514615559984791707466524546778752823276552092115399599325705605166751646997]";
char str_id[100] = "123";
char str_pw[100] = "456";
char str_Bi[1024] = "15BAC940E309C680089916A9ECC4A02B159DE296";
char str_Ci[1024] = "D999D27928FE8D864E8EE575A6EF5A550D8C2A85";
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

void password_change()
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

//// 4.输入新的pwd
	char str_pw_new[100]="123";

///	5.计算HPWi_new
	len1 = strlen(str_pw_new);
	len2 = strlen(str_b);
	char *CONSTR3 =(char *)malloc(sizeof(char) * (len1+len2)+1);
	memset(CONSTR3,0,len1+len2+1);
	strncpy(CONSTR3,str_pw_new,len1);
	strncpy(CONSTR3+len1,str_b,len2);
	printf("CONSTR3 = %s\n",CONSTR3);
	unsigned char bytes_HPWi_new[100]={0};
	sha1((unsigned char *)CONSTR3, bytes_HPWi_new); 
	char str_HPWi_new[1024]={0};
	bytes2hex(bytes_HPWi_new,strlen((char *)bytes_HPWi_new),str_HPWi_new);


//// 6.计算Bi_new
	len1 = strlen(str_id);
	len2 = strlen((char *)bytes_HPWi_new);
	char *CONSTR4 =(char *)malloc(sizeof(char) * (len1+len2)+1); 
	memset(CONSTR4,0,len1+len2+1);
	memcpy(CONSTR4,str_id,len1);
	memcpy(CONSTR4+len1,bytes_HPWi_new,len2);

	unsigned char bytes_temp1_new[1024]={0};
	sha1((unsigned char*)CONSTR4,bytes_temp1_new);	 // h( IDi || HPWi	)
	// 转化成mpz_t类型，然后mod
	char str_temp1_new[1024]={0};
	bytes2hex(bytes_temp1_new,strlen((char *)bytes_temp1_new),str_temp1_new);
	printf("str_temp1_new = %s\n",str_temp1_new);
	mpz_t mpz_temp1_new;
	mpz_init_set_str(mpz_temp1_new,str_temp1_new,16);
	gmp_printf("mpz_temp1 = %Zd\n",mpz_temp1_new);

	mpz_t mpz_res_new;
	mpz_init(mpz_res_new);
//	void mpz_mod (mpz t r, mpz t n, mpz t d) [Function]
//**** Set r to n mod d.
	mpz_mod(mpz_res_new,mpz_temp1_new,m);
	gmp_printf("mpz_res = %Zd\n",mpz_res_new);	// h( IDi || HPWi  ) mod m
	// 将mpz_res转化为字符串
//	char * mpz_get_str (char *str, int base, mpz t op); 
	char str_res_new[1024]={0};
	mpz_get_str(str_res_new,-16,mpz_res_new);
	printf("str_res_new = %s\n",str_res_new);
	unsigned char bytes_Bi_new[100]={0};
	sha1((unsigned char *)str_res_new,bytes_Bi_new);
	char str_Bi_new[1024]={0};
	bytes2hex(bytes_Bi_new,strlen((char *)bytes_Bi_new),str_Bi_new);

//// 7.获得Ai
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


//// 8.计算Ci_new
	mpz_t mpz_HPWi_new,mpz_Bi_new;
	mpz_t mpz_Ci_new;
	mpz_init(mpz_Ci_new);
	mpz_init_set_str(mpz_HPWi_new,str_HPWi_new,16);  // mpz_HPWi
	mpz_init_set_str(mpz_Bi_new,str_Bi_new,16);  // mpz_HPWi
	mpz_xor(mpz_Ci_new,mpz_Ai,mpz_HPWi_new);
	mpz_xor(mpz_Ci_new,mpz_Ci_new,mpz_Bi_new);

	char str_Ci_new[1024]={0};
	// 将mpz_res转化为字符串
//  char * mpz_get_str (char *str, int base, mpz t op);	
	mpz_get_str(str_Ci_new,-16,mpz_Ci_new);


	printf("str_Bi_new = %s\n",str_Bi_new);
	printf("str_Ci_new = %s\n",str_Ci_new);



////// 释放资源
	free(CONSTR);
	free(CONSTR2);
	free(CONSTR3);
	free(CONSTR4);
	mpz_clear(mpz_temp1_new);
	mpz_clear(mpz_temp1);
	mpz_clear(mpz_res);
	mpz_clear(m);
	
	
}


int main()
{
	password_change();
	
	return 0;
}


#endif
