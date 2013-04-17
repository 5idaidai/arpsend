#pragma once
#define u_char unsigned char
#define u_short unsigned short

class CApk
{
public:
	CApk(void);
	virtual ~CApk(void);
protected:
	u_short hdtyp;   //硬件类型.值0001
	u_short protyp;  //协议类型
	u_char hdsize;   //物理地址长度
	u_char prosize;  //协议地址长度
	u_short op;      //操作
	u_char smac[6];  //源主机MAC地址
	u_char sip[4];   //源主机IP地址
	u_char dmac[6];  //目的主机MAC地址
	u_char dip[4];   //目的主机IP地址
};
