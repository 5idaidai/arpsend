#pragma once
#define u_char unsigned char
#define u_short unsigned short

class CApk
{
public:
	CApk(void);
	virtual ~CApk(void);
protected:
	u_short hdtyp;   //Ӳ������.ֵ0001
	u_short protyp;  //Э������
	u_char hdsize;   //�����ַ����
	u_char prosize;  //Э���ַ����
	u_short op;      //����
	u_char smac[6];  //Դ����MAC��ַ
	u_char sip[4];   //Դ����IP��ַ
	u_char dmac[6];  //Ŀ������MAC��ַ
	u_char dip[4];   //Ŀ������IP��ַ
};
