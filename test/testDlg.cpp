// testDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "test.h"
#include "testDlg.h"
#include "stdlib.h"
#include <string>

using namespace std;

#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"Packet.lib")
#pragma comment(lib,"Ws2_32.lib")
#ifdef _DEBUG
#define new DEBUG_NEW
#endif

//�Լ���������ݽṹ
#define ETH_IP       0x0800
#define ETH_ARP      0x0806
#define ARP_REQUEST  0x0001
#define ARP_REPLY    0x0002
#define ARP_HARDWARE 0x0001
//#define max_num_adapter  10

//28�ֽ�ARP֡�ṹ
struct arp_head
{
    unsigned short hardware_type;    //Ӳ������
    unsigned short protocol_type;    //Э������
    unsigned char hardware_add_len; //Ӳ����ַ����
    unsigned char protocol_add_len; //Э���ַ����
    unsigned short operation_field; //�����ֶ�
    unsigned char source_mac_add[6]; //Դmac��ַ
    unsigned long source_ip_add;    //Դip��ַ
    unsigned char dest_mac_add[6]; //Ŀ��mac��ַ
    unsigned long dest_ip_add;      //Ŀ��ip��ַ
};
//14�ֽ���̫��֡�ṹ
struct ethernet_head
{
    unsigned char dest_mac_add[6];    //Ŀ��mac��ַ
    unsigned char source_mac_add[6]; //Դmac��ַ
    unsigned short type;              //֡����
};
 
//arp���հ��ṹ
struct arp_packet
{
    ethernet_head eh;
    arp_head ah;
};

struct pc
{
	unsigned long ip;
	unsigned char mac[6];
}pcGroup[255];

struct threadInfo{  
    CListCtrl *m_listctrl;
    CButton *pBtn;
	CButton *pBtn1;
}ThreadInfo;

u_char selfMac[6]={0};
u_long myip;
pcap_t *adhandle;
u_long firstip,secondip;
unsigned int HostNum = 0;
int flag = FALSE;
CWinThread *pThread,*gThread,*sThread,*mThread;
int dev_num = 2;
int freeip[255] = {1};
string strBuf;

// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// �Ի�������
	enum { IDD = IDD_ABOUTBOX };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
protected:
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnIpnFieldchangedIpaddress1(NMHDR *pNMHDR, LRESULT *pResult);
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
END_MESSAGE_MAP()


// CtestDlg �Ի���




CtestDlg::CtestDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CtestDlg::IDD, pParent)
	, ip_temp1(0)
	, ip_temp2(0)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CtestDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST3, m_listctrl);
	DDX_Control(pDX, IDC_IPADDRESS1, m_ipcontrol);
	DDX_Control(pDX, IDC_IPADDRESS2, m_ipcontrol2);
}

BEGIN_MESSAGE_MAP(CtestDlg, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
	ON_NOTIFY(IPN_FIELDCHANGED, IDC_IPADDRESS1, &CtestDlg::OnIpnFieldchangedIpaddress1)
	ON_BN_CLICKED(IDC_BUTTON6, &CtestDlg::OnBnClickedButton6)
	ON_CBN_SELCHANGE(IDC_COMBO1, &CtestDlg::OnCbnSelchangeCombo1)
	ON_NOTIFY(IPN_FIELDCHANGED, IDC_IPADDRESS2, &CtestDlg::OnIpnFieldchangedIpaddress2)
	ON_BN_CLICKED(IDC_BUTTON1, &CtestDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON3, &CtestDlg::OnBnClickedButton3)
	ON_BN_CLICKED(IDC_BUTTON5, &CtestDlg::OnBnClickedButton5)
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST3, &CtestDlg::OnLvnItemchangedList3)
END_MESSAGE_MAP()


// CtestDlg ��Ϣ�������

BOOL CtestDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		CString strAboutMenu;
		strAboutMenu.LoadString(IDS_ABOUTBOX);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// ���ô˶Ի����ͼ�ꡣ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO: �ڴ���Ӷ���ĳ�ʼ������

	//��ʼ�������ӿ�
	CString strTemp;
	((CComboBox*)GetDlgItem(IDC_COMBO1))->ResetContent();  //����������������
    pcap_if_t *alldevs;
    pcap_if_t *d;
	char errbuf[PCAP_ERRBUF_SIZE];/* ���������ռ�winpcap����Ļ������Ĵ�С*/
	/* ��ȡ�ӿ��б� */
    if (pcap_findalldevs( &alldevs, errbuf) == -1)
    {
        AfxMessageBox(errbuf);
        exit(1);
    }
    CComboBox* combobox1=(CComboBox*)GetDlgItem(IDC_COMBO1);
	for(d= alldevs; d != NULL; d= d->next)
	{
		strTemp.Format("%s",d->description);
		combobox1->AddString(strTemp);
	}
	combobox1->SetCurSel(1);

	//��ʼ���ѱ�ʹ��IP��MAC��ַ�б�
	CString temp[2]={"IP��ַ","���������ַ"};
	for(int i=0;i<2;i++)
	{
		m_listctrl.InsertColumn(i,temp[i],LVCFMT_LEFT,120);
	}

	//��ʼ������ա���ť
	CButton *pBtn= (CButton *)GetDlgItem(IDC_BUTTON5); //IDC_BUTTON5�����ť 
	if(pBtn!=NULL) 
    { 
        pBtn->EnableWindow(FALSE); // True or False 
    }

	ThreadInfo.pBtn1 = pBtn;

	//��ʼ��IP Address Control
	m_ipcontrol.SetAddress(192,168,1,1);
	m_ipcontrol2.SetAddress(192,168,1,255);

	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
}

//�Լ�����ĺ���
string IpToStr(const sockaddr *addr)
{
	string s;
	s = inet_ntoa((*(sockaddr_in *)addr).sin_addr);
	return s;
}

int OpenIf(int dev_num){	
    int j=0,inum = 0;
	char errbuf[PCAP_ERRBUF_SIZE];	
	pcap_if_t *alldevs;
    pcap_if_t *d;

    /* ��ȡ�ӿ��б� */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* ����ҪԶ����֤ */, &alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
        exit(1);
    }

	for(d= alldevs; d != NULL; d= d->next)
    {
        printf("%d. %s", ++j, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

	//printf("��ѡ������(1-%d)��",j);
    //scanf_s("%d", &inum);
	inum = dev_num;
    if(inum < 1 || inum > j)
    {
        printf("\nInterface number out of range.\n");
        /* �ͷ��豸�ӿ��б� */
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    /* ת����ѡ�Ľӿ� */
    for(d=alldevs, j=0; j< inum-1 ;d=d->next, j++);
	strBuf = IpToStr(d->addresses->next->addr);


	 /* �򿪷������ݱ����������ӿ�*/
    if ( (adhandle= pcap_open(d->name,            // ����������
                        100,                // ��Ҫ��������ݰ���С(������ǰ���ֽ�)
                        PCAP_OPENFLAG_PROMISCUOUS,  // ����ģʽ
                        1000,               // ��ʱʱ��
                        NULL,               // Զ����֤
                        errbuf              // ���󻺳���
                        ) ) == NULL)
    {
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        return 0;
    }


	else       /* ���������·�㣬Ϊ�˼򵥣�����ֻ������̫�� */
    if(pcap_datalink(adhandle) != DLT_EN10MB)
    {
        fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
        /* �ͷ��豸�б� */
        pcap_freealldevs(alldevs);
        return -1;
    }
	
	else return 1;
}

//����Լ�������IP��MAC��ַ
int GetSelfMac()
{
	struct pcap_pkthdr * pkt_header;
    const u_char * pkt_data;
	unsigned char sendbuf[42]={0};//arp���ṹ��С
    int i = -1;
    int res;
    ethernet_head eh;
    arp_head ah;
 
    memset(eh.dest_mac_add,0xff,6);
    memset(eh.source_mac_add,0x0f,6);
 
    memset(ah.source_mac_add,0x0f,6);
    memset(ah.dest_mac_add,0x00,6);
 
    eh.type = htons(ETH_ARP);
    ah.hardware_type = htons(ARP_HARDWARE);
    ah.protocol_type = htons(ETH_IP);
    ah.hardware_add_len = 6;
    ah.protocol_add_len = 4;
    ah.source_ip_add = inet_addr("219.219.71.230"); //����������ip
	//printf("%x\n",ah.source_ip_add);
    ah.operation_field = htons(ARP_REQUEST);
    // unsigned long ip;
    // ip = ntohl(inet_addr("192.168.1.101"));
    // ah.dest_ip_add =htonl(ip + loop);
	ah.dest_ip_add = inet_addr(strBuf.c_str());
	//printf("%x\n",ah.dest_ip_add);
    memset(sendbuf,0,sizeof(sendbuf));
	memcpy(sendbuf,&eh,sizeof(eh));
    memcpy(sendbuf+sizeof(eh),&ah,14);
	memcpy(sendbuf+sizeof(eh)+14,&ah.source_ip_add,10);
	memcpy(sendbuf+sizeof(eh)+24,&ah.dest_ip_add,4);

	if(pcap_sendpacket(adhandle,sendbuf,42)==0)
    {
    //   printf("\nPacketSend succeed\n");
    }
    else
    {
         printf("PacketSendPacket in getmine Error: %d\n",GetLastError());
         return 1;
    }
 
    while((res = pcap_next_ex(adhandle,&pkt_header,&pkt_data)) > 0)
    {
		if(*(unsigned short *)(pkt_data+12) == htons(ETH_ARP)&&
        *(unsigned short*)(pkt_data+20) == htons(ARP_REPLY)&&
        *(unsigned long*)(pkt_data+38) == inet_addr("219.219.71.230"))
        {
            printf("�ҵ�������ַ�ǣ�"); 
            for(i=0; i<5; i++)
            {
                selfMac[i] = *(unsigned char*)(pkt_data+22+i);				
				printf("%x:",selfMac[i]);
            }
            selfMac[i] = *(unsigned char*)(pkt_data+22+i);	
			printf("%x\n",selfMac[i]);
			myip = *(unsigned long *)(pkt_data+28);
			//printf("myip=%u",myip);
            break;			
        }
    }
	
	if(res == 0){
        printf("Get the packet timeout,please confirm whether the network connect!\n");
        return -1;
    }

	if(res == -1){
        printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
        return -2;
    }
	if(i==6) return 0;
    else return 2;
}

//��������ڵ����п��ܵ�IP��ַ����ARP������߳�
 
UINT CtestDlg::sendArpPacket(LPVOID pParam)
{ 
    unsigned char sendbuf[42];//arp���ṹ��С
    unsigned long ip;
	const char iptosendh[20] = {0};
    ethernet_head eh;
    arp_head ah;
    memset(eh.dest_mac_add,0xff,6);
    memcpy(eh.source_mac_add,selfMac,6);
 
    memcpy(ah.source_mac_add,selfMac,6);
    memset(ah.dest_mac_add,0x00,6);
 
    eh.type = htons(ETH_ARP);
    ah.hardware_type = htons(ARP_HARDWARE);
    ah.protocol_type = htons(ETH_IP);
    ah.hardware_add_len = 6;
    ah.protocol_add_len = 4;
    ah.operation_field = htons(ARP_REQUEST);
    ah.source_ip_add = myip;
 
    for (unsigned long i=0; i<HostNum; i++)
	{	
		for(unsigned long j=0;j<3;j++)
        {
            ip = firstip;
		    ah.dest_ip_add =htonl((ip) + i);
            memset(sendbuf,0,sizeof(sendbuf));
            memcpy(sendbuf,&eh,sizeof(eh));
            memcpy(sendbuf+sizeof(eh),&ah,14);
	        memcpy(sendbuf+sizeof(eh)+14,&ah.source_ip_add,10);
	        memcpy(sendbuf+sizeof(eh)+24,&ah.dest_ip_add,4);
            if(pcap_sendpacket(adhandle,sendbuf,42)==0)
            {
              // printf("\nRequest Packet succeed\n");
            }
            else
            {
                 printf("Request Packet in getmine Error: %d\n",GetLastError());
				 return 1;
            }
		    Sleep(100);
        }
	}
    flag = TRUE;
	return 0;
}

/*//���ڴ���δ��ռ��IP��ַ�����
UINT CtestDlg::Print_free(LPVOID pParam)
{
    CListCtrl *m_listctrl2 = (CListCtrl *)pParam;
	//Sleep(500);
	for(int i=0;i<HostNum;i++)
	{
	    if(freeip[i])
		{
			char str[20]={0};
			char str1[4],str2[4],str3[4],str4[4];
			char ch[2] = ".";
		    sprintf(str1,"%d",(firstip+i)&255);
			sprintf(str2,"%d",(firstip+i)>>8&255);
			sprintf(str3,"%d",(firstip+i)>>16&255);
			sprintf(str4,"%d",(firstip+i)>>24&255);
			strcat(str,str4);
			strcat(str,ch);
			strcat(str,str3);
			strcat(str,ch);
			strcat(str,str2);
			strcat(str,ch);
			strcat(str,str1);
			m_listctrl2->InsertItem(0,str,0);
		}
		Sleep(100);
	}
    return 1;
}*/

//����ARP��Ӧ�̣߳��������ݰ��󼴿ɻ�û������IP��ַ��
 
UINT CtestDlg::GetlivePc(LPVOID pParam)
{
    //pcap_t *p=(pcap_t *)lpParameter;
    int res;
	int aliveNum=0;
	threadInfo *ThreadInfo = (threadInfo *)pParam;
 
    // arp_head ah;
    struct pcap_pkthdr *pkt_header;
    const u_char * pkt_data;
    //unsigned char tempMac[6];
    while (true)
    {
        if(flag)
        {
            printf("ɨ����ϣ������߳��˳�!\n");
            //ExitThread(0);
            break;
        }
 
        if ((res = pcap_next_ex(adhandle,&pkt_header,&pkt_data)) > 0)
        { 
            //printf("%x",ntohs(*(unsigned short *)(pkt_data+12)));
            if(*(unsigned short *)(pkt_data+12) == htons(ETH_ARP))
            {
				arp_packet *recv = (arp_packet*)pkt_data;
				//printf("%x\n",recv->ah.source_ip_add);
				recv->ah.source_ip_add = *(unsigned long *)(pkt_data+28);
                if(*(unsigned short *)(pkt_data+20) == htons(ARP_REPLY))
                {
                    printf("����arpӦ�����\n");
                    printf("IP��ַ��%d.%d.%d.%d---------->mac��ַ��",
                    recv->ah.source_ip_add&255, recv->ah.source_ip_add>>8&255,
                    recv->ah.source_ip_add>>16&255, recv->ah.source_ip_add>>24&255);
                    pcGroup[aliveNum].ip = *(unsigned long *)(pkt_data+28);
                    memcpy(pcGroup[aliveNum].mac,(pkt_data+22),6);
					freeip[(recv->ah.source_ip_add>>24&255)-1] = 0;
					char str[20]={0};
					char str1[4],str2[4],str3[4],str4[4];
					char ch[2] = ".";
					sprintf(str1,"%d",recv->ah.source_ip_add&255);
					sprintf(str2,"%d",recv->ah.source_ip_add>>8&255);
					sprintf(str3,"%d",recv->ah.source_ip_add>>16&255);
					sprintf(str4,"%d",recv->ah.source_ip_add>>24&255);
					strcat(str,str1);
					strcat(str,ch);
					strcat(str,str2);
					strcat(str,ch);
					strcat(str,str3);
					strcat(str,ch);
					strcat(str,str4);					
					char mac[20]={0};
					char c[2]=":";
					char mac1[4],mac2[4],mac3[4],mac4[4],mac5[4],mac6[4];
					sprintf(mac1,"%02x",pcGroup[aliveNum].mac[0]);
					sprintf(mac2,"%02x",pcGroup[aliveNum].mac[1]);
					sprintf(mac3,"%02x",pcGroup[aliveNum].mac[2]);
					sprintf(mac4,"%02x",pcGroup[aliveNum].mac[3]);
					sprintf(mac5,"%02x",pcGroup[aliveNum].mac[4]);
					sprintf(mac6,"%02x",pcGroup[aliveNum].mac[5]);
					strcat(mac,mac1);
					strcat(mac,c);
					strcat(mac,mac2);
					strcat(mac,c);
					strcat(mac,mac3);
					strcat(mac,c);
					strcat(mac,mac4);
					strcat(mac,c);
					strcat(mac,mac5);
					strcat(mac,c);
					strcat(mac,mac6);
					LVFINDINFO findinfo;
					findinfo.flags = LVFI_PARTIAL|LVFI_STRING;
					findinfo.psz = (LPCSTR)str;
					if((*ThreadInfo).m_listctrl->FindItem(&findinfo)==-1)
					{
					    (*ThreadInfo).m_listctrl->InsertItem(aliveNum,str,0);
						(*ThreadInfo).m_listctrl->SetItemText(aliveNum,1,mac);
						aliveNum++;
					}					
                    /*for(int i=0; i<6; i++)
                    {
                        tempMac[i] = *(unsigned char*)(pkt_data+22+i);
                        printf("%02x",tempMac[i]);
                    }*/
                    printf("\n");
                }
            }
        }
    }
	//pThread->ResumeThread();
	CButton *pBtn= (*ThreadInfo).pBtn; //IDC_BUTTON1�����ť 
    if(pBtn!=NULL) 
    { 
        pBtn->EnableWindow(TRUE); // True or False 
    }
	CButton *pBtn1= (*ThreadInfo).pBtn1; //IDC_BUTTON1�����ť 
	if(pBtn1!=NULL) 
    { 
        pBtn1->EnableWindow(TRUE); // True or False 
    }
	flag = FALSE;
	return 0;
}

void CtestDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CtestDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR CtestDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CtestDlg::OnIpnFieldchangedIpaddress1(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMIPADDRESS pIPAddr = reinterpret_cast<LPNMIPADDRESS>(pNMHDR);
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	m_ipcontrol.GetAddress(ip_temp1);
	*pResult = 0;
}

void CtestDlg::OnBnClickedButton6()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	OnOK();
}

void CtestDlg::OnCbnSelchangeCombo1()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	
}

void CtestDlg::OnIpnFieldchangedIpaddress2(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMIPADDRESS pIPAddr = reinterpret_cast<LPNMIPADDRESS>(pNMHDR);
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	m_ipcontrol2.GetAddress(ip_temp2);
	*pResult = 0;
}

void CtestDlg::OnBnClickedButton1()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	CButton *pBtn= (CButton *)GetDlgItem(IDC_BUTTON1); //IDC_BUTTON1�����ť 
	ThreadInfo.pBtn = pBtn;
	ThreadInfo.m_listctrl = &m_listctrl;
	if(pBtn!=NULL) 
    { 
        pBtn->EnableWindow(FALSE); // True or False 
    }
	m_ipcontrol.GetAddress(ip_temp1);
	m_ipcontrol2.GetAddress(ip_temp2);
	dev_num=((CComboBox *)GetDlgItem(IDC_COMBO1))->GetCurSel()+1;
	firstip=ip_temp1;
	secondip=ip_temp2;
	HostNum = secondip - firstip + 1;
	OpenIf(dev_num);
	GetSelfMac();
	sThread = AfxBeginThread(sendArpPacket,NULL,0,0,0,NULL);
	gThread = AfxBeginThread(&CtestDlg::GetlivePc,&ThreadInfo,0,0,0,NULL);
	//pThread = AfxBeginThread(weak,NULL,0,0,0,NULL);
	//pThread->SuspendThread();
}

void CtestDlg::OnBnClickedButton3()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	CAboutDlg dlgAbout;
	dlgAbout.DoModal();
}

void CtestDlg::OnBnClickedButton5()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	CButton *pBtn= (CButton *)GetDlgItem(IDC_BUTTON5); //IDC_BUTTON5�����ť 
	if(pBtn!=NULL) 
    { 
        pBtn->EnableWindow(FALSE); // True or False 
    }
	m_listctrl.DeleteAllItems();
}

void CtestDlg::OnLvnItemchangedList3(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	*pResult = 0;
}
