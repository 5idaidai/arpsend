// testDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "test.h"
#include "testDlg.h"
#include "stdlib.h"
#include "pcap.h"
#include "remote-ext.h"

#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"Packet.lib")
#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
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


// CtestDlg 对话框




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
	ON_LBN_SELCHANGE(IDC_LIST2, &CtestDlg::OnLbnSelchangeList2)
	ON_NOTIFY(IPN_FIELDCHANGED, IDC_IPADDRESS1, &CtestDlg::OnIpnFieldchangedIpaddress1)
	ON_BN_CLICKED(IDC_BUTTON6, &CtestDlg::OnBnClickedButton6)
	ON_CBN_SELCHANGE(IDC_COMBO1, &CtestDlg::OnCbnSelchangeCombo1)
	ON_NOTIFY(IPN_FIELDCHANGED, IDC_IPADDRESS2, &CtestDlg::OnIpnFieldchangedIpaddress2)
	ON_BN_CLICKED(IDC_BUTTON1, &CtestDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &CtestDlg::OnBnClickedButton2)
	ON_BN_CLICKED(IDC_BUTTON3, &CtestDlg::OnBnClickedButton3)
	ON_BN_CLICKED(IDC_BUTTON4, &CtestDlg::OnBnClickedButton4)
	ON_BN_CLICKED(IDC_BUTTON5, &CtestDlg::OnBnClickedButton5)
	ON_BN_CLICKED(IDOK, &CtestDlg::OnBnClickedOk)
	ON_BN_CLICKED(IDCANCEL, &CtestDlg::OnBnClickedCancel)
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST3, &CtestDlg::OnLvnItemchangedList3)
END_MESSAGE_MAP()


// CtestDlg 消息处理程序

BOOL CtestDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
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

	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	//初始化网卡接口
	CString strTemp;
	((CComboBox*)GetDlgItem(IDC_COMBO1))->ResetContent();  //消除现有所有内容
    pcap_if_t *alldevs;
    pcap_if_t *d;
	char errbuf[PCAP_ERRBUF_SIZE];/* 用来定义收集winpcap错误的缓冲区的大小*/
	/* 获取接口列表 */
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

	//初始化IP、MAC地址列表
	CString temp[2]={"IP地址","网卡物理地址"};
	for(int i=0;i<2;i++)
	{
		m_listctrl.InsertColumn(i,temp[i],LVCFMT_LEFT,50);
	}

	//初始化IP Address Control
	m_ipcontrol.SetAddress(0,0,0,0);
	m_ipcontrol2.SetAddress(0,0,0,0);

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
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

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CtestDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CtestDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CtestDlg::OnLbnSelchangeList2()
{
	// TODO: 在此添加控件通知处理程序代码
}

void CtestDlg::OnIpnFieldchangedIpaddress1(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMIPADDRESS pIPAddr = reinterpret_cast<LPNMIPADDRESS>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码
	m_ipcontrol.GetAddress(ip_temp1);
	*pResult = 0;
}

void CtestDlg::OnBnClickedButton6()
{
	// TODO: 在此添加控件通知处理程序代码
	OnOK();
}

void CtestDlg::OnCbnSelchangeCombo1()
{
	// TODO: 在此添加控件通知处理程序代码
}

void CtestDlg::OnIpnFieldchangedIpaddress2(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMIPADDRESS pIPAddr = reinterpret_cast<LPNMIPADDRESS>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码
	*pResult = 0;
}

void CtestDlg::OnBnClickedButton1()
{
	// TODO: 在此添加控件通知处理程序代码
	m_ipcontrol2.SetAddress(ip_temp1);
}

void CtestDlg::OnBnClickedButton2()
{
	// TODO: 在此添加控件通知处理程序代码
}

void CtestDlg::OnBnClickedButton3()
{
	// TODO: 在此添加控件通知处理程序代码
	CAboutDlg dlgAbout;
	dlgAbout.DoModal();
}

void CtestDlg::OnBnClickedButton4()
{
	// TODO: 在此添加控件通知处理程序代码
}

void CtestDlg::OnBnClickedButton5()
{
	// TODO: 在此添加控件通知处理程序代码
}

void CtestDlg::OnBnClickedOk()
{
	// TODO: 在此添加控件通知处理程序代码
	OnOK();
}

void CtestDlg::OnBnClickedCancel()
{
	// TODO: 在此添加控件通知处理程序代码
	OnCancel();
}

void CtestDlg::OnLvnItemchangedList3(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码
	*pResult = 0;
}
