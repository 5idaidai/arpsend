// testDlg.h : ͷ�ļ�
//

#pragma once
#include "afxcmn.h"


// CtestDlg �Ի���
class CtestDlg : public CDialog
{
// ����
public:
	CtestDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
	enum { IDD = IDD_TEST_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnIpnFieldchangedIpaddress1(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnBnClickedButton6();
	afx_msg void OnCbnSelchangeCombo1();
	afx_msg void OnIpnFieldchangedIpaddress2(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnBnClickedButton1();
	afx_msg void OnBnClickedButton3();
	afx_msg void OnBnClickedButton5();
	afx_msg void OnLvnItemchangedList3(NMHDR *pNMHDR, LRESULT *pResult);
	static UINT sendArpPacket(LPVOID pParam);
	static UINT GetlivePc(LPVOID pParam);
	static UINT Print_free(LPVOID pParam);
	CListCtrl m_listctrl;
	CIPAddressCtrl m_ipcontrol;
	CIPAddressCtrl m_ipcontrol2;
	DWORD ip_temp1;
	DWORD ip_temp2;
};
