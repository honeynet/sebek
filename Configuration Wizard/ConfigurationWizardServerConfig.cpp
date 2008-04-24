// ConfigurationWizardServerConfig.cpp : implementation file
//

#include "stdafx.h"
#include "configuration wizard.h"
#include "ConfigurationWizardServerConfig.h"
#include "DriverConfig.h"

using namespace std;

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CConfigurationWizardServerConfig property page

IMPLEMENT_DYNCREATE(CConfigurationWizardServerConfig, CPropertyPageEx)

CConfigurationWizardServerConfig::CConfigurationWizardServerConfig() : CPropertyPageEx(CConfigurationWizardServerConfig::IDD)
{
	//{{AFX_DATA_INIT(CConfigurationWizardServerConfig)
	m_strMAC0 = _T("");
	m_strMAC1 = _T("");
	m_strMAC2 = _T("");
	m_strMAC3 = _T("");
	m_strMAC4 = _T("");
	m_strMAC5 = _T("");
	m_uiDestPort = 0;
	//}}AFX_DATA_INIT
	m_strHeaderTitle = "Server Configuration";
	m_strHeaderSubTitle = "Sebek logs all data it collects to a central server. Please specify the information sebek will use to generate packets the server can collect.";
	m_psp.dwFlags |= PSP_USEHEADERSUBTITLE | PSP_USEHEADERTITLE;
}

CConfigurationWizardServerConfig::~CConfigurationWizardServerConfig()
{
}

void CConfigurationWizardServerConfig::DoDataExchange(CDataExchange* pDX)
{
	CPropertyPage::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CConfigurationWizardServerConfig)
	DDX_Control(pDX, IDC_DESTPORT, m_edtDestPort);
	DDX_Control(pDX, IDC_DESTIP, m_DestIP);
	DDX_Control(pDX, IDC_MAC5, m_edtMAC5);
	DDX_Control(pDX, IDC_MAC4, m_edtMAC4);
	DDX_Control(pDX, IDC_MAC3, m_edtMAC3);
	DDX_Control(pDX, IDC_MAC2, m_edtMAC2);
	DDX_Control(pDX, IDC_MAC1, m_edtMAC1);
	DDX_Control(pDX, IDC_MAC0, m_edtMAC0);
	DDX_Text(pDX, IDC_MAC0, m_strMAC0);
	DDX_Text(pDX, IDC_MAC1, m_strMAC1);
	DDX_Text(pDX, IDC_MAC2, m_strMAC2);
	DDX_Text(pDX, IDC_MAC3, m_strMAC3);
	DDX_Text(pDX, IDC_MAC4, m_strMAC4);
	DDX_Text(pDX, IDC_MAC5, m_strMAC5);
	DDX_Text(pDX, IDC_DESTPORT, m_uiDestPort);
	DDV_MinMaxUInt(pDX, m_uiDestPort, 1, 65536);
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(CConfigurationWizardServerConfig, CPropertyPageEx)
	//{{AFX_MSG_MAP(CConfigurationWizardServerConfig)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

BOOL CConfigurationWizardServerConfig::OnSetActive() 
{
	CPropertySheet *pParentSheet = (CPropertySheet *)GetParent();
	pParentSheet->SetWizardButtons(PSWIZB_NEXT | PSWIZB_BACK);
	
	CDriverConfig &objConfig = CSingleton<CDriverConfig>::Instance();
	const string &strMAC = objConfig.GetDestinationMAC();

	string strMACOctet;
	strMACOctet += strMAC[0];
	strMACOctet += strMAC[1];
	m_edtMAC0.SetWindowText(strMACOctet.c_str());
	
	strMACOctet = "";
	strMACOctet += strMAC[2];
	strMACOctet += strMAC[3];
	m_edtMAC1.SetWindowText(strMACOctet.c_str());

	strMACOctet = "";
	strMACOctet += strMAC[4];
	strMACOctet += strMAC[5];
	m_edtMAC2.SetWindowText(strMACOctet.c_str());

	strMACOctet = "";
	strMACOctet += strMAC[6];
	strMACOctet += strMAC[7];
	m_edtMAC3.SetWindowText(strMACOctet.c_str());

	strMACOctet = "";
	strMACOctet += strMAC[8];
	strMACOctet += strMAC[9];
	m_edtMAC4.SetWindowText(strMACOctet.c_str());

	strMACOctet = "";
	strMACOctet += strMAC[10];
	strMACOctet += strMAC[11];
	m_edtMAC5.SetWindowText(strMACOctet.c_str());
	
	m_DestIP.SetWindowText(objConfig.GetDestinationIP().c_str());
	m_edtDestPort.SetWindowText(objConfig.GetDestinationPortAsString().c_str());
	return CPropertyPageEx::OnSetActive();
}

LRESULT CConfigurationWizardServerConfig::OnWizardNext() 
{
	UpdateData();

	if(!m_DestIP.GetWindowTextLength()) {
		MessageBox("No Destination IP Address was specified. Please specify an address!", "No Destination IP Address Specified!", MB_OK | MB_ICONEXCLAMATION);
		return -1;
	}

	CString strDestIP;
	m_DestIP.GetWindowText(strDestIP);

	if(!m_strMAC0 || !m_strMAC1 || !m_strMAC2 || !m_strMAC3 || !m_strMAC4 || !m_strMAC5) {
		MessageBox("Invalid Destination MAC was specified. Please specify a valid MAC!", "No Destination MAC Specified!", MB_OK | MB_ICONEXCLAMATION);
		return -1;
	}

	string strMAC = m_strMAC0 + m_strMAC1 + m_strMAC2 + m_strMAC3 + m_strMAC4 + m_strMAC5;
	CDriverConfig &objConfig = CSingleton<CDriverConfig>::Instance();
	objConfig.SetDestinationIP(strDestIP);
	objConfig.SetDestinationMAC(strMAC);
	objConfig.SetDestinationPort(m_uiDestPort);

	return CPropertyPageEx::OnWizardNext();
}
