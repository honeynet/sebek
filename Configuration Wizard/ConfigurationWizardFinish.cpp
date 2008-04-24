// ConfigurationWizardFinish.cpp : implementation file
//

#include "stdafx.h"
#include "configuration wizard.h"
#include "ConfigurationWizardFinish.h"
#include "DriverConfig.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

using namespace std;

/////////////////////////////////////////////////////////////////////////////
// CConfigurationWizardFinish property page

IMPLEMENT_DYNCREATE(CConfigurationWizardFinish, CPropertyPageEx)

CConfigurationWizardFinish::CConfigurationWizardFinish() : CPropertyPageEx(CConfigurationWizardFinish::IDD)
{
	//{{AFX_DATA_INIT(CConfigurationWizardFinish)
	m_strDetails = _T("");
	//}}AFX_DATA_INIT
	m_psp.dwFlags |= PSP_DEFAULT|PSP_HIDEHEADER;
}

CConfigurationWizardFinish::~CConfigurationWizardFinish()
{
}

void CConfigurationWizardFinish::DoDataExchange(CDataExchange* pDX)
{
	CPropertyPage::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CConfigurationWizardFinish)
	DDX_Control(pDX, IDC_CONFIGDETAILS, m_edtDetails);
	DDX_Text(pDX, IDC_CONFIGDETAILS, m_strDetails);
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(CConfigurationWizardFinish, CPropertyPage)
	//{{AFX_MSG_MAP(CConfigurationWizardFinish)
		// NOTE: the ClassWizard will add message map macros here
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CConfigurationWizardFinish message handlers

BOOL CConfigurationWizardFinish::OnSetActive() 
{
	if(!CPropertyPage::OnSetActive()) 
		return FALSE;

	CPropertySheet *pParentSheet = (CPropertySheet *)GetParent();

	pParentSheet->SetWizardButtons(PSWIZB_BACK | PSWIZB_FINISH);

	UpdateData();
	CDriverConfig &objConfig = CSingleton<CDriverConfig>::Instance();

	string strDetails;
	strDetails = "File Location: " + objConfig.GetFileLocation() + "\r\n";
	strDetails += "Destination MAC: ";

	const string &strMAC = objConfig.GetDestinationMAC();
	for(unsigned int i = 0; i < strMAC.size(); i+=2) {
		strDetails += strMAC.substr(i, 2);
		if(i != strMAC.size() - 2)
			strDetails += ":";
	}
	strDetails += "\r\n";

	strDetails += "Destination IP: " + objConfig.GetDestinationIP() + "\r\n";
	strDetails += "Destination Port: " + objConfig.GetDestinationPortAsString() + "\r\n";
	strDetails += "Magic Value: " + objConfig.GetMagicValueAsString() + "\r\n";
	strDetails += "Network Interface: " + objConfig.GetDeviceName() + "\r\n";
	strDetails += "Configuration File Name: " + objConfig.GetConfigFileName() + "\r\n";
	m_edtDetails.SetWindowText(strDetails.c_str());
	
	return TRUE;
}

BOOL CConfigurationWizardFinish::OnWizardFinish() 
{
	CDriverConfig &objConfig = CSingleton<CDriverConfig>::Instance();

	// We do this here because we do not give the use an option to configure this.
	if(!objConfig.SaveConfig()) {
		MessageBox(objConfig.GetErrorString().c_str(), "Error saving configuration!", MB_OK | MB_ICONEXCLAMATION);
		return -1;
	}
	
	return CPropertyPage::OnWizardFinish();
}
