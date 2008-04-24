// ConfigurationWizardConfigFileName.cpp : implementation file
//

#include "stdafx.h"
#include "configuration wizard.h"
#include "ConfigurationWizardConfigFileName.h"
#include "DriverConfig.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CConfigurationWizardConfigFileName property page

IMPLEMENT_DYNCREATE(CConfigurationWizardConfigFileName, CPropertyPageEx)

CConfigurationWizardConfigFileName::CConfigurationWizardConfigFileName() : CPropertyPageEx(CConfigurationWizardConfigFileName::IDD)
{
	//{{AFX_DATA_INIT(CConfigurationWizardConfigFileName)
	m_strFileName = _T("");
	//}}AFX_DATA_INIT
	m_strHeaderTitle = "Configuration Program Name";
	m_strHeaderSubTitle = "Sebek will hide itself from all applications except the special configuration program. Specify the filename of the configuration program.";
	m_psp.dwFlags |= PSP_USEHEADERSUBTITLE | PSP_USEHEADERTITLE;
}

CConfigurationWizardConfigFileName::~CConfigurationWizardConfigFileName()
{
}

void CConfigurationWizardConfigFileName::DoDataExchange(CDataExchange* pDX)
{
	CPropertyPage::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CConfigurationWizardConfigFileName)
	DDX_Control(pDX, IDC_FILENAME, m_edtFileName);
	DDX_Text(pDX, IDC_FILENAME, m_strFileName);
	DDV_MaxChars(pDX, m_strFileName, CONFIG_PROC_SIZE);
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(CConfigurationWizardConfigFileName, CPropertyPageEx)
	//{{AFX_MSG_MAP(CConfigurationWizardConfigFileName)
	ON_BN_CLICKED(IDC_THISAPP, OnThisapp)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CConfigurationWizardConfigFileName message handlers

BOOL CConfigurationWizardConfigFileName::OnSetActive() 
{
	CPropertySheet *pParentSheet = (CPropertySheet *)GetParent();
	pParentSheet->SetWizardButtons(PSWIZB_NEXT | PSWIZB_BACK);
	
	CDriverConfig &objConfig = CSingleton<CDriverConfig>::Instance();
	
	m_edtFileName.SetWindowText(objConfig.GetConfigFileName().c_str());	
	if(objConfig.GetConfigFileName().size() == 0)
		OnThisapp();

	return CPropertyPageEx::OnSetActive();
}

LRESULT CConfigurationWizardConfigFileName::OnWizardNext() 
{
	UpdateData();
	
	if(m_strFileName == "") {
		MessageBox("No filename was specified. Please specify a filename!", "No File Name Specified!", MB_OK | MB_ICONEXCLAMATION);
		return -1;
	}
	
	CDriverConfig &objConfig = CSingleton<CDriverConfig>::Instance();
	objConfig.SetConfigFileName(m_strFileName);
	
	return CPropertyPageEx::OnWizardNext();
}

void CConfigurationWizardConfigFileName::OnThisapp() 
{
	char *p;
  char file_name[MAX_PATH+1];

  if (GetModuleFileName (GetModuleHandle (NULL), file_name, sizeof (file_name)-1)) {
		p = strrchr (file_name, '\\');
		p++;
		p[strlen(p) - 4] = '\0'; // Remove the ".exe"
		if(strlen(p) > CONFIG_PROC_SIZE) {
			p[CONFIG_PROC_SIZE - 1] = '\0';
		}
		m_edtFileName.SetWindowText(p);	
	}
}
