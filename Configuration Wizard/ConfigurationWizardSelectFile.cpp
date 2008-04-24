// ConfigurationWizardSelectFile.cpp : implementation file
//

#include "stdafx.h"
#include "configuration wizard.h"
#include "ConfigurationWizardSelectFile.h"
#include "DriverConfig.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CConfigurationWizardSelectFile property page

IMPLEMENT_DYNCREATE(CConfigurationWizardSelectFile, CPropertyPageEx)

CConfigurationWizardSelectFile::CConfigurationWizardSelectFile() : CPropertyPageEx(CConfigurationWizardSelectFile::IDD)
{
	//{{AFX_DATA_INIT(CConfigurationWizardSelectFile)
	m_strFileLoc = _T("");
	//}}AFX_DATA_INIT
	m_strHeaderTitle = "Please select the Sebek driver file";
	m_strHeaderSubTitle = "The Sebek Driver file contains the configuration information used throughout this wizard.";
	m_psp.dwFlags |= PSP_USEHEADERSUBTITLE | PSP_USEHEADERTITLE;
}

CConfigurationWizardSelectFile::~CConfigurationWizardSelectFile()
{
}

void CConfigurationWizardSelectFile::DoDataExchange(CDataExchange* pDX)
{
	CPropertyPage::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CConfigurationWizardSelectFile)
	DDX_Control(pDX, IDC_FILELOC, m_edtFileLoc);
	DDX_Text(pDX, IDC_FILELOC, m_strFileLoc);
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(CConfigurationWizardSelectFile, CPropertyPageEx)
	//{{AFX_MSG_MAP(CConfigurationWizardSelectFile)
	ON_BN_CLICKED(IDC_BROWSE, OnBrowse)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CConfigurationWizardSelectFile message handlers

void CConfigurationWizardSelectFile::OnBrowse() 
{
	OPENFILENAME ofn;       // common dialog box structure
	char szFile[260];       // buffer for file name
	memset(szFile, 0, sizeof(szFile));
	
	// Initialize OPENFILENAME
	ZeroMemory(&ofn, sizeof(OPENFILENAME));
	ofn.lStructSize = sizeof(OPENFILENAME);
	ofn.hwndOwner = m_hWnd;
	ofn.lpstrFile = szFile;
	ofn.nMaxFile = sizeof(szFile);
	ofn.lpstrFilter = "All (*.*)\0*.*\0";
	ofn.nFilterIndex = 1;
	ofn.lpstrFileTitle = NULL;
	ofn.nMaxFileTitle = 0;
	ofn.lpstrInitialDir = NULL;
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

	// Display the Open dialog box. 

	if (GetOpenFileName(&ofn)==TRUE) {
		m_edtFileLoc.SetWindowText(szFile);
		CPropertySheet *pParentSheet = (CPropertySheet *)GetParent();
	}	
}

LRESULT CConfigurationWizardSelectFile::OnWizardNext() 
{
	UpdateData();
	
	if(m_strFileLoc == "") {
		MessageBox("No driver was specified. Please specify a driver!", "No Driver Specified!", MB_OK | MB_ICONEXCLAMATION);
		return -1;
	}
	
	CDriverConfig &objConfig = CSingleton<CDriverConfig>::Instance();
	objConfig.SetFileLocation(m_strFileLoc);
	if(!objConfig.LoadConfig()) {
		MessageBox(objConfig.GetErrorString().c_str(), "Error loading configuration!", MB_OK | MB_ICONEXCLAMATION);
		return -1;
	}

	return CPropertyPageEx::OnWizardNext();
}

BOOL CConfigurationWizardSelectFile::OnSetActive() 
{
	CPropertySheet *pParentSheet = (CPropertySheet *)GetParent();
	pParentSheet->SetWizardButtons(PSWIZB_NEXT | PSWIZB_BACK);
	
	char strSystemDir[MAX_PATH + 1];
	ZeroMemory(strSystemDir, MAX_PATH + 1);
	
	GetSystemDirectory(strSystemDir, MAX_PATH);

	m_strFileLoc = strSystemDir;
	m_strFileLoc += "\\drivers\\SEBEK.SYS";
	
	UpdateData(FALSE);
  return CPropertyPageEx::OnSetActive();
}
