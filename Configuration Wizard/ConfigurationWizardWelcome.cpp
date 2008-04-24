// ConfigurationWizardWelcome.cpp : implementation file
//

#include "stdafx.h"
#include "resource.h"
#include "ConfigurationWizardWelcome.h"

#ifdef _DEBUG
#undef THIS_FILE
static char BASED_CODE THIS_FILE[] = __FILE__;
#endif

IMPLEMENT_DYNCREATE(CConfigurationWizardWelcome, CPropertyPageEx)

BEGIN_MESSAGE_MAP(CConfigurationWizardWelcome, CPropertyPageEx)
	//{{AFX_MSG_MAP(CConfigurationWizardWelcome)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CConfigurationWizardWelcome property page

CConfigurationWizardWelcome::CConfigurationWizardWelcome() : CPropertyPageEx(CConfigurationWizardWelcome::IDD)
{
	//{{AFX_DATA_INIT(CConfigurationWizardWelcome)
		// NOTE: the ClassWizard will add member initialization here
	//}}AFX_DATA_INIT
	m_psp.dwFlags |= PSP_DEFAULT|PSP_HIDEHEADER;
}

CConfigurationWizardWelcome::~CConfigurationWizardWelcome()
{
}

void CConfigurationWizardWelcome::DoDataExchange(CDataExchange* pDX)
{
	CPropertyPage::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CConfigurationWizardWelcome)
		// NOTE: the ClassWizard will add DDX and DDV calls here
	//}}AFX_DATA_MAP
}

BOOL CConfigurationWizardWelcome::OnSetActive() 
{
	CPropertySheet *pParentSheet = (CPropertySheet*)GetParent();

  pParentSheet->SetWizardButtons(PSWIZB_NEXT);

  return CPropertyPageEx::OnSetActive();
}
