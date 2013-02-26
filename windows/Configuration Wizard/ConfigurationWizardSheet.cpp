 // ConfigurationWizardSheet.cpp : implementation file
//

#include "stdafx.h"
#include "resource.h"
#include "ConfigurationWizardSheet.h"

#ifdef _DEBUG
#undef THIS_FILE
static char BASED_CODE THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CConfigurationWizardSheet

IMPLEMENT_DYNAMIC(CConfigurationWizardSheet, CPropertySheetEx)

CConfigurationWizardSheet::CConfigurationWizardSheet(CWnd* pParentWnd,
	UINT iSelectPage, HBITMAP hWatermark, HPALETTE hpalWatermark,
	HBITMAP hHeader)
: CPropertySheetEx(IDS_PROPSHT_CAPTION, pParentWnd, iSelectPage,
				  hWatermark, hpalWatermark, hHeader)
{
	// Add all of the property pages here.  Note that
	// the order that they appear in here will be
	// the order they appear in on screen.  By default,
	// the first page of the set is the active one.
	// One way to make a different property page the 
	// active one is to call SetActivePage().

	AddPage(&m_WelcomePage);
	AddPage(&m_SelectFilePage);
	AddPage(&m_ServerConfigPage);
	AddPage(&m_MagicValuePage);
	AddPage(&m_NetworkConfigPage);
	AddPage(&m_ConfigFileNamePage);
	AddPage(&m_FinishPage);

	//Set the Wizard 97 Style for the Property Sheet
	m_psh.dwFlags |= PSH_WIZARD97|PSH_WATERMARK;
}

CConfigurationWizardSheet::~CConfigurationWizardSheet()
{
}


BEGIN_MESSAGE_MAP(CConfigurationWizardSheet, CPropertySheet)
	//{{AFX_MSG_MAP(CConfigurationWizardSheet)
		// NOTE - the ClassWizard will add and remove mapping macros here.
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()


/////////////////////////////////////////////////////////////////////////////
// CConfigurationWizardSheet message handlers


