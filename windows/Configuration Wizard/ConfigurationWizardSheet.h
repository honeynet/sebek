// ConfigurationWizardSheet.h : header file
//
// This class defines custom modal property sheet 
// CConfigurationWizardSheet.
 
#ifndef __CONFIGURATIONWIZARDSHEET_H__
#define __CONFIGURATIONWIZARDSHEET_H__

#include "ConfigurationWizardWelcome.h"
#include "ConfigurationWizardSelectFile.h"
#include "ConfigurationWizardServerConfig.h"
#include "ConfigurationWizardMagicValue.h"
#include "ConfigurationWizardNetworkConfig.h"
#include "ConfigurationWizardConfigFileName.h"
#include "ConfigurationWizardFinish.h"

/////////////////////////////////////////////////////////////////////////////
// CConfigurationWizardSheet

class CConfigurationWizardSheet : public CPropertySheetEx
{
	DECLARE_DYNAMIC(CConfigurationWizardSheet)

// Construction
public:
	CConfigurationWizardSheet(CWnd* pWndParent = NULL, UINT iSelectPage = 0, HBITMAP hWatermark = NULL,
			HPALETTE hpalWatermark = NULL, HBITMAP hHeader = NULL);

// Attributes
public:
	CConfigurationWizardWelcome m_WelcomePage;
	CConfigurationWizardSelectFile m_SelectFilePage;
	CConfigurationWizardServerConfig m_ServerConfigPage;
	CConfigurationWizardMagicValue m_MagicValuePage;
	CConfigurationWizardNetworkConfig m_NetworkConfigPage;
	CConfigurationWizardConfigFileName m_ConfigFileNamePage;
	CConfigurationWizardFinish m_FinishPage;

// Operations
public:

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CConfigurationWizardSheet)
	//}}AFX_VIRTUAL

// Implementation
public:
	virtual ~CConfigurationWizardSheet();

// Generated message map functions
protected:
	//{{AFX_MSG(CConfigurationWizardSheet)
		// NOTE - the ClassWizard will add and remove member functions here.
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

/////////////////////////////////////////////////////////////////////////////

#endif	// __CONFIGURATIONWIZARDSHEET_H__
