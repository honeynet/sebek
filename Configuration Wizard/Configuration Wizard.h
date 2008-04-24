// Configuration Wizard.h : main header file for the CONFIGURATION WIZARD application
//

#if !defined(AFX_CONFIGURATIONWIZARD_H__97BB04A4_5548_4671_A37B_C3CD71CCAFBC__INCLUDED_)
#define AFX_CONFIGURATIONWIZARD_H__97BB04A4_5548_4671_A37B_C3CD71CCAFBC__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifndef __AFXWIN_H__
	#error include 'stdafx.h' before including this file for PCH
#endif

#include "resource.h"		// main symbols

/////////////////////////////////////////////////////////////////////////////
// CConfigurationWizardApp:
// See Configuration Wizard.cpp for the implementation of this class
//

class CConfigurationWizardApp : public CWinApp
{
public:
	CConfigurationWizardApp();

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CConfigurationWizardApp)
	public:
	virtual BOOL InitInstance();
	virtual int ExitInstance();
	//}}AFX_VIRTUAL

// Implementation

	//{{AFX_MSG(CConfigurationWizardApp)
		// NOTE - the ClassWizard will add and remove member functions here.
		//    DO NOT EDIT what you see in these blocks of generated code !
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};


/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_CONFIGURATIONWIZARD_H__97BB04A4_5548_4671_A37B_C3CD71CCAFBC__INCLUDED_)
