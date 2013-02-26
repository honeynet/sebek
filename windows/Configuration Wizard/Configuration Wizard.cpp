// Configuration Wizard.cpp : Defines the class behaviors for the application.
//

#include "stdafx.h"
#include "Configuration Wizard.h"
#include "ConfigurationWizardSheet.h"
#include "DriverConfig.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CConfigurationWizardApp

BEGIN_MESSAGE_MAP(CConfigurationWizardApp, CWinApp)
	//{{AFX_MSG_MAP(CConfigurationWizardApp)
		// NOTE - the ClassWizard will add and remove mapping macros here.
		//    DO NOT EDIT what you see in these blocks of generated code!
	//}}AFX_MSG
	ON_COMMAND(ID_HELP, CWinApp::OnHelp)
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CConfigurationWizardApp construction

CConfigurationWizardApp::CConfigurationWizardApp()
{
	// TODO: add construction code here,
	// Place all significant initialization in InitInstance
}

/////////////////////////////////////////////////////////////////////////////
// The one and only CConfigurationWizardApp object

CConfigurationWizardApp theApp;

/////////////////////////////////////////////////////////////////////////////
// CConfigurationWizardApp initialization

BOOL CConfigurationWizardApp::InitInstance()
{
// Memory Leak Checking...
#ifdef _DEBUG

// get current dbg flag (report it)
int flag = _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG);

// logically OR leak check bit
flag |= _CRTDBG_LEAK_CHECK_DF;

// set the flags again
_CrtSetDbgFlag(flag); 
#endif
	AfxEnableControlContainer();

	// Standard initialization
	// If you are not using these features and wish to reduce the size
	//  of your final executable, you should remove from the following
	//  the specific initialization routines you do not need.

#ifdef _AFXDLL
	Enable3dControls();   // Call this when using MFC in a shared DLL
#else
	Enable3dControlsStatic(); // Call this when linking to MFC statically
#endif

	// Create our DriverConfiguration Singleton
	CDriverConfig &objConfig = CSingleton<CDriverConfig>::Instance();
		
	CBitmap bmWatermark;
	CBitmap bmHeader;
	if(!bmWatermark.LoadBitmap(IDB_WIZWATERMARK))
		return FALSE;
	if(!bmHeader.LoadBitmap(IDB_WIZHEADER))
		return FALSE;

	CConfigurationWizardSheet propSheet(NULL, 0, bmWatermark, NULL, bmHeader);;
	m_pMainWnd = &propSheet;
	propSheet.DoModal();

	// Since the dialog has been closed, return FALSE so that we exit the
	//  application, rather than start the application's message pump.
 

	return FALSE;
}

int CConfigurationWizardApp::ExitInstance() 
{
	CSingleton<CDriverConfig>::Release();	
	return CWinApp::ExitInstance();
}
