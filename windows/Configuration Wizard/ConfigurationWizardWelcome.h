// ConfigurationWizardWelcome.h : header file
//

#ifndef __CONFIGURATIONWIZARDWELCOME_H__
#define __CONFIGURATIONWIZARDWELCOME_H__

/////////////////////////////////////////////////////////////////////////////
// CConfigurationWizardWelcome dialog

class CConfigurationWizardWelcome : public CPropertyPageEx
{
	DECLARE_DYNCREATE(CConfigurationWizardWelcome)

// Construction
public:
	CConfigurationWizardWelcome();
	~CConfigurationWizardWelcome();

// Dialog Data
	//{{AFX_DATA(CConfigurationWizardWelcome)
	enum { IDD = IDD_CONFIGWIZ_WELCOME };
		// NOTE - ClassWizard will add data members here.
		//    DO NOT EDIT what you see in these blocks of generated code !
	//}}AFX_DATA


// Overrides
	// ClassWizard generate virtual function overrides
	//{{AFX_VIRTUAL(CConfigurationWizardWelcome)
	public:
	virtual BOOL OnSetActive();
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	// Generated message map functions
	//{{AFX_MSG(CConfigurationWizardWelcome)
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()

};



#endif // __CONFIGURATIONWIZARDWELCOME_H__
