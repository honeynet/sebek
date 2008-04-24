#if !defined(AFX_CONFIGURATIONWIZARDFINISH_H__39372D29_E01E_401E_B79E_3FD5F177C448__INCLUDED_)
#define AFX_CONFIGURATIONWIZARDFINISH_H__39372D29_E01E_401E_B79E_3FD5F177C448__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
// ConfigurationWizardFinish.h : header file
//

/////////////////////////////////////////////////////////////////////////////
// CConfigurationWizardFinish dialog

class CConfigurationWizardFinish : public CPropertyPageEx
{
	DECLARE_DYNCREATE(CConfigurationWizardFinish)

// Construction
public:
	CConfigurationWizardFinish();
	~CConfigurationWizardFinish();

// Dialog Data
	//{{AFX_DATA(CConfigurationWizardFinish)
	enum { IDD = IDD_CONFIGWIZ_FINISHED };
	CEdit	m_edtDetails;
	CString	m_strDetails;
	//}}AFX_DATA


// Overrides
	// ClassWizard generate virtual function overrides
	//{{AFX_VIRTUAL(CConfigurationWizardFinish)
	public:
	virtual BOOL OnSetActive();
	virtual BOOL OnWizardFinish();
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	// Generated message map functions
	//{{AFX_MSG(CConfigurationWizardFinish)
		// NOTE: the ClassWizard will add member functions here
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()

};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_CONFIGURATIONWIZARDFINISH_H__39372D29_E01E_401E_B79E_3FD5F177C448__INCLUDED_)
