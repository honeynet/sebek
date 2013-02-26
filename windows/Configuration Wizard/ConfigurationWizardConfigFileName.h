#if !defined(AFX_CONFIGURATIONWIZARDCONFIGFILENAME_H__BE7685DC_1DBC_4F53_8B50_340E5CAF0FE6__INCLUDED_)
#define AFX_CONFIGURATIONWIZARDCONFIGFILENAME_H__BE7685DC_1DBC_4F53_8B50_340E5CAF0FE6__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
// ConfigurationWizardConfigFileName.h : header file
//

/////////////////////////////////////////////////////////////////////////////
// CConfigurationWizardConfigFileName dialog

class CConfigurationWizardConfigFileName : public CPropertyPageEx
{
	DECLARE_DYNCREATE(CConfigurationWizardConfigFileName)

// Construction
public:
	CConfigurationWizardConfigFileName();
	~CConfigurationWizardConfigFileName();

// Dialog Data
	//{{AFX_DATA(CConfigurationWizardConfigFileName)
	enum { IDD = IDD_CONFIGWIZ_CONFIGFILENAME };
	CEdit	m_edtFileName;
	CString	m_strFileName;
	//}}AFX_DATA


// Overrides
	// ClassWizard generate virtual function overrides
	//{{AFX_VIRTUAL(CConfigurationWizardConfigFileName)
	public:
	virtual BOOL OnSetActive();
	virtual LRESULT OnWizardNext();
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	// Generated message map functions
	//{{AFX_MSG(CConfigurationWizardConfigFileName)
	afx_msg void OnThisapp();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()

};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_CONFIGURATIONWIZARDCONFIGFILENAME_H__BE7685DC_1DBC_4F53_8B50_340E5CAF0FE6__INCLUDED_)
