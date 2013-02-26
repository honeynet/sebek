#if !defined(AFX_CONFIGURATIONWIZARDSELECTFILE_H__E49D8AA8_018F_4E1A_90FA_4F5450843E94__INCLUDED_)
#define AFX_CONFIGURATIONWIZARDSELECTFILE_H__E49D8AA8_018F_4E1A_90FA_4F5450843E94__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
// ConfigurationWizardSelectFile.h : header file
//

/////////////////////////////////////////////////////////////////////////////
// CConfigurationWizardSelectFile dialog

class CConfigurationWizardSelectFile : public CPropertyPageEx
{
	DECLARE_DYNCREATE(CConfigurationWizardSelectFile)

// Construction
public:
	CConfigurationWizardSelectFile();
	~CConfigurationWizardSelectFile();

// Dialog Data
	//{{AFX_DATA(CConfigurationWizardSelectFile)
	enum { IDD = IDD_CONFIGWIZ_SELECTFILE };
	CEdit	m_edtFileLoc;
	CString	m_strFileLoc;
	//}}AFX_DATA


// Overrides
	// ClassWizard generate virtual function overrides
	//{{AFX_VIRTUAL(CConfigurationWizardSelectFile)
	public:
	virtual LRESULT OnWizardNext();
	virtual BOOL OnSetActive();
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	// Generated message map functions
	//{{AFX_MSG(CConfigurationWizardSelectFile)
	afx_msg void OnBrowse();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()

};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_CONFIGURATIONWIZARDSELECTFILE_H__E49D8AA8_018F_4E1A_90FA_4F5450843E94__INCLUDED_)
