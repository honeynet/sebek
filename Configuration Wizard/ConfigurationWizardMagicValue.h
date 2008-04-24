#if !defined(AFX_CONFIGURATIONWIZARDMAGICVALUE_H__4FEC3E79_7343_4079_9131_C356D1AB07B2__INCLUDED_)
#define AFX_CONFIGURATIONWIZARDMAGICVALUE_H__4FEC3E79_7343_4079_9131_C356D1AB07B2__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
// ConfigurationWizardMagicValue.h : header file
//

/////////////////////////////////////////////////////////////////////////////
// CConfigurationWizardMagicValue dialog

class CConfigurationWizardMagicValue : public CPropertyPageEx
{
	DECLARE_DYNCREATE(CConfigurationWizardMagicValue)

// Construction
public:
	CConfigurationWizardMagicValue();
	~CConfigurationWizardMagicValue();

// Dialog Data
	//{{AFX_DATA(CConfigurationWizardMagicValue)
	enum { IDD = IDD_CONFIGWIZ_MAGICVALUE };
	CEdit	m_edtMagicValue;
	UINT	m_uiMagicValue;
	//}}AFX_DATA


// Overrides
	// ClassWizard generate virtual function overrides
	//{{AFX_VIRTUAL(CConfigurationWizardMagicValue)
	public:
	virtual BOOL OnSetActive();
	virtual LRESULT OnWizardNext();
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	// Generated message map functions
	//{{AFX_MSG(CConfigurationWizardMagicValue)
	afx_msg void OnGenrandom();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()

};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_CONFIGURATIONWIZARDMAGICVALUE_H__4FEC3E79_7343_4079_9131_C356D1AB07B2__INCLUDED_)
