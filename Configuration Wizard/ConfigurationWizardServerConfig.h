#if !defined(AFX_CONFIGURATIONWIZARDSERVERCONFIG_H__0D20A11B_8E2A_44E3_9DC7_DAB461A86C6A__INCLUDED_)
#define AFX_CONFIGURATIONWIZARDSERVERCONFIG_H__0D20A11B_8E2A_44E3_9DC7_DAB461A86C6A__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
// ConfigurationWizardServerConfig.h : header file
//

/////////////////////////////////////////////////////////////////////////////
// CConfigurationWizardServerConfig dialog

class CConfigurationWizardServerConfig : public CPropertyPageEx
{
	DECLARE_DYNCREATE(CConfigurationWizardServerConfig)

// Construction
public:
	CConfigurationWizardServerConfig();
	~CConfigurationWizardServerConfig();

// Dialog Data
	//{{AFX_DATA(CConfigurationWizardServerConfig)
	enum { IDD = IDD_CONFIGWIZ_SERVERCONFIG };
	CEdit	m_edtDestPort;
	CIPAddressCtrl	m_DestIP;
	CEdit	m_edtMAC5;
	CEdit	m_edtMAC4;
	CEdit	m_edtMAC3;
	CEdit	m_edtMAC2;
	CEdit	m_edtMAC1;
	CEdit	m_edtMAC0;
	CString	m_strMAC0;
	CString	m_strMAC1;
	CString	m_strMAC2;
	CString	m_strMAC3;
	CString	m_strMAC4;
	CString	m_strMAC5;
	UINT	m_uiDestPort;
	//}}AFX_DATA


// Overrides
	// ClassWizard generate virtual function overrides
	//{{AFX_VIRTUAL(CConfigurationWizardServerConfig)
	public:
	virtual BOOL OnSetActive();
	virtual LRESULT OnWizardNext();
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	// Generated message map functions
	//{{AFX_MSG(CConfigurationWizardServerConfig)
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()

};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_CONFIGURATIONWIZARDSERVERCONFIG_H__0D20A11B_8E2A_44E3_9DC7_DAB461A86C6A__INCLUDED_)
