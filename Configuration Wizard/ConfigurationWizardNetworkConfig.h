#if !defined(AFX_CONFIGURATIONWIZARDNETWORKCONFIG_H__3AD5A9C3_5572_4C95_BB0E_3B1D13A4D90D__INCLUDED_)
#define AFX_CONFIGURATIONWIZARDNETWORKCONFIG_H__3AD5A9C3_5572_4C95_BB0E_3B1D13A4D90D__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
// ConfigurationWizardNetworkConfig.h : header file
//

/////////////////////////////////////////////////////////////////////////////
// CConfigurationWizardNetworkConfig dialog

class CConfigurationWizardNetworkConfig : public CPropertyPageEx
{
	DECLARE_DYNCREATE(CConfigurationWizardNetworkConfig)

// Construction
public:
	CConfigurationWizardNetworkConfig();
	~CConfigurationWizardNetworkConfig();

// Dialog Data
	//{{AFX_DATA(CConfigurationWizardNetworkConfig)
	enum { IDD = IDD_CONFIGWIZ_NETWORKCONFIG };
	CComboBox	m_cbInterfaces;
	//}}AFX_DATA


// Overrides
	// ClassWizard generate virtual function overrides
	//{{AFX_VIRTUAL(CConfigurationWizardNetworkConfig)
	public:
	virtual BOOL OnSetActive();
	virtual LRESULT OnWizardNext();
	virtual BOOL OnKillActive();
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	// Generated message map functions
	//{{AFX_MSG(CConfigurationWizardNetworkConfig)
		// NOTE: the ClassWizard will add member functions here
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()

};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_CONFIGURATIONWIZARDNETWORKCONFIG_H__3AD5A9C3_5572_4C95_BB0E_3B1D13A4D90D__INCLUDED_)
