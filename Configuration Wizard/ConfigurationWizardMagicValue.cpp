// ConfigurationWizardMagicValue.cpp : implementation file
//

#include "stdafx.h"
#include "configuration wizard.h"
#include "ConfigurationWizardMagicValue.h"
#include "MersenneTwister.h"
#include <sstream>
#include "DriverConfig.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

using namespace std;

/////////////////////////////////////////////////////////////////////////////
// CConfigurationWizardMagicValue property page

IMPLEMENT_DYNCREATE(CConfigurationWizardMagicValue, CPropertyPageEx)

CConfigurationWizardMagicValue::CConfigurationWizardMagicValue() : CPropertyPageEx(CConfigurationWizardMagicValue::IDD)
{
	//{{AFX_DATA_INIT(CConfigurationWizardMagicValue)
	m_uiMagicValue = 0;
	//}}AFX_DATA_INIT
	m_strHeaderTitle = "Magic Value";
	m_strHeaderSubTitle = "Sebek will hide packets with the proper magic value. Specify a magic value to use.";
	m_psp.dwFlags |= PSP_USEHEADERSUBTITLE | PSP_USEHEADERTITLE;
}

CConfigurationWizardMagicValue::~CConfigurationWizardMagicValue()
{
}

void CConfigurationWizardMagicValue::DoDataExchange(CDataExchange* pDX)
{
	CPropertyPage::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CConfigurationWizardMagicValue)
	DDX_Control(pDX, IDC_MAGICVALUE, m_edtMagicValue);
	DDX_Text(pDX, IDC_MAGICVALUE, m_uiMagicValue);
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(CConfigurationWizardMagicValue, CPropertyPageEx)
	//{{AFX_MSG_MAP(CConfigurationWizardMagicValue)
	ON_BN_CLICKED(IDC_GENRANDOM, OnGenrandom)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CConfigurationWizardMagicValue message handlers

void CConfigurationWizardMagicValue::OnGenrandom() 
{
	MTRand Random;
	unsigned long ulNumber = 0;

	ulNumber = Random.randInt();
	stringstream ss;
	ss << ulNumber;

	m_edtMagicValue.SetWindowText(ss.str().c_str());
}

BOOL CConfigurationWizardMagicValue::OnSetActive() 
{
	CPropertySheet *pParentSheet = (CPropertySheet *)GetParent();
	pParentSheet->SetWizardButtons(PSWIZB_NEXT | PSWIZB_BACK);
	
	CDriverConfig &objConfig = CSingleton<CDriverConfig>::Instance();
	
	m_edtMagicValue.SetWindowText(objConfig.GetMagicValueAsString().c_str());	
	return CPropertyPageEx::OnSetActive();
}

LRESULT CConfigurationWizardMagicValue::OnWizardNext() 
{
	UpdateData();

	if(!m_uiMagicValue) {
		MessageBox("Invalid Magic Value was specified. Please specify a Magic Value greater then 0!", "Invalid Magic Value Specified!", MB_OK | MB_ICONEXCLAMATION);
		return -1;
	}

	CDriverConfig &objConfig = CSingleton<CDriverConfig>::Instance();
	objConfig.SetMagicValue(m_uiMagicValue);

	
	return CPropertyPageEx::OnWizardNext();
}
