// ConfigurationWizardNetworkConfig.cpp : implementation file
//

#include "stdafx.h"
#include "configuration wizard.h"
#include "ConfigurationWizardNetworkConfig.h"
#include "DriverConfig.h"
#include <vector>
#include <algorithm>
#include <sstream>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

using namespace std;

/////////////////////////////////////////////////////////////////////////////
// CConfigurationWizardNetworkConfig property page

IMPLEMENT_DYNCREATE(CConfigurationWizardNetworkConfig, CPropertyPageEx)

CConfigurationWizardNetworkConfig::CConfigurationWizardNetworkConfig() : CPropertyPageEx(CConfigurationWizardNetworkConfig::IDD)
{
	//{{AFX_DATA_INIT(CConfigurationWizardNetworkConfig)
		// NOTE: the ClassWizard will add member initialization here
	//}}AFX_DATA_INIT
	m_strHeaderTitle = "Network Configuration";
	m_strHeaderSubTitle = "Sebek logs all data it collects to a central server. Please specify the network interface sebek will use to send the collected data.";
	m_psp.dwFlags |= PSP_USEHEADERSUBTITLE | PSP_USEHEADERTITLE;
}

CConfigurationWizardNetworkConfig::~CConfigurationWizardNetworkConfig()
{
}

void CConfigurationWizardNetworkConfig::DoDataExchange(CDataExchange* pDX)
{
	CPropertyPage::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CConfigurationWizardNetworkConfig)
	DDX_Control(pDX, IDC_INTERFACES, m_cbInterfaces);
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(CConfigurationWizardNetworkConfig, CPropertyPage)
	//{{AFX_MSG_MAP(CConfigurationWizardNetworkConfig)
		// NOTE: the ClassWizard will add message map macros here
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CConfigurationWizardNetworkConfig message handlers

BOOL CConfigurationWizardNetworkConfig::OnSetActive() 
{
	CPropertySheet *pParentSheet = (CPropertySheet *)GetParent();
	pParentSheet->SetWizardButtons(PSWIZB_NEXT | PSWIZB_BACK);
	
	m_cbInterfaces.ResetContent();
	DWORD iIndex = m_cbInterfaces.AddString("Select an interface");
	m_cbInterfaces.SetItemData(iIndex, NULL);
	m_cbInterfaces.SetCurSel(iIndex);

	// Get a list of all network devices on this machine. We *MUST* make sure
	// the indexes are static because the driver refers to NICs via index *NOT* name.
	HKEY hKey;
	string strKeyName("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards");
	if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, strKeyName.c_str(), 0, KEY_QUERY_VALUE | KEY_READ, &hKey) != ERROR_SUCCESS) {
		MessageBox("Unable to open registry key.", "Unable to open registry!", MB_OK | MB_ICONEXCLAMATION);
		return FALSE;
	}

	vector<long> vecNICs;
	char strSubKeyName[MAX_PATH];
	FILETIME ftLastWriteTime; // Used to because function cannot take a NULL for LastWriteTime argument
	DWORD dwBufLen = MAX_PATH;
	char *strValueData = NULL;
	DWORD retCode, i;

	for (i = 0, retCode = ERROR_SUCCESS; retCode != ERROR_NO_MORE_ITEMS; i++) { 
		dwBufLen = MAX_PATH;
		retCode = RegEnumKeyEx(hKey, i, strSubKeyName, &dwBufLen, NULL, NULL, NULL, &ftLastWriteTime);
		if(retCode == ERROR_SUCCESS) {
			vecNICs.push_back(atoi(strSubKeyName));
		}
	}

	std::sort(vecNICs.begin(), vecNICs.end());
	
	if(RegCloseKey(hKey) != ERROR_SUCCESS)
		return FALSE;

	for(i = 0; i <vecNICs.size(); i++) {
		stringstream strInterfaceName, strKey;
		strInterfaceName << vecNICs[i];
		strKey << strKeyName << "\\" << vecNICs[i];
		
		if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, strKey.str().c_str(), 0, KEY_QUERY_VALUE | KEY_READ, &hKey) != ERROR_SUCCESS) {
			MessageBox("Unable to open registry key.", "Unable to open registry!", MB_OK | MB_ICONEXCLAMATION);
			return FALSE;
		}

		dwBufLen = 0;
		// Query the value.
		if(RegQueryValueEx(hKey, "Description", NULL, NULL, NULL, &dwBufLen) == ERROR_SUCCESS) {
			strValueData = new char[dwBufLen + 1];
			memset(strValueData, 0, dwBufLen + 1);
			if(RegQueryValueEx(hKey, "Description", NULL, NULL, (LPBYTE)strValueData, &dwBufLen) != ERROR_SUCCESS) {
				delete [] strValueData;
				goto end;
			}
		} else {
			goto end;
		}

		strInterfaceName << " - " << strValueData;
		delete [] strValueData;

		dwBufLen = 0;
		// Query the value.
		if(RegQueryValueEx(hKey, "ServiceName", NULL, NULL, NULL, &dwBufLen) == ERROR_SUCCESS) {
			strValueData = new char[dwBufLen + 1];
			memset(strValueData, 0, dwBufLen + 1);
			if(RegQueryValueEx(hKey, "ServiceName", NULL, NULL, (LPBYTE)strValueData, &dwBufLen) != ERROR_SUCCESS) {
				delete [] strValueData;
				goto end;
			}
		} else {
			goto end;
		}

		// Add to the Combo Box
		iIndex = m_cbInterfaces.AddString(strInterfaceName.str().c_str());
		m_cbInterfaces.SetItemData(iIndex, (unsigned long)strValueData);
	}

end:
	if(RegCloseKey(hKey) != ERROR_SUCCESS)
		return FALSE;

	CDriverConfig &objConfig = CSingleton<CDriverConfig>::Instance();
	if(objConfig.GetDeviceName() != "") {
		for(i = 0; i <m_cbInterfaces.GetCount(); i++) {
			strValueData = (char *)m_cbInterfaces.GetItemData(i);
			if(strValueData && strValueData == objConfig.GetDeviceName()) {
				m_cbInterfaces.SetCurSel(i);
				break;
			}
		}
	}
	return CPropertyPage::OnSetActive();
}

LRESULT CConfigurationWizardNetworkConfig::OnWizardNext() 
{
	DWORD iIndex = m_cbInterfaces.GetCurSel();
	if(!m_cbInterfaces.GetItemData(iIndex)) {
		MessageBox("No network interface selected. Please select an interface.", "No Network Interface Selected!", MB_OK | MB_ICONEXCLAMATION);
		return -1;
	}
	
	CDriverConfig &objConfig = CSingleton<CDriverConfig>::Instance();
	objConfig.SetDeviceName((char *)m_cbInterfaces.GetItemData(iIndex));
	
	return CPropertyPage::OnWizardNext();
}

BOOL CConfigurationWizardNetworkConfig::OnKillActive() 
{
	char *strValueData = NULL;
	unsigned int i;
	
	for(i = 0; i <m_cbInterfaces.GetCount(); i++) {
		strValueData = (char *)m_cbInterfaces.GetItemData(i);
		if(strValueData) {
			delete [] strValueData;
		}
	}
	
	return CPropertyPage::OnKillActive();
}
