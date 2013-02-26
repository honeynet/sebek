// DriverConfig.cpp: implementation of the CDriverConfig class.
//
//////////////////////////////////////////////////////////////////////

#include "StdAfx.h"
#include "DriverConfig.h"
#include <winsock2.h>
#include <sstream>
#include "Imagehlp.h"
#include "Iphlpapi.h"
#include <vector>
#include "MersenneTwister.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

using namespace std;

// List of Driver Symbols we will modify
#define DEVICENAME_SYMBOL						"g_DeviceName"
#define CONFIGPROCNAME_SYMBOL				"g_ConfigProcName"
#define MAGIC_SYMBOL								"g_uiMagic"
#define DESTPORT_SYMBOL							"g_usDestPort"
#define DESTMAC_SYMBOL							"g_DestMAC"
#define DESTIP_SYMBOL								"g_uiDestIP"

#define MakePtr( cast, ptr, addValue ) (cast)( (DWORD)(ptr) + (addValue) )


// List of potential Auto Detection Target IPs. This may or may not help with detection of sebek.
const std::string CDriverConfig::strAutoDetectionTargetIPs[] = 
{
	"192.5.41.40",
	"192.5.41.209",
	"192.43.244.18",
	"128.9.176.30",
	"164.67.62.194"
};

#define NUMBER_OF_AUTODETECTION_TARGET_IPS sizeof(strAutoDetectionTargetIPs)/sizeof(strAutoDetectionTargetIPs[0])

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CDriverConfig::CDriverConfig() : m_usDestinationPort(0), m_uiMagicValue(0)
{
	ClearErrorString();
}

CDriverConfig::~CDriverConfig()
{

}

const std::string CDriverConfig::GetFileLocation()
{
	return m_strFileLocation;
}

void CDriverConfig::SetFileLocation(const char *strFileLocation)
{
	m_strFileLocation = strFileLocation;
}

const std::string CDriverConfig::GetDestinationMAC()
{
	return m_strDestinationMAC;
}

void CDriverConfig::SetDestinationMAC(std::string &strDestinationMAC)
{
	m_strDestinationMAC = strDestinationMAC;
}

void CDriverConfig::SetDestinationMAC(const char *strDestinationMAC)
{
	m_strDestinationMAC = strDestinationMAC;
}

const std::string CDriverConfig::GetDestinationIP()
{
	return m_strDestinationIP;
}

void CDriverConfig::SetDestinationIP(std::string &strDestinationIP)
{
	m_strDestinationIP = strDestinationIP;
}

void CDriverConfig::SetDestinationIP(const char *strDestinationIP)
{
	m_strDestinationIP = strDestinationIP;
}

const unsigned short CDriverConfig::GetDestinationPort()
{
	return m_usDestinationPort;
}

const std::string CDriverConfig::GetDestinationPortAsString()
{
	stringstream ss;
	ss << m_usDestinationPort;
	return ss.str();
}

void CDriverConfig::SetDestinationPort(const unsigned short usDestinationPort)
{
	m_usDestinationPort = usDestinationPort;
}

const unsigned int CDriverConfig::GetMagicValue()
{
	return m_uiMagicValue;
}

const std::string CDriverConfig::GetMagicValueAsString()
{
	stringstream ss;
	ss << m_uiMagicValue;
	return ss.str();
}

void CDriverConfig::SetMagicValue(const unsigned int uiMagicValue)
{
	m_uiMagicValue = uiMagicValue;
}

const std::string CDriverConfig::GetDeviceName()
{
	return m_strDeviceName;
}

void CDriverConfig::SetDeviceName(std::string &strDeviceName)
{
	m_strDeviceName = strDeviceName;
}

void CDriverConfig::SetDeviceName(const char *strDeviceName)
{
	m_strDeviceName = strDeviceName;
}

const std::string CDriverConfig::GetConfigFileName()
{
	return m_strConfigFileName;
}

void CDriverConfig::SetConfigFileName(std::string &strConfigFileName)
{
	m_strConfigFileName = strConfigFileName;
}

void CDriverConfig::SetConfigFileName(const char *strConfigFileName)
{
	m_strConfigFileName = strConfigFileName;
}

bool CDriverConfig::SaveConfig()
{
	ClearErrorString();

	if(m_strFileLocation.size() == 0) {
		SetErrorString("No Driver file specified");
		return false;
	}

	HANDLE hFile;
	HANDLE hFileMapping;
	LPVOID lpFileBase;
	PIMAGE_DOS_HEADER dosHeader;
	DWORD ret = 0;

	hFile = CreateFile(m_strFileLocation.c_str(), GENERIC_READ | GENERIC_WRITE , FILE_SHARE_READ, NULL,
						OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
					
	if(hFile == INVALID_HANDLE_VALUE)
	{
		SetErrorString("Couldn't open file with CreateFile()");
		return false;
	}

	hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
	if(hFileMapping == 0)
	{
		CloseHandle(hFile);
		SetErrorString("Couldn't open file mapping with CreateFileMapping()");
		return false;
	}

	lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_WRITE, 0, 0, 0);
	if(!lpFileBase)
	{
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		SetErrorString("Couldn't map view of file with MapViewOfFile()");
		return false;
	}

	bool fRet = true;
	dosHeader = (PIMAGE_DOS_HEADER)lpFileBase;
	IMAGE_NT_HEADERS *pImageHeader = NULL;
	DWORD dwOldCheckSum, dwNewCheckSum;
	if(dosHeader->e_magic == IMAGE_DOS_SIGNATURE)
	{
		if(!StoreDestinationMACInDriver(dosHeader)) {
			fRet = false;
			goto end;
		}

		if(!StoreDestinationIPInDriver(dosHeader)) {
			fRet = false;
			goto end;
		}

		if(!StoreDestinationPortInDriver(dosHeader)) {
			fRet = false;
			goto end;
		}

		if(!StoreMagicValueInDriver(dosHeader)) {
			fRet = false;
			goto end;
		}

		if(!StoreDeviceNameInDriver(dosHeader)) {
			fRet = false;
			goto end;
		}

		if(!StoreConfigFileNameInDriver(dosHeader)) {
			fRet = false;
			goto end;
		}

		pImageHeader = CheckSumMappedFile(lpFileBase, GetFileSize(hFile, NULL), &dwOldCheckSum, &dwNewCheckSum);
		if(!pImageHeader) {
			SetErrorString("Unable to recompute checksum. Driver will NOT load properly now. Please rerun the Wizard.!");
			goto end;
		}

		pImageHeader->OptionalHeader.CheckSum = dwNewCheckSum;

		if(!FlushViewOfFile(lpFileBase, 0)) {
			SetErrorString("Unable to save configuration changes to disk!");
			goto end;
		}
	} else {
		SetErrorString("Unable to find DOS header in file");
		fRet = false;
		goto end;
	}
	
end:
	UnmapViewOfFile(lpFileBase);
	CloseHandle(hFileMapping);
	CloseHandle(hFile);
	return fRet;
}

bool CDriverConfig::LoadConfig()
{
	ClearErrorString();

	if(m_strFileLocation.size() == 0) {
		SetErrorString("No Driver file specified");
		return false;
	}

	HANDLE hFile;
	HANDLE hFileMapping;
	LPVOID lpFileBase;
	PIMAGE_DOS_HEADER dosHeader;
	DWORD ret = 0;

	hFile = CreateFile(m_strFileLocation.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
						OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
					
	if(hFile == INVALID_HANDLE_VALUE)
	{
		SetErrorString("Couldn't open file with CreateFile()");
		return false;
	}

	hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if(hFileMapping == 0)
	{
		CloseHandle(hFile);
		SetErrorString("Couldn't open file mapping with CreateFileMapping()");
		return false;
	}

	lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if(!lpFileBase)
	{
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		SetErrorString("Couldn't map view of file with MapViewOfFile()");
		return false;
	}

	bool fRet = true;
	dosHeader = (PIMAGE_DOS_HEADER)lpFileBase;
	if(dosHeader->e_magic == IMAGE_DOS_SIGNATURE)
	{
		if(!GetDestinationMACFromDriver(dosHeader)) {
			fRet = false;
			goto end;
		}

		if(!GetDestinationIPFromDriver(dosHeader)) {
			fRet = false;
			goto end;
		}

		if(!GetDestinationPortFromDriver(dosHeader)) {
			fRet = false;
			goto end;
		}

		if(!GetMagicValueFromDriver(dosHeader)) {
			fRet = false;
			goto end;
		}

		if(!GetDeviceNameFromDriver(dosHeader)) {
			fRet = false;
			goto end;
		}

		if(!GetConfigFileNameFromDriver(dosHeader)) {
			fRet = false;
			goto end;
		}

	} else {
		SetErrorString("Unable to find DOS header in file");
		fRet = false;
		goto end;
	}
	
end:
	UnmapViewOfFile(lpFileBase);
	CloseHandle(hFileMapping);
	CloseHandle(hFile);
	return fRet;
}

PIMAGE_SECTION_HEADER CDriverConfig::GetSectionHeader(PSTR name, PIMAGE_NT_HEADERS pNTHeader)
{
	PIMAGE_SECTION_HEADER section;
	unsigned i;
	
	section = (PIMAGE_SECTION_HEADER)(pNTHeader+1);
	
	for ( i=0; i < pNTHeader->FileHeader.NumberOfSections; i++, section++ )
	{
		if ( strnicmp((const char *)section->Name, name, IMAGE_SIZEOF_SHORT_NAME) == 0 )
			return section;
	}
	
	return 0;
}

DWORD CDriverConfig::FindExport(DWORD base, PIMAGE_NT_HEADERS pNTHeader, const char *strExportName)
{
	PIMAGE_EXPORT_DIRECTORY exportDir;
	PIMAGE_SECTION_HEADER header, dheader;
	INT delta; 
	DWORD i;
	PDWORD functions;
	PSTR *name;
	
	header = GetSectionHeader(".edata", pNTHeader);
	if(!header) {
		SetErrorString("Unable to retrieve .edata section header");
		return 0;
	}
	exportDir = MakePtr(PIMAGE_EXPORT_DIRECTORY, base, header->PointerToRawData);

	dheader = GetSectionHeader(".data", pNTHeader);
	if(!dheader) {
		SetErrorString("Unable to retrieve .data section header");
		return 0;
	}

	delta = (INT)(header->VirtualAddress - header->PointerToRawData);
	
	functions = (PDWORD)((DWORD)exportDir->AddressOfFunctions - delta + base);
	name = (PSTR *)((DWORD)exportDir->AddressOfNames - delta + base);

	size_t len = strlen(strExportName);
	for ( i=0; i < exportDir->NumberOfNames; i++, name++, functions++ )
	{
		if(_strnicmp((*name - delta + base), strExportName, len) == 0)
			return *functions - (dheader->VirtualAddress - dheader->PointerToRawData);
	}

	string strError = "Unable to find '";
	strError += strExportName;
	strError += "' in configuration!";
	SetErrorString(strError);
	return 0;
}

DWORD CDriverConfig::GetExportValue( PIMAGE_DOS_HEADER dosHeader, const char *strExportName)
{
	PIMAGE_NT_HEADERS pNTHeader;
	DWORD base = (DWORD)dosHeader;
	
	pNTHeader = MakePtr( PIMAGE_NT_HEADERS, dosHeader,
								dosHeader->e_lfanew );

	// First, verify that the e_lfanew field gave us a reasonable
	// pointer, then verify the PE signature.
	if ( IsBadReadPtr(pNTHeader, sizeof(IMAGE_NT_HEADERS)) ||
	     pNTHeader->Signature != IMAGE_NT_SIGNATURE )
	{
		SetErrorString("Unhandled file type, or invalid PE Image.");
		return 0;
	}
	
	return FindExport(base, pNTHeader, strExportName);
}

const std::string CDriverConfig::GetErrorString()
{
	return m_strErrorString;
}

void CDriverConfig::SetErrorString(std::string strErrorString)
{
	m_strErrorString = strErrorString;
}

void CDriverConfig::ClearErrorString()
{
	m_strErrorString = "No Error";
}

bool CDriverConfig::GetDestinationMACFromDriver(const PIMAGE_DOS_HEADER pDosHeader)
{
	void *lpFileBase = (VOID *)pDosHeader;
	DWORD dwAddress = GetExportValue(pDosHeader, DESTMAC_SYMBOL);
	
	if(!dwAddress)
		return false;

	string strMAC;
	unsigned char *pData = (unsigned char *)lpFileBase + dwAddress;
	if(IsBadReadPtr(pData, DEST_MAC_SIZE)) {
		SetErrorString("Invalid Read Pointer!");
		return false;
	}

	char MAC[3]; // Only need enough room for 2 characters and a null
	memset(MAC, 0, sizeof(MAC));

	for(unsigned int i = 0; i < DEST_MAC_SIZE; i++) {
		_snprintf(MAC, sizeof(MAC), "%02X", pData[i]);
		strMAC += MAC;
	}

	SetDestinationMAC(strMAC);
	return true;
}

bool CDriverConfig::GetDestinationIPFromDriver(const PIMAGE_DOS_HEADER pDosHeader)
{
	struct in_addr sin;
	sin.S_un.S_addr = 0;
	if(!GetLongFromDriver(pDosHeader, DESTIP_SYMBOL, &sin.S_un.S_addr))
		return false;
	
	SetDestinationIP(inet_ntoa(sin));
	return true;
}

bool CDriverConfig::GetMagicValueFromDriver(const PIMAGE_DOS_HEADER pDosHeader)
{
	unsigned long ulValue;
	if(!GetLongFromDriver(pDosHeader, MAGIC_SYMBOL, (unsigned long *)&ulValue))
		return false;
	
	SetMagicValue(ntohl(ulValue));
	return true;
}

bool CDriverConfig::GetDeviceNameFromDriver(const PIMAGE_DOS_HEADER pDosHeader)
{
	char *strValue = new char[DEVICE_SIZE + 1];
	memset(strValue, 0, DEVICE_SIZE + 1);
	
	if(!GetStringFromDriver(pDosHeader, DEVICENAME_SYMBOL, DEVICE_SIZE, strValue)) {
		delete [] strValue;
		return false;
	}
	
	SetDeviceName(strValue);
	delete [] strValue;
	return true;
}

bool CDriverConfig::GetConfigFileNameFromDriver(const PIMAGE_DOS_HEADER pDosHeader)
{
	char *strValue = new char[CONFIG_PROC_SIZE + 1];
	memset(strValue, 0, CONFIG_PROC_SIZE + 1);
	
	if(!GetStringFromDriver(pDosHeader, CONFIGPROCNAME_SYMBOL, CONFIG_PROC_SIZE, strValue)){
		delete [] strValue;
		return false;
	}
	
	SetConfigFileName(strValue);
	delete [] strValue;
	return true;
}

bool CDriverConfig::GetLongFromDriver(const PIMAGE_DOS_HEADER pDosHeader, const char *strExportName, unsigned long *pulValue)
{
	void *lpFileBase = (VOID *)pDosHeader;
	DWORD dwAddress = GetExportValue(pDosHeader, strExportName);
	
	if(!dwAddress)
		return false;

	unsigned long *pData = (unsigned long *)((unsigned char *)lpFileBase + dwAddress);
	if(IsBadReadPtr(pData, sizeof(unsigned long))) {
		SetErrorString("Invalid Read Pointer!");
		return false;
	}
	*pulValue = *pData;

	return true;
}

bool CDriverConfig::GetStringFromDriver(const PIMAGE_DOS_HEADER pDosHeader, const char *strExportName, const unsigned int uiValueLen, char *strValue)
{
	void *lpFileBase = (VOID *)pDosHeader;
	DWORD dwAddress = GetExportValue(pDosHeader, strExportName);
	
	if(!dwAddress)
		return false;

	unsigned char *pData = (unsigned char *)lpFileBase + dwAddress;
	if(IsBadReadPtr(pData, uiValueLen)) {
		SetErrorString("Invalid Read Pointer!");
		return false;
	}
	memcpy(strValue, pData, uiValueLen);

	return true;
}

bool CDriverConfig::GetDestinationPortFromDriver(const PIMAGE_DOS_HEADER pDosHeader)
{
	void *lpFileBase = (VOID *)pDosHeader;
	DWORD dwAddress = GetExportValue(pDosHeader, DESTPORT_SYMBOL);
	
	if(!dwAddress)
		return false;

	unsigned short *pData = (unsigned short *)((unsigned char *)lpFileBase + dwAddress);
	if(IsBadReadPtr(pData, sizeof(unsigned short))) {
		SetErrorString("Invalid Read Pointer!");
		return false;
	}
	SetDestinationPort(ntohs(*pData));
	return true;
}

bool CDriverConfig::StoreDestinationMACInDriver(const PIMAGE_DOS_HEADER pDosHeader)
{
	void *lpFileBase = (VOID *)pDosHeader;
	DWORD dwAddress = GetExportValue(pDosHeader, DESTMAC_SYMBOL);
	
	if(!dwAddress)
		return false;

	unsigned char *pData = (unsigned char *)lpFileBase + dwAddress;
	if(IsBadWritePtr(pData, DEST_MAC_SIZE)) {
		SetErrorString("Invalid Write Pointer!");
		return false;
	}
	const string &strMAC = GetDestinationMAC();
	unsigned long ulOctet;
	for(unsigned int i = 0; i < DEST_MAC_SIZE * 2; i+=2) {
		ulOctet = strtol(strMAC.substr(i, 2).c_str(), (char **)NULL, 16);
		memcpy(pData + (i / 2), &ulOctet, 1);
	}
	
	return true;
}

bool CDriverConfig::StoreDestinationIPInDriver(const PIMAGE_DOS_HEADER pDosHeader)
{
	return StoreLongInDriver(pDosHeader, DESTIP_SYMBOL, inet_addr(GetDestinationIP().c_str()));
}

bool CDriverConfig::StoreDestinationPortInDriver(const PIMAGE_DOS_HEADER pDosHeader)
{
	void *lpFileBase = (VOID *)pDosHeader;
	DWORD dwAddress = GetExportValue(pDosHeader, DESTPORT_SYMBOL);
	
	if(!dwAddress)
		return false;

	unsigned short *pData = (unsigned short *)((unsigned char *)lpFileBase + dwAddress);
	if(IsBadWritePtr(pData, sizeof(unsigned short))) {
		SetErrorString("Invalid Write Pointer!");
		return false;
	}
	*pData = htons(GetDestinationPort());

	return true;
}

bool CDriverConfig::StoreLongInDriver(const PIMAGE_DOS_HEADER pDosHeader, const char *strExportName, const unsigned long ulValue)
{
	void *lpFileBase = (VOID *)pDosHeader;
	DWORD dwAddress = GetExportValue(pDosHeader, strExportName);
	
	if(!dwAddress)
		return false;

	unsigned long *pData = (unsigned long *)((unsigned char *)lpFileBase + dwAddress);
	if(IsBadWritePtr(pData, sizeof(unsigned long))) {
		SetErrorString("Invalid Write Pointer!");
		return false;
	}
	*pData = ulValue;

	return true;
}

// We will automatically pad with nulls if the string is not long enough for the length.
bool CDriverConfig::StoreStringInDriver(const PIMAGE_DOS_HEADER pDosHeader, const char *strExportName, const char *strValue, const unsigned int uiMaxLen)
{
	void *lpFileBase = (VOID *)pDosHeader;
	DWORD dwAddress = GetExportValue(pDosHeader, strExportName);
	
	if(!dwAddress)
		return false;

	unsigned char *pData = (unsigned char *)lpFileBase + dwAddress;
	unsigned int uiLen = strlen(strValue);
	if(IsBadWritePtr(pData, uiLen)) {
		SetErrorString("Invalid Write Pointer!");
		return false;
	}
	memcpy(pData, strValue, uiLen);
	if(uiLen != uiMaxLen)
		memset(pData + uiLen, 0, uiMaxLen - uiLen);

	return true;
}

bool CDriverConfig::StoreMagicValueInDriver(const PIMAGE_DOS_HEADER pDosHeader)
{
	return StoreLongInDriver(pDosHeader, MAGIC_SYMBOL, htonl(GetMagicValue()));
}

bool CDriverConfig::StoreDeviceNameInDriver(const PIMAGE_DOS_HEADER pDosHeader)
{
	return StoreStringInDriver(pDosHeader, DEVICENAME_SYMBOL, GetDeviceName().c_str(), DEVICE_SIZE);
}

bool CDriverConfig::StoreConfigFileNameInDriver(const PIMAGE_DOS_HEADER pDosHeader)
{
	return StoreStringInDriver(pDosHeader, CONFIGPROCNAME_SYMBOL, GetConfigFileName().c_str(), CONFIG_PROC_SIZE);
}

/*

	This is a multi step auto detection. It is a PITA.

	1) Find the "Best Interface" to get to a predefined IP (AUTO_DETECT_TARGET_IP)
	2) Loop through the IP Tables to find what IP belongs to that interface
	3) Loop though what the registry says are the available interfaces.
	4) For each registry interface, get that interface's IP and compare to our Best Interface IP.
	   If we get a match then grab that registry interface's service name.
	
	XXX: If we don't find a match we default to NO interface which will disable sending of data.
*/
std::string CDriverConfig::AutoDetectDeviceName()
{
	IPAddr dstip = inet_addr(GetAutoDetectTargetIP().c_str());
	DWORD dwIface, dwRetVal;

	if(GetBestInterface(dstip, &dwIface) != NO_ERROR)
		return "";

	PMIB_IPADDRTABLE pIPAddrTable;
	DWORD dwSize = 0;

	pIPAddrTable = new MIB_IPADDRTABLE;

	// Make an initial call to GetIpAddrTable to get the
	// necessary size into the dwSize variable
	if (GetIpAddrTable(pIPAddrTable, &dwSize, 0) == ERROR_INSUFFICIENT_BUFFER) {
		delete pIPAddrTable;
		pIPAddrTable = (MIB_IPADDRTABLE *) new char[dwSize];
	}

	// Make a second call to GetIpAddrTable to get the
	// actual data we want
	dwRetVal = GetIpAddrTable( pIPAddrTable, &dwSize, 0 );
	if(dwRetVal != NO_ERROR) {
		delete [] pIPAddrTable;
		return "";
	}

	struct in_addr a;
	a.s_addr = 0;

	for(unsigned int i = 0; i < pIPAddrTable->dwNumEntries; i++) {
		if(pIPAddrTable->table[i].dwIndex == dwIface) {
			a.s_addr = pIPAddrTable->table[i].dwAddr;
			break;
		}
	}

	
	delete [] pIPAddrTable;
	if(a.s_addr)
		return FindRegistryAdapter(inet_ntoa(a));
	else
		return "";
}

const std::string CDriverConfig::GetAutoDetectTargetIP()
{
	MTRand Random;
	unsigned long ulNumber = 0;

	ulNumber = Random.randInt(NUMBER_OF_AUTODETECTION_TARGET_IPS);
	return strAutoDetectionTargetIPs[ulNumber];
}

/*

	1) Loop though what the registry says are the available interfaces.
	2) For each registry interface, get that interface's IP and compare to our strIP.
	   
	If we get a match then grab that registry interface's service name and return it
	
	XXX: If we don't find a match we default to NO interface which will disable sending of data.
*/
std::string CDriverConfig::FindRegistryAdapter(const char *strIP)
{
// Get a list of all network devices on this machine. We *MUST* make sure
	// the indexes are static because the driver refers to NICs via index *NOT* name.
	HKEY hKey;
	string strServiceName;

	string strKeyName("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards");
	if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, strKeyName.c_str(), 0, KEY_QUERY_VALUE | KEY_READ, &hKey) != ERROR_SUCCESS) {
		return "";
	}

	vector<string> vecNICs;
	char strSubKeyName[MAX_PATH];
	FILETIME ftLastWriteTime; // Used to because function cannot take a NULL for LastWriteTime argument
	DWORD dwBufLen = MAX_PATH;
	char *strValueData = NULL;
	DWORD retCode, i;

	for (i = 0, retCode = ERROR_SUCCESS; retCode != ERROR_NO_MORE_ITEMS; i++) { 
		dwBufLen = MAX_PATH;
		retCode = RegEnumKeyEx(hKey, i, strSubKeyName, &dwBufLen, NULL, NULL, NULL, &ftLastWriteTime);
		if(retCode == ERROR_SUCCESS) {
			vecNICs.push_back(strSubKeyName);
		}
	}

	if(RegCloseKey(hKey) != ERROR_SUCCESS)
		return "";

	for(i = 0; i <vecNICs.size(); i++) {
		string strKey;
		strKey = strKeyName + "\\" + vecNICs[i];
		
		if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, strKey.c_str(), 0, KEY_QUERY_VALUE | KEY_READ, &hKey) != ERROR_SUCCESS) {
			return "";
		}

		dwBufLen = 0;
		// Query the value.
		if(RegQueryValueEx(hKey, "ServiceName", NULL, NULL, NULL, &dwBufLen) == ERROR_SUCCESS) {
			strValueData = new char[dwBufLen + 1];
			memset(strValueData, 0, dwBufLen + 1);
			if(RegQueryValueEx(hKey, "ServiceName", NULL, NULL, (LPBYTE)strValueData, &dwBufLen) != ERROR_SUCCESS) {
				delete [] strValueData;
				goto end;
			}

			strServiceName = strValueData;
			
			if(RegCloseKey(hKey) != ERROR_SUCCESS)
				return "";

			// Get the IP For this Network Interface Card.
			strKey = "SYSTEM\\CurrentControlSet\\Services\\";
			strKey += strValueData;
			strKey += "\\Parameters\\Tcpip";
			
			delete [] strValueData;

			if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, strKey.c_str(), 0, KEY_QUERY_VALUE | KEY_READ, &hKey) != ERROR_SUCCESS) {
				return "";
			}

			dwBufLen = sizeof(BOOL);
			BOOL bIsDHCP = FALSE;

			// Query the value.
			RegQueryValueEx(hKey, "EnableDHCP", NULL, NULL, (LPBYTE)&bIsDHCP, &dwBufLen);
				
			dwBufLen = 0;
			if(RegQueryValueEx(hKey, bIsDHCP ? "DhcpIpAddress" : "IPAddress", NULL, NULL, NULL, &dwBufLen) == ERROR_SUCCESS) {
				strValueData = new char[dwBufLen + 1];
				memset(strValueData, 0, dwBufLen + 1);
				if(RegQueryValueEx(hKey, bIsDHCP ? "DhcpIpAddress" : "IPAddress", NULL, NULL, (LPBYTE)strValueData, &dwBufLen) != ERROR_SUCCESS) {
					delete [] strValueData;
					goto end;
				}
			}

			if(inet_addr(strValueData) == inet_addr(strIP)) {
				delete [] strValueData;
				return strServiceName;
			}
		} else {
			goto end;
		}
	}

end:
	if(RegCloseKey(hKey) != ERROR_SUCCESS)
		return "";

	delete [] strValueData;
	return "";
}
