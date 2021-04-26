// Win32Project1.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "Win32Project1.h"
#include <wincrypt.h>
#include <wintrust.h>
#include <stdio.h>
#include <string>
#include <shellapi.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <vector>
#include <shlobj.h>
#include <shellapi.h>
#include <new> 
#include <mutex>
#include <io.h>  
#include <fcntl.h>
using namespace std;
#define _WIN32_DCOM
#include <comdef.h>
#include <Wbemidl.h>



#pragma comment(lib, "crypt32.lib") //certificate
#pragma comment(lib, "version.lib") //version information 
#pragma comment(lib, "shell32.lib") //shell notifications
#pragma comment(lib, "wbemuuid.lib")//WMI 
#pragma warning( disable : 4302 )


#define MAX_LOADSTRING 100

#define WM_FILESYSTEM_CHANGED_MSG (WM_USER+100)
#define CONSOLE_TITLE		_T("Software Monitor Log")
#define RUNNING				"running"  
#define SUSPENDED			"suspended" 
#define VER_QUERY_PATH		_T("\\VarFileInfo\\Translation")
#define VER_QUERY_STR_PATH  _T("\\StringFileInfo\\%04X%04X\\%s")
#define INFO				_T("Info")
#define UNKNOWN_APP_TYPE    "Unknown application type"
#define WIN_APP				"Windows application"	
#define WIN_CONSOLE		    "Win32 Console Application"
#define MS_DOS				"MS-DOS .exe, .bat or .com"
#define NORMAL				"Normal"
#define ABOVE_NORMAL		"Above Normal"
#define BELOW_NORMAL		"Below Normal"
#define HIGH				"High"
#define REALTIME			"Real-time"
#define IDLE				"Idle"
#define READ_BINARY			"rb"
#define RUN_APP				_T("Do you want to run this application?")
#define CRLN				_T("\r\n")
#define LINE_OFFSET			26
#define PROD_NAME_MSG       _T("product name is %S")
#define COMP_NAME_MSG       _T("company name is %S")
#define CERT_SUB_MSG		_T("certificate subject name is %s")
#define FILE_SIZE_MSG		_T("file size on disk is %d bytes")
#define PROC_STATE_MSG		_T("process state is : %S")
#define PROC_PRIORITY_MSG   _T("process priority is : %S")
#define PROC_START_MSG 	    _T("process start time is : %S")
#define PROC_PEAK_MSG 	    _T("process peak page usage is : %u")
#define EXE_NAME_MSG		_T("exe name is %S")
#define EXE_SIGNED_MSG		_T("exe is signed")
#define EXE_NOT_SIGNED_MSG  _T("exe is not signed")
#define BIN_RES_MSG			_T("exe contains a binary resource")
#define NO_BIN_RES_MSG		_T("exe does not contain a binary resource")
#define ATL_RES_MSG			_T("exe is an ATL exe")
#define NO_ATL_RES_MSG		_T("exe is not an ATL exe")
#define EXE_TYPE_MSG		_T("exe type is : %S")
#define RUN_PROC_MSG		_T("exe runs %d processes")
#define LISTEN_PORT_MSG		_T("exe uses ports %S")
#define NOT_LISTEN_PORT_MSG _T("exe does not listen to any port")
#define IE_BROWSE_MSG		_T("exe has a dialog with IE browser control")
#define NO_IE_BROWSE_MSG	_T("exe does not have a dialog with IE browser control")
#define RUN_ADMIN_MSG		_T("exe runs as admin")
#define NO_RUN_ADMIN_MSG	_T("exe does not run as admin")
#define REQUIRE_ADMIN_MSG   _T("exe requires admin permissions")
#define NO_REQUIRE_ADMIN_MSG _T("exe does not require admin permissions")
#define IMPORT_DLLS_MSG		_T("imported DLLS are : %s")
#define EXPORT_FUNC_MSG		_T("exported functions are : %s")
#define PROD_VER_MSG		_T("product version is : %S")
#define BACKSLASH			_T("\\")
#define PROC_ID_MSG			_T("process ID is %d")
#define BIN					_T("bin")
#define TYPELIB				_T("TYPELIB")
#define COMP_NAME			"CompanyName"
#define PROD_NAME			"ProductName"
#define TASK_KILL_CMD       "/C Taskkill /PID %d /F /T"
#define CMD_EXE				"cmd.exe"
#define OPEN				"open"
#define NETSTAT_CMD			"netstat -no|find \"%d\""
#define WMIC_WC				"wmic process get processid,parentprocessid,executablepath|find \"%s\" | find /v /c \"\"  "
#define WMIC_EXE_PATH		"wmic process get processid,parentprocessid,executablepath|find \"%d\" "
#define SYS_RESTORE_CREATE  "Wmic.exe  /Namespace:\\\\root\\default Path SystemRestore Call CreateRestorePoint \"%DATE%\", 100, 7"
#define RESTORE_CMD			"rstrui.exe"
#define PROCESS_CREATED_MSG _T("%s process was created\n")
#define PROCESS_DELETED_MSG _T("%s process was deleted\n")
#define CLASS_NAME_MSG      _T("window class name is %s")
#define FONT_NAME			_T("Arial")
#define PROCESS_CPU_USAGE   _T("process CPU uage is %f")

#define ENCODING (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)

//Certificate publisher information
typedef struct {
	wchar_t* programName;
	wchar_t* publisherLink;
	wchar_t* moreInfoLink;
} PUBLISHERINFO, *PPUBLISHERINFO;

//Shell message structure
typedef struct {
	DWORD dwItem1;
	DWORD dwItem2;
} SHMSGSTRUCT;



// Global Variables:
HINSTANCE hInst;								// current instance
TCHAR szTitle[MAX_LOADSTRING];					// The title bar text
TCHAR szWindowClass[MAX_LOADSTRING];			// the main window class name
BOOL  bSigned = FALSE;							//is exe signed
char  szExeFullPath[MAX_PATH * 4];				//full path
char  szExePath[MAX_PATH * 4];					//exe name
char  szFolderPath[MAX_PATH * 4];				//folder path 
HWND  ghWnd = NULL;								//window handle
HWND  hConsole = NULL;							//console handle
int   iNumOfProcesseses = NULL;					//number of processes
string portNumbers;								//ports numbers that EXE listens to 
BOOL  bHasMainBrowserControl = FALSE;			//contain browser IE control
DWORD pid = 0;									//process ID
BOOL  bAdmin = FALSE;							//runs as admin
BOOL  bRequireAdmin=FALSE;						//require admin manifest
wstring dllNames;								//imported DLL names
wstring exportedFunctions;						//exported function names
string strProductVersion;						//product version
string exeType;									//exe type
string processPriority;							//process priority
string startTime,exitTime,kernelTime,userTime;  //process start time
PROCESS_MEMORY_COUNTERS memCounter;				//memory counters
string  processStatus = RUNNING;				//process status
mutex   mutexMessages;							//mutex for synchronizing notifications
long    dwExeSize = 0;							//exe size
wstring signerName;								//signer name
string  companyName;							//company name
string  productName;							//product name
wstring clipboardText;							//clipboard text
wstring clipboardFileName;						//clipboard file name
BOOL    bLeftButtonDown = FALSE;				//left botton down
wstring wndClassName;							//window class name
double       processCPU=-1.0;					//process CPU usage


//Certificate information
BOOL				  GetProgramAndPublisherInfo(IN PCMSG_SIGNER_INFO pSignerInfo, OUT	PPUBLISHERINFO publisherInfo);
BOOL				  GetSigningTime(IN PCMSG_SIGNER_INFO pSignerInfo,OUT SYSTEMTIME *st);
BOOL				  GetCertificateInfo(PCCERT_CONTEXT pCertContext);
BOOL				  GetSignerInfo(PCMSG_SIGNER_INFO pSignerInfo,	PCMSG_SIGNER_INFO *pCounterSignerInfo);
//File system
void				  RegisterFileSystemChanges();
void				  HandleFileSystemChange(WPARAM wParam, LPARAM lParam);
void				  OpenContainingFolder();
//Drag and Drop files 
void				  HandleDroppedFiles(IDataObject *pdto);
//Window 
void				  Paint(HWND hWnd,HDC hdc);
void				  PositionWindow(HWND hwndWindow, HWND hwndParent);
void				  RepaintWindow();
ATOM				  RegisterWndClass(HINSTANCE hInstance);
BOOL				  InitApp(HINSTANCE hInstance, int nCmdShow);
void				  EnableMenuItems();
//Callbacks
LRESULT CALLBACK	  WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK	  About(HWND, UINT, WPARAM, LPARAM);
BOOL    CALLBACK	  EnumChildProc(HWND hwnd, LPARAM lParam);
//Process
void				  OpenProcessByPath(const char* exeFullPath);
void				  SuspendProcess(DWORD processId, BOOL bSuspend);
HWND				  FindProcessByWindow(DWORD pid);
void				  GetProcessPriority(HANDLE hProcess);
void				  GetProcessTimes(HANDLE hProcess);
void				  KillTask();
//EXE
void				  GetVersionInfo(wchar_t* szFilename);
string				  GetExeType(char* filePath);
void				  GetFormattedTime(IN FILETIME& time, OUT string& timeStr);
BOOL				  IsRunningAsAdmin(const char* pName);
void				  InspectEXE(HWND hwnd);
void				  InspectStaticEXE(const char* exePath);
void				  ReadExeImportTable(const char* name);
BOOL				  ReadImportAndExportTables(wstring strFileName);
void				  ReadImportTable(BYTE * file, DWORD vraOffset, DWORD codeOffset, int fileSize, PIMAGE_NT_HEADERS pNTHeader, PIMAGE_SECTION_HEADER pNTSection);
void				  ReadExportTableList(BYTE * file, DWORD vraOffset, DWORD codeOffset, int fileSize, PIMAGE_NT_HEADERS pNTHeader, PIMAGE_SECTION_HEADER pNTSection);
string				  GetPathFromPIDL(DWORD pidl);
//Strings
LPWSTR				  CopyWString(const wchar_t* str);
std::string			  GetClipboardString();
//Unexpected exception
void				  myunexpected(){}


/*
/* Function: GetPathFromPIDL
/* Get file path from PIDL
/* input:
/*			pidl -  pointer to ID list
/* returns: modified file path
*/
string GetPathFromPIDL(DWORD pidl)
{
	char sPath[MAX_PATH];
	string strTemp = "";
	if (SHGetPathFromIDListA((struct _ITEMIDLIST *)pidl, sPath))
		strTemp = sPath;

	return strTemp;
}


//Class for process events notifications
class ProcessEventSink : public IWbemObjectSink
{
public:
	ProcessEventSink() { m_cRef = 0; }
	~ProcessEventSink() {}

	virtual ULONG STDMETHODCALLTYPE AddRef(){ return InterlockedIncrement(&m_cRef); }
	virtual ULONG STDMETHODCALLTYPE Release(){
		LONG cRef = InterlockedDecrement(&m_cRef);
		if (cRef == 0)
			delete this;
		return cRef;
	}

	virtual HRESULT
		STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv){
			if (riid == IID_IUnknown || riid == IID_IWbemObjectSink)
			{
				*ppv = (IWbemObjectSink *) this;
				AddRef();
				return WBEM_S_NO_ERROR;
			}
			return E_NOINTERFACE;
		}

	virtual HRESULT STDMETHODCALLTYPE Indicate(
		LONG lObjectCount,
		IWbemClassObject __RPC_FAR *__RPC_FAR *apObjArray
		)
		{
			HRESULT hr = S_OK;
			variant_t var;
			for (int i = 0; i < lObjectCount; i++)
			{
				hr = apObjArray[i]->Get(_bstr_t(L"__Class"), 0, &var, 0, 0);
				if (SUCCEEDED(hr))
				{
					wstring classOrigin(var.bstrVal);		
					wstring processName;
					wchar_t buffer[MAX_PATH * 2];
					hr = apObjArray[i]->Get(_bstr_t(L"TargetInstance"), 0, &var, 0, 0);
					if (SUCCEEDED(hr))
					{
						IUnknown* str = var;
						hr = str->QueryInterface(IID_IWbemClassObject, reinterpret_cast< void** >(&apObjArray[i]));
						if (SUCCEEDED(hr))
						{
							_variant_t varName;
							hr = apObjArray[i]->Get(L"Name", 0, &varName, NULL, NULL);
							if (SUCCEEDED(hr))
							{
								processName = varName.bstrVal;
							}
							VariantClear(&varName);

						}
					}
					{
						if (0 == classOrigin.compare(L"__InstanceDeletionEvent"))
						{
							wprintf_s(PROCESS_DELETED_MSG, processName.c_str());
							if (!processName.empty())
							{
								wsprintf(buffer, PROCESS_CREATED_MSG, processName.c_str());
								OutputDebugString(buffer);
							}
						}
						else if (0 == classOrigin.compare(L"__InstanceCreationEvent"))
						{
							wprintf_s(PROCESS_CREATED_MSG, processName.c_str());
							if (!processName.empty())
							{
								wsprintf(buffer, PROCESS_CREATED_MSG, processName.c_str());
								OutputDebugString(buffer);
							}
						}
					}
				}
				VariantClear(&var);
			}
			RepaintWindow();
			return WBEM_S_NO_ERROR;
		}

	virtual HRESULT STDMETHODCALLTYPE SetStatus(
		/* [in] */ LONG lFlags,
		/* [in] */ HRESULT hResult,
		/* [in] */ BSTR strParam,
		/* [in] */ IWbemClassObject __RPC_FAR *pObjParam
		){
		return WBEM_S_NO_ERROR;
	}

	LONG m_cRef;

};


//contains resource information
class ResourceInfo
{
public:
	ResourceInfo(const wstring &name, const wstring& type) :m_name(name), m_type(type), m_isNumber(TRUE){};
	ResourceInfo() :m_type(L""), m_isNumber(TRUE){};

	wstring m_name;
	wstring	m_type;
	wstring m_displayName;
	BOOL    m_isNumber;
};

//Loads resource from EXE files
class CRessourceLoader
{
public:
	CRessourceLoader(wchar_t* path);
	virtual ~CRessourceLoader();

	BOOL		TraverseResources();
	static BOOL EnumNames(HANDLE hModule, wchar_t* lpType, wchar_t* lpName, long lParam);
	static BOOL EnumResourceNames(HANDLE hModule, wchar_t* lpType, long lParam);
	BOOL		LoadLibrary();

private:

	void Cleanup();

	wstring				  m_path;
	vector<ResourceInfo>  m_resInfos;
	HANDLE				  m_hExe;       
};


/*
/* Function: CRessourceLoader
/* Constructor which assigns EXE path
/* input: none
/* returns: none
*/
CRessourceLoader::CRessourceLoader(wchar_t* path)
{
	m_hExe = NULL;
	m_path = path;
}

/*
/* Function: ~CRessourceLoader
/* Destructor which cleans allocated resources
/* input: none
/* returns: none
*/
CRessourceLoader::~CRessourceLoader()
{
	Cleanup();
}


/*
/* Function: LoadLibrary
/* Loads module into current process address space
/* input: none

/* returns: TRUE for success, else FALSE
*/
BOOL CRessourceLoader::LoadLibrary()
{
	Cleanup();
	m_hExe = ::LoadLibrary(m_path.c_str());

	if (m_hExe == NULL)
		return FALSE;
	return TRUE;
}

/*
/* Function: Cleanup
/* release resources
/* input: none

/* returns: none
*/
void CRessourceLoader::Cleanup()
{
	if (m_hExe)
		::FreeLibrary((HMODULE)m_hExe);
	m_hExe = NULL;
}



/*
/* Function: EnumResourceNames
/* enumerate EXE resources
/* input: hModule - handle to module to search at
/*		  lpType  - resouce type
/*		  lParam  - application value to pass to callback	 
/* returns: TRUE for success, else FALSE
*/
BOOL CRessourceLoader::EnumResourceNames(HANDLE hModule, wchar_t* lpType, long lParam)
{
	::EnumResourceNames((HINSTANCE)hModule,
		lpType,
		(ENUMRESNAMEPROC)EnumNames,
		lParam);

	return TRUE;
}


/*
/* Function: EnumNames
/* enumerate EXE resources callback
/* input: hModule - handle to module to search at
/*		  lpType  - resouce type
/*		  lpName  - resource name	
/*		  lParam  - application value to pass to callback
/* returns: TRUE for success, else FALSE
*/
BOOL CRessourceLoader::EnumNames(HANDLE hModule, wchar_t* lpType, wchar_t* lpName, long lParam)
{
	vector<ResourceInfo> *infos = (vector<ResourceInfo> *)lParam;
	ResourceInfo info;

	wchar_t buffer[MAX_PATH];
	
	if (lpType == RT_MANIFEST)
	{
		HRSRC hResource = ::FindResource((HMODULE)hModule, lpName, lpType);
		if (hResource)
		{
			DWORD dwResource = ::SizeofResource((HMODULE)hModule, hResource);

			HGLOBAL hResData = LoadResource((HMODULE)hModule, hResource);
			if (hResData)
			{
				const BYTE *pResource = (const BYTE *)LockResource(hResData);
				if (pResource)
				{
					std::string assemblyIdentity;
					std::string input = (char*)pResource;

					const char* str = strstr(input.c_str(), "requireAdministrator");
					if (str)
						bRequireAdmin = TRUE;
					else
						bRequireAdmin = FALSE;
				}
				UnlockResource(hResData);
				FreeResource(hResData);
			}
		}
	}


	if ((ULONG)lpName & 0xFFFF0000)
	{
		info.m_name = lpName;
	}
	else
	{
		swprintf_s(buffer, L"%u", (USHORT)lpName);
		info.m_name = buffer;
	}
	if ((ULONG)lpType & 0xFFFF0000)
	{
		info.m_type = lpType;
		info.m_isNumber = false;
	}
	else
	{
		info.m_isNumber = true;
		swprintf_s(buffer, L"%d", (USHORT)info.m_isNumber);
		info.m_name = buffer;
	}

	if (infos)
		infos->insert(infos->begin(),info);

	return TRUE;
}

/*
/* Function: TraverseResources
/* traverse module resources
/* input: none
/* returns: TRUE for success, else FALSE
*/
BOOL CRessourceLoader::TraverseResources()
{
	if (m_hExe)
	{
		return EnumResourceTypes((HMODULE)m_hExe,
			(ENUMRESTYPEPROC)EnumResourceNames,
			(LONG)&m_resInfos);

	}
	return FALSE;
}


//class for implementing drop target (for drag and drop)
class CWndDropTarget : public IDropTarget
{
public:
	CWndDropTarget() : m_refCount(1) {}

	STDMETHODIMP QueryInterface(REFIID riid, void **ppv)
	{
		if (riid == IID_IUnknown || riid == IID_IDropTarget) {
			*ppv = (IUnknown*)(this);
			AddRef();
			return S_OK;
		}
		*ppv = NULL;
		return E_NOINTERFACE;
	}

	STDMETHODIMP_(ULONG) AddRef()
	{
		return InterlockedIncrement(&m_refCount);
	}

	STDMETHODIMP_(ULONG) Release()
	{
		LONG refCount = InterlockedDecrement(&m_refCount);
		if (refCount == 0) 
			delete this;

		return refCount;
	}


	STDMETHODIMP DragEnter(IDataObject *pdto,
		DWORD grfKeyState, POINTL ptl, DWORD *pdwEffect)
	{
		*pdwEffect &= DROPEFFECT_COPY;
		return S_OK;
	}

	STDMETHODIMP DragOver(DWORD grfKeyState,
		POINTL ptl, DWORD *pdwEffect)
	{
		*pdwEffect &= DROPEFFECT_COPY;
		return S_OK;
	}

	STDMETHODIMP DragLeave()
	{
		return S_OK;
	}

	STDMETHODIMP Drop(IDataObject *pdto, DWORD grfKeyState,
		POINTL ptl, DWORD *pdwEffect)
	{
		HandleDroppedFiles(pdto);
		*pdwEffect &= DROPEFFECT_COPY;
		return S_OK;
	}

private:
	LONG m_refCount;
};



/*
/* Function: HandleDroppedFiles
/* Handle files dropped into the window
/* input:    
/*			pdto - pointer to data object, containing dropped information
/* returns: void
*/
void HandleDroppedFiles(IDataObject *pdto)
{
	FORMATETC fmte = { CF_HDROP, NULL, DVASPECT_CONTENT,-1, TYMED_HGLOBAL };
	STGMEDIUM stgm;
	if (SUCCEEDED(pdto->GetData(&fmte, &stgm))) 
	{
		HDROP hdrop = reinterpret_cast<HDROP>(stgm.hGlobal);
		UINT cFiles = DragQueryFile(hdrop, 0xFFFFFFFF, NULL, 0);
		for (UINT i = 0; i < cFiles; i++) 
		{
			TCHAR szFile[MAX_PATH];
			UINT cch = DragQueryFile(hdrop, i, szFile, MAX_PATH);
			if (cch > 0 && cch < MAX_PATH) {
				wstring droppedFileName = szFile;
				//Handle dropped EXE files
				if (droppedFileName.find(L".exe"))
				{
					size_t converted = 0;
					wcstombs_s(&converted, szExeFullPath, droppedFileName.c_str(), MAX_PATH);
					InspectStaticEXE(szExeFullPath);
					RepaintWindow();
					if (MessageBox(0, RUN_APP, INFO, MB_OKCANCEL) == 1)
					{
						STARTUPINFO info = { sizeof(info) };
						PROCESS_INFORMATION processInfo;
						if (CreateProcess(droppedFileName.c_str(), L"", NULL, NULL, TRUE, 0, NULL, NULL, &info, &processInfo))
						{
							WaitForSingleObject(processInfo.hProcess, 1000);
							pid = processInfo.dwProcessId;
							HWND hWnd = FindProcessByWindow(pid);
							if (hWnd)
							{
								InspectEXE(hWnd);
							}
							CloseHandle(processInfo.hProcess);
							CloseHandle(processInfo.hThread);
						}
					}
				}
			}
		}
		ReleaseStgMedium(&stgm);
	}
}



/*
/* Function: GetCertificateInfo
/* Inspect certificate infromation
/* input:
/*			pCertContext - certificate context
/* returns: TRUE for success, else FALSE
*/
BOOL GetCertificateInfo(PCCERT_CONTEXT pCertContext)
{
	BOOL     retVal = FALSE;
	wchar_t* szName = NULL;
	DWORD    dwData;
	signerName = L"";

	try
	{
		dwData = pCertContext->pCertInfo->SerialNumber.cbData;

		// Get Issuer name size.
		if (!(dwData = CertGetNameString(pCertContext,
			CERT_NAME_SIMPLE_DISPLAY_TYPE,
			CERT_NAME_ISSUER_FLAG,
			NULL,
			NULL,
			0)))
		{
			return retVal;
		}

		// Allocate memory for Issuer name.
		szName = new wchar_t[dwData];
		if (!szName)
		{
			return retVal;
		}

		// Get Issuer name.
		if (!(CertGetNameString(pCertContext,
			CERT_NAME_SIMPLE_DISPLAY_TYPE,
			CERT_NAME_ISSUER_FLAG,
			NULL,
			szName,
			dwData)))
		{
			delete[]szName;
			return retVal;
		}

		// print Issuer name.
		delete[]szName;
		szName = NULL;

		// Get Subject name size.
		if (!(dwData = CertGetNameString(pCertContext,
			CERT_NAME_SIMPLE_DISPLAY_TYPE,
			0,
			NULL,
			NULL,
			0)))
		{
			return retVal;
		}

		// Allocate memory for subject name.
		szName = new wchar_t[dwData];
		if (!szName)
		{
			return retVal;
		}

		// Get subject name.
		if (!(CertGetNameString(pCertContext,
			CERT_NAME_SIMPLE_DISPLAY_TYPE,
			0,
			NULL,
			szName,
			dwData)))
		{
			return retVal;
		}

		signerName = szName;

		retVal = TRUE;
	}
	catch (...)
	{
	}
	if (szName != NULL)
		delete []szName;

	return retVal;
}

/*
/* Function: CopyWString
/* copy wide character string
/* input:
/*			inputString - input string
/* returns: copied string
*/
LPWSTR CopyWString(const wchar_t* str)
{
	LPWSTR outputString = NULL;
	outputString = new wchar_t[wcslen(str) + 1];
	if (outputString)
	{
		lstrcpyW(outputString, str);
	}
	return outputString;
}


/*
/* Function: GetProgramAndPublisherInfo
/* get program and publisher information
/* input:
/*			pSignerInfo - signer information
/*			Info		- publisher information
/* returns: TRUE for success, else FALSE
*/
BOOL GetProgramAndPublisherInfo(IN PCMSG_SIGNER_INFO pSignerInfo,OUT	PPUBLISHERINFO publisherInfo)
{
	BOOL			  returnRes = FALSE;
	PSPC_SP_OPUS_INFO pInfo     = NULL;
	DWORD			  dwData;

	try
	{
		for (DWORD n = 0; n < pSignerInfo->AuthAttrs.cAttr; n++)
		{
			if (lstrcmpA(SPC_SP_OPUS_INFO_OBJID,
				pSignerInfo->AuthAttrs.rgAttr[n].pszObjId) == 0)
			{
				returnRes = CryptDecodeObject(ENCODING,
					SPC_SP_OPUS_INFO_OBJID,
					pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
					pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData,
					0,
					NULL,
					&dwData);
				if (!returnRes)
				{
					break;
				}

				pInfo = new SPC_SP_OPUS_INFO;
				if (!pInfo)
				{
					break;
				}

				returnRes = CryptDecodeObject(ENCODING,
					SPC_SP_OPUS_INFO_OBJID,
					pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
					pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData,
					0,
					pInfo,
					&dwData);
				if (!returnRes)
				{
					break;
				}
				if (pInfo->pwszProgramName)
				{
					publisherInfo->programName = CopyWString(pInfo->pwszProgramName);
				}
				else
					publisherInfo->programName = NULL;

				if (pInfo->pPublisherInfo)
				{

					switch (pInfo->pPublisherInfo->dwLinkChoice)
					{
					case SPC_URL_LINK_CHOICE:
						publisherInfo->publisherLink = CopyWString(pInfo->pPublisherInfo->pwszUrl);
						break;

					case SPC_FILE_LINK_CHOICE:
						publisherInfo->publisherLink = CopyWString(pInfo->pPublisherInfo->pwszFile);
						break;

					default:
						publisherInfo->publisherLink = NULL;
						break;
					}
				}
				else
				{
					publisherInfo->publisherLink = NULL;
				}

				if (pInfo->pMoreInfo)
				{
					switch (pInfo->pMoreInfo->dwLinkChoice)
					{
					case SPC_URL_LINK_CHOICE:
						publisherInfo->moreInfoLink = CopyWString(pInfo->pMoreInfo->pwszUrl);
						break;

					case SPC_FILE_LINK_CHOICE:
						publisherInfo->moreInfoLink = CopyWString(pInfo->pMoreInfo->pwszFile);
						break;

					default:
						publisherInfo->moreInfoLink = NULL;
						break;
					}
				}
				else
				{
					publisherInfo->moreInfoLink = NULL;
				}
				break; 
			} 
		} 
	}
	catch (...)
	{
	}

	if (pInfo)
		delete pInfo;

	return returnRes;
}

/*
/* Function: GetSigningTime
/* get signing time
/* input:
/*			path - EXE path
/*			pSignerInfo - signer information
/*			systemTime  - signing time , if function succeeds
/* returns: TRUE if it succeeds , else FALSE
*/
BOOL GetSigningTime(IN PCMSG_SIGNER_INFO pSignerInfo,OUT SYSTEMTIME *st)
{
	BOOL     res = FALSE;
	FILETIME localFiletime, filetime;
	DWORD    structInfoSize;

	for (DWORD n = 0; n < pSignerInfo->AuthAttrs.cAttr; n++)
	{
		if (lstrcmpA(szOID_RSA_signingTime,
			pSignerInfo->AuthAttrs.rgAttr[n].pszObjId) == 0)
		{
			structInfoSize = sizeof(filetime);
			res = CryptDecodeObject(ENCODING,
				szOID_RSA_signingTime,
				pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
				pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData,
				0,
				(PVOID)&filetime,
				&structInfoSize);

			if (!res)
			{
				break;
			}
			FileTimeToLocalFileTime(&filetime, &localFiletime);
			FileTimeToSystemTime(&localFiletime, st);
			break; 
		} 
	} 
	return res;
}


/*
/* Function: GetSignerInfo
/* get counter signer info time
/* input:
/*			pSignerInfo - signer information
/*			pCounterSignerInfo - counter signer information
/* returns: TRUE if it succeeds , else FALSE
*/
BOOL GetSignerInfo(IN PCMSG_SIGNER_INFO pSignerInfo, OUT PCMSG_SIGNER_INFO *pCounterSignerInfo)
{
	PCCERT_CONTEXT pCertContext = NULL;
	BOOL fReturn = FALSE;
	BOOL fResult;
	DWORD dwSize;

	try
	{
		*pCounterSignerInfo = NULL;

		for (DWORD n = 0; n < pSignerInfo->UnauthAttrs.cAttr; n++)
		{
			if (lstrcmpA(pSignerInfo->UnauthAttrs.rgAttr[n].pszObjId,
				szOID_RSA_counterSign) == 0)
			{
				fResult = CryptDecodeObject(ENCODING,
					PKCS7_SIGNER_INFO,
					pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData,
					pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
					0,
					NULL,
					&dwSize);
				if (!fResult)
				{
					break;
				}

				*pCounterSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSize);
				if (!*pCounterSignerInfo)
				{
					break;
				}

				fResult = CryptDecodeObject(ENCODING,
					PKCS7_SIGNER_INFO,
					pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData,
					pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
					0,
					(PVOID)*pCounterSignerInfo,
					&dwSize);
				if (!fResult)
				{
					break;
				}
				fReturn = TRUE;
				break; 
			}
		}
	}
	catch (...)
	{
	}
	if (pCertContext != NULL)
		CertFreeCertificateContext(pCertContext);

	return fReturn;
}

/*														
/* Function: CheckSignature							
/* check EXE signature
/* input:    			
/*			path - EXE path
/* returns: void 
*/
BOOL CheckSignature(const char* path)
{
	HCERTSTORE		  hStore = NULL;
	HCRYPTMSG		  hMsg = NULL;
	PCCERT_CONTEXT    pCertContext = NULL;
	BOOL			  res;
	DWORD			  dwEncoding, dwContentType, dwFormatType;
	PCMSG_SIGNER_INFO pSignerInfo = NULL;
	PCMSG_SIGNER_INFO pCounterSignerInfo = NULL;
	DWORD			  dwSignerInfo;
	CERT_INFO		  CertInfo;
	SYSTEMTIME        systemTime;

	try
	{
		const size_t cSize = strlen(path) + 1;
		wchar_t* szFileName = new wchar_t[cSize];
		if (!szFileName)
			return 0;

		size_t converted = 0;
		mbstowcs_s(&converted,szFileName, cSize, path, cSize);
		// Get message handle and store handle from the signed file.
		res = CryptQueryObject(CERT_QUERY_OBJECT_FILE,
			szFileName,
			CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
			CERT_QUERY_FORMAT_FLAG_BINARY,
			0,
			&dwEncoding,
			&dwContentType,
			&dwFormatType,
			&hStore,
			&hMsg,
			NULL);
		delete[] szFileName;
		if (!res)
		{
			return 0;
		}

		// Get signer information size.
		res = CryptMsgGetParam(hMsg,
			CMSG_SIGNER_INFO_PARAM,
			0,
			NULL,
			&dwSignerInfo);
		if (!res)
		{
			return 0;
		}

		// Allocate memory for signer information.
		pSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSignerInfo);
		if (!pSignerInfo)
		{
			return 0;
		}
		
		// Get Signer Information.
		res = CryptMsgGetParam(hMsg,
			CMSG_SIGNER_INFO_PARAM,
			0,
			(PVOID)pSignerInfo,
			&dwSignerInfo);
		if (!res)
		{
			if (pSignerInfo)
				GlobalFree(pSignerInfo);

			return 0;
		}
		// Search for the signer certificate in the temporary 
		// certificate store.
		CertInfo.Issuer = pSignerInfo->Issuer;
		CertInfo.SerialNumber = pSignerInfo->SerialNumber;

		pCertContext = CertFindCertificateInStore(hStore,
			ENCODING,
			0,
			CERT_FIND_SUBJECT_CERT,
			(PVOID)&CertInfo,
			NULL);
		if (!pCertContext)
		{
			if (pSignerInfo)
				GlobalFree(pSignerInfo);

			return 0;
		}

		// Get Signer certificate information.
		GetCertificateInfo(pCertContext);

		// Get certificate signerinfo structure.
		if (GetSignerInfo(pSignerInfo, &pCounterSignerInfo))
		{
			CertInfo.Issuer = pCounterSignerInfo->Issuer;
			CertInfo.SerialNumber = pCounterSignerInfo->SerialNumber;

			pCertContext = CertFindCertificateInStore(hStore,
				ENCODING,
				0,
				CERT_FIND_SUBJECT_CERT,
				(PVOID)&CertInfo,
				NULL);
			if (!pCertContext)
			{
				if (pSignerInfo)
					GlobalFree(pSignerInfo);
				if (pCounterSignerInfo)
					GlobalFree(pCounterSignerInfo);

				return 0;
			}
			GetCertificateInfo(pCertContext);
			GetSigningTime(pCounterSignerInfo, &systemTime);
		}
	}
	catch (...){}

	if (pSignerInfo) 
		GlobalFree(pSignerInfo);
	if (pCounterSignerInfo)
		GlobalFree(pCounterSignerInfo);
	if (pCertContext) 
		CertFreeCertificateContext(pCertContext);
	if (hStore)
		CertCloseStore(hStore, 0);
	if (hMsg)
		CryptMsgClose(hMsg);
	return 1;
}

/*
/* Function: IsRunningAsAdmin
/* check if EXE has admin permissions
/* input:
/*			pName - EXE path
/* returns: TRUE if EXE has admin permissions, else FALSE
*/
BOOL IsRunningAsAdmin(const char* pName) {
	int size = strlen(pName) * 2 + 1;
	wchar_t* szFileName = new wchar_t[size];
	if (!szFileName)
		return 0;

	size_t converted = 0;
	mbstowcs_s(&converted, szFileName, size, pName, size);
	HANDLE hProcess = 0;
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (_wcsicmp(entry.szExeFile, szFileName) == 0)
			{
				hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
				GetProcessPriority(hProcess);
				GetProcessTimes(hProcess);
				GetProcessMemoryInfo(hProcess, &memCounter, sizeof(memCounter));
				CloseHandle(hProcess);
			}
		}
	}
	CloseHandle(snapshot);
	delete[]szFileName;
	BOOL fRet = FALSE;
	HANDLE hToken = NULL;
	if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
		TOKEN_ELEVATION Elevation;
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
			fRet = Elevation.TokenIsElevated;
		}
	}
	if (hToken) {
		CloseHandle(hToken);
	}
	return fRet;
}

/*
/* Function: InspectEXE
/* inspect EXE properties
/* input:
/*			hwnd - window handle
/* returns: void
*/
void InspectEXE(HWND hwnd)
{
	bHasMainBrowserControl = false;
	if (hwnd)
	{
		TCHAR buffer[MAX_PATH];
		GetClassName(hwnd, buffer, MAX_PATH);
		wndClassName = buffer;
		::GetClassName(hwnd, buffer, MAX_PATH);
		if (!lstrcmp(buffer, L"#32770"))
			EnumChildWindows(hwnd, EnumChildProc, 0);
	}
	else
		return;


	COLORREF color = RGB(0, 128, 128);
	HBRUSH brush = CreateSolidBrush(color);

	//Get PID
	pid = 0;
	GetWindowThreadProcessId(hwnd, &pid);
	//Get process name
	char buffer[MAX_PATH];
	sprintf_s(buffer, 256, WMIC_EXE_PATH, pid);
	FILE *fp = _popen(buffer, "r");
	if (!fp)
	{
		return;
	}
	char bufferOutput[1024];
	char *line_p = fgets(bufferOutput, sizeof(bufferOutput), fp);
	int len = strlen(line_p);
	char* exeEndPos = strstr(line_p, ".exe") ? strstr(line_p, ".exe") + 4 : exeEndPos = strstr(line_p, ".EXE") + 4;
	char* exeStartPos = line_p;
	do{
		exeStartPos = strstr(exeStartPos, "\\")+1;
	} while (strstr(exeStartPos, "\\"));
	strncpy_s(szExeFullPath, 1024, line_p, exeEndPos - line_p);
	strncpy_s(szExePath, 1024, exeStartPos, exeEndPos - exeStartPos);
	strncpy_s(szFolderPath, 1024, line_p, exeEndPos - line_p - strlen(szExePath));
	//Check process signature
	bSigned = CheckSignature(szExeFullPath) == TRUE;
	//Check process product and version
	strProductVersion="";
	int size = strlen(szExeFullPath) * 2 + 1;
	wchar_t* szFileName = new wchar_t[size];
	if (!szFileName)
		return;
	size_t converted = 0;
	mbstowcs_s(&converted, szFileName, size, szExeFullPath, size);
	GetVersionInfo(szFileName);
	//Read process import table
	ReadExeImportTable(szExeFullPath);
	//check EXE type
	exeType = GetExeType(szExeFullPath);
	//check process resources
	size = strlen(szExeFullPath) * 2 + 1;
	wchar_t* wszFileName = new wchar_t[size];
	if (!wszFileName)
		return;
	converted = 0;
	mbstowcs_s(&converted, wszFileName, size, szExeFullPath, size);
	CRessourceLoader  res(wszFileName);
	delete[] wszFileName;
	res.LoadLibrary();
	res.TraverseResources();

	fclose(fp);
	//Get child processes
	sprintf_s(buffer, 256, WMIC_WC, szExePath);
	FILE* fp1 = _popen(buffer, "r");
	char ch = 0;
	if (fp1)
	{
		iNumOfProcesseses = 0;
		while (!feof(fp1))
		{
			ch = fgetc(fp1);
			if (ch >= '0' && ch <= '9')
				iNumOfProcesseses = iNumOfProcesseses * 10 + ch - '0';
			if (ch == '\n')
			{
				break;
			}
		}
		fclose(fp1);
	}
	//check number of listening connections
	sprintf_s(buffer, 256, NETSTAT_CMD, pid);
	FILE* fp2 = _popen(buffer, "r");
	fp2 = _popen(buffer, "r");
	BOOL startPort = FALSE;
	int portNumber = 0;
	portNumbers = "";
	if (fp2)
	{
		ch = 0;
		while (!feof(fp2))
		{
			ch = fgetc(fp2);
			if (ch == ':')
			{
				startPort = TRUE;
				portNumber = 0;
			}
			if (startPort && ch == ' ')
			{
				startPort = FALSE;
				if (!portNumbers.empty())
					portNumbers += ",";
				sprintf_s(buffer, MAX_PATH, "%d", portNumber);
				portNumbers += buffer;
			}
			if (startPort && ch >= '0' && ch <= '9')
				portNumber = portNumber * 10 + ch - '0';
			if (ch == '\n')
			{
				break;
			}
		}
		_pclose(fp2);
	}
	bAdmin = IsRunningAsAdmin(szExePath)==TRUE;

	if (ghWnd)
	{
		RepaintWindow();
	}

}

/*
/* Function: InspectStaticEXE
/* inspect static EXE file  properties
/* input:
/*			exePath - EXE path
/* returns: void
*/
void InspectStaticEXE(const char* exePath)
{
	bHasMainBrowserControl = false;
	//Check process signature
	bSigned = CheckSignature(szExeFullPath) == TRUE;
	//Check process product and version
	strProductVersion = "";
	int size = strlen(szExeFullPath) * 2 + 1;
	wchar_t* szFileName = new wchar_t[size];
	if (!szFileName)
		return;

	size_t converted = 0;
	mbstowcs_s(&converted, szFileName, size, szExeFullPath, size);
	GetVersionInfo(szFileName);
	//Calculate containing folder path
	char* exeEndPos = szExeFullPath;
	char* exeStartPos = szExeFullPath;
	do{
		exeStartPos = strstr(exeStartPos, "\\") + 1;
	} while (strstr(exeStartPos, "\\"));
	strncpy_s(szFolderPath, 1024, szExeFullPath, exeStartPos - szExeFullPath);
	//check EXE type
	exeType = GetExeType(szExeFullPath);
	//check process resources
	size = strlen(szExeFullPath) * 2 + 1;
	wchar_t* wszFileName = new wchar_t[size];
	if (!wszFileName)
		return;

	converted = 0;
	mbstowcs_s(&converted, wszFileName, size, szExeFullPath, size);
	CRessourceLoader res(wszFileName);
	res.LoadLibrary();
	res.TraverseResources();
	bAdmin = IsRunningAsAdmin(szExePath) == TRUE;
	HANDLE hFile = CreateFile(szFileName,
		GENERIC_READ,
		FILE_SHARE_WRITE | FILE_SHARE_READ,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		dwExeSize = GetFileSize(hFile, 0);
		CloseHandle(hFile);
	}
	//Check process signature
	bSigned = CheckSignature(szExeFullPath) == TRUE;
	delete[] szFileName;
	if (ghWnd)
	{
		RepaintWindow();
	}

}

/*
/* Function: EnumChildProc
/* Enumerate window's child window
/* input:
/*			hwnd   - window handle
/*			lParam - message specific id
/* returns: void
*/
BOOL CALLBACK EnumChildProc(HWND hwnd, LPARAM lParam) {
	wchar_t name[64];
	memset(name, 64, 1);
	::GetClassName(hwnd, name, 64);
	if (!lstrcmp(name, L"Internet Explorer_Server"))
	{
		bHasMainBrowserControl = true;
	}
	return TRUE; 
}


/*
/* Function: _tWinMain
/* EMain window function
/* input:
/*			hInstance     - application instance handle
/*			hPrevInstance - previous instance
/*			lpCmdLine     - command line
/*			nCmdShow	  - show window flag
/* returns: void
*/
int APIENTRY _tWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPTSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

	set_unexpected(myunexpected);

 	// TODO: Place code here.
	MSG msg;
	HACCEL hAccelTable;

	// Initialize global strings
	LoadString(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
	LoadString(hInstance, IDC_WIN32PROJECT1, szWindowClass, MAX_LOADSTRING);
	RegisterWndClass(hInstance);

	// Perform application initialization:
	if (!InitApp(hInstance, nCmdShow))
	{
		return FALSE;
	}
	//Add clipboard listener
	AddClipboardFormatListener(ghWnd);

	hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_WIN32PROJECT1));

	IWbemLocator  *pLoc = NULL;
	IWbemServices *pSvc = NULL;
	// Use an unsecured apartment for security
	IUnsecuredApartment* pUnsecApp = NULL;
	IUnknown* pStubUnk = NULL;
	ProcessEventSink* pSink = NULL;
	IWbemObjectSink* pStubSink = NULL;


	CWndDropTarget *pdt = 0;
	IDropTarget* ppv = 0;
	HRESULT hr = S_OK;

	//Initialize OLE and associate window as drag and rop
	if (SUCCEEDED(OleInitialize(NULL))) {
		HRESULT hrRegister=0;
		{
			pdt = new(nothrow)CWndDropTarget();
			hr = pdt->QueryInterface(IID_IDropTarget,(void**) &ppv);
			pdt->Release();

			hr = RegisterDragDrop(ghWnd, ppv);
		} 
	}

	if (SUCCEEDED(hr = CoInitializeSecurity(
		NULL,
		-1,
		NULL,
		NULL,
		RPC_C_AUTHN_LEVEL_DEFAULT,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_NONE,
		NULL
	)) || hr == 0x80010119) {
		hr = CoCreateInstance(
			CLSID_WbemLocator,
			0,
			CLSCTX_INPROC_SERVER,
			IID_IWbemLocator, (LPVOID *)&pLoc);

		if (SUCCEEDED(hr))
		{
			hr = pLoc->ConnectServer(
				_bstr_t(L"ROOT\\CIMV2"),
				NULL,
				NULL,
				0,
				NULL,
				0,
				0,
				&pSvc
				);

			if (SUCCEEDED(hr))
			{
				hr = CoSetProxyBlanket(
					pSvc,                        
					RPC_C_AUTHN_WINNT,           
					RPC_C_AUTHZ_NONE,            
					NULL,                        
					RPC_C_AUTHN_LEVEL_CALL,      
					RPC_C_IMP_LEVEL_IMPERSONATE, 
					NULL,                        
					EOAC_NONE                    
					);

				if (SUCCEEDED(hr))
				{

					hr = CoCreateInstance(CLSID_UnsecuredApartment, NULL,
						CLSCTX_LOCAL_SERVER, IID_IUnsecuredApartment,
						(void**)&pUnsecApp);
					if (SUCCEEDED(hr))
					{
						pSink = new ProcessEventSink;
						pSink->AddRef();
						pUnsecApp->CreateObjectStub(pSink, &pStubUnk);
						pStubUnk->QueryInterface(IID_IWbemObjectSink, (void **)&pStubSink);

						hr = pSvc->ExecNotificationQueryAsync(
							_bstr_t("WQL"),
							_bstr_t("SELECT * "
							"FROM __InstanceCreationEvent WITHIN 1 "
							"WHERE TargetInstance ISA 'Win32_Process'"),
							WBEM_FLAG_SEND_STATUS,
							NULL,
							pStubSink);
					}
				}
			}
		}
	}
	
	RegisterFileSystemChanges();

	// Main message loop:
	while (GetMessage(&msg, NULL, 0, 0))
	{
		if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}
	//Revoke drag and drop
	RevokeDragDrop(ghWnd);
	//Remove clipboard listener
	RemoveClipboardFormatListener(ghWnd);
	//release nterface and delete class
	if (ppv)
		ppv->Release();
	delete pdt;
	pdt = NULL;

	if (pSvc)
		pSvc->Release();
	if (pLoc)
		pLoc->Release();
	if (pUnsecApp)
		pUnsecApp->Release();
	if (pStubUnk)
		pStubUnk->Release();
	if (pSink)
		pSink->Release();
	if (pStubSink)
		pStubSink->Release();
	CoUninitialize();

	//Uninitialize OLE
	OleUninitialize();


	return (int) msg.wParam;
}


/*
/* Function: RegisterWndClass
/* register window classs
/* input:
/*			hInstance - instance handle
/* returns: void
*/
ATOM RegisterWndClass(HINSTANCE hInstance)
{
	WNDCLASSEX wcex;

	wcex.cbSize = sizeof(WNDCLASSEX);

	wcex.style			= CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc	= WndProc;
	wcex.cbClsExtra		= 0;
	wcex.cbWndExtra		= 0;
	wcex.hInstance		= hInstance;
	wcex.hIcon			= LoadIcon(hInstance, MAKEINTRESOURCE(IDI_WIN32PROJECT1));
	wcex.hCursor		= LoadCursor(NULL, IDC_ARROW);
	wcex.hbrBackground =  (HBRUSH)(COLOR_MENU);//(HBRUSH)GetStockObject(NULL_BRUSH);
	wcex.lpszMenuName	= MAKEINTRESOURCE(IDC_WIN32PROJECT1);
	wcex.lpszClassName	= szWindowClass;
	wcex.hIconSm		= LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

	return RegisterClassEx(&wcex);
}


/*
/* Function: InitApp
/* create and display main window
/* input:    
/*			hInstance - instance handle
/*			nCmdShow  - show window flag
/* returns: TRUE for success, else false
*/
BOOL InitApp(HINSTANCE hInstance, int nCmdShow)
{
   hInst = hInstance; // Store instance handle in our global variable

   ghWnd = CreateWindow(szWindowClass, szTitle, WS_EX_LAYERED,
      CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, NULL, NULL, hInstance, NULL);

   if (!ghWnd)
   {
      return FALSE;
   }
   //Transparent window
//   SetWindowLong(ghWnd, GWL_EXSTYLE, GetWindowLong(ghWnd, GWL_EXSTYLE) | WS_EX_LAYERED);
  // SetLayeredWindowAttributes(ghWnd, RGB(255, 255, 255), 50, LWA_ALPHA|LWA_COLORKEY);
   ShowWindow(ghWnd, nCmdShow);
   //Display window
   UpdateWindow(ghWnd);

   return TRUE;
}


/*
/* Function: WndProc
/* Main window events handler
/* input:
/*			hWnd     - window handle
/*			message  - command ID
/*          wParam   - message specific data
/*          lParam   - message specific ID
/* returns: TRUE for success, else false
*/
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int         eventId=0;
	PAINTSTRUCT ps;
	HDC			hdc;
	wchar_t     buffer[2 * MAX_PATH];


	switch (message)
	{
		//clipboard content changed
	case WM_CLIPBOARDUPDATE:
		wsprintf(buffer, L"clipboard content updated. text is: %S", GetClipboardString().c_str());
		OutputDebugString(buffer);
		break;
		//Initialize menu
	case WM_INITMENU:
		EnableMenuItems();
		break;
		//Menu commands
	case WM_COMMAND:
		eventId = LOWORD(wParam);
		// Parse the menu selections:
		switch (eventId)
		{
		case IDM_OPENPROCESS:
			OpenProcessByPath(szExeFullPath);
			break;
		case IDM_RESUME:
			SuspendProcess(pid, FALSE);
			RepaintWindow();
			break;
		case IDM_SUSPEND:
			SuspendProcess(pid, TRUE);
			RepaintWindow();
			break;
		case IDM_ABOUT:
			DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
			break;
		case IDM_EXIT:
			DestroyWindow(hWnd);
			break;
		case IDM_CLOSE:
			KillTask();
			break;
		case IDM_FOLDER:
			OpenContainingFolder();
			break;
		default:
			return DefWindowProc(hWnd, message, wParam, lParam);
		}
		break;
		//File system change notification
	case WM_FILESYSTEM_CHANGED_MSG:
		HandleFileSystemChange(wParam, lParam);
		break;

	case WM_LBUTTONDOWN:
	{
 	     bLeftButtonDown = TRUE;
	}
	break;
	case WM_MOUSEMOVE:
	{
		if (bLeftButtonDown)
		{
			SetCapture(ghWnd);
			//SetCursor((HCURSOR)LoadCursor(NULL, IDC_CROSS));
			SetCursor((HCURSOR)LoadCursor(hInst, MAKEINTRESOURCE(IDC_MAG_GLASS)));
		}
		else
		{
			ReleaseCapture();
			SetCursor((HCURSOR)LoadCursor(NULL, IDC_ARROW));
		}
	}
	break;
	case WM_LBUTTONUP:
	{
 	   bLeftButtonDown = FALSE;
 	   ReleaseCapture();
 	   POINT p;
	   GetCursorPos(&p);
	   HWND wnd = ::WindowFromPoint(p);
	   if (wnd != ghWnd && wnd != hConsole)
		 InspectEXE(wnd);
	}
	break;
	//Paint
	case WM_PAINT:
		{
			hdc = BeginPaint(hWnd, &ps);
			Paint(hWnd,hdc);
			EndPaint(hWnd, &ps);
		}
		break;
	//Destroy window
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	default:
		return DefWindowProc(hWnd, message, wParam, lParam);
	}
	return 0;
}


/*
/* Function: About
/* Message handler for about box.
/* input:
/*			hDlg     - dialog handle
/*			message  - command ID
/*          wParam   - message specific data
/*          lParam   - message specific ID
/* returns: TRUE for success, else false
*/
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
		return (INT_PTR)TRUE;

	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}


/*
/* Function: ReadExeImportTable
/* Inspect EXE file import table
/* input:
/*			name				- EXE path
/*          wParam   - message specific data
/*          lParam   - message specific ID
/* returns: TRUE for success, else false
*/
void ReadExeImportTable(const char* name)
{
	int size = strlen(name) * 2 + 1;
	wchar_t* szFileName = new wchar_t[size];
	if (!szFileName)
		return;

	size_t converted = 0;
	mbstowcs_s(&converted, szFileName, size, name, size);
	HANDLE hFile = CreateFile(szFileName,
		GENERIC_READ,
		FILE_SHARE_WRITE | FILE_SHARE_READ,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		delete[] szFileName;
		return;
	}
	char *mem = NULL;
	dwExeSize = GetFileSize(hFile, 0);
	if (dwExeSize == 0)
	{
		CloseHandle(hFile);
		delete[] szFileName;
		return;
	}
	mem = new char[dwExeSize];
	if (!mem)
	{
		CloseHandle(hFile);
	}
	else
	{
		ReadImportAndExportTables(szFileName);
		delete[] szFileName;
	}
}


/*
/* Function: GetExeType
/* Check EXE type
/* input:    
/*			filePath - EXE file path
/* returns: exe type
*/
string GetExeType(char* filePath)
{
	int size = strlen(filePath) * 2 + 1;
	wchar_t* szFileName = new wchar_t[size];
	if (!szFileName)
		return "";

	size_t converted = 0;
	mbstowcs_s(&converted, szFileName, size, filePath, size);

	SHFILEINFO shFileInfo;
	const DWORD dwRetVal = SHGetFileInfo(szFileName,
		FILE_ATTRIBUTE_NORMAL,
		&shFileInfo,
		sizeof(shFileInfo),
		SHGFI_EXETYPE);
	delete[] szFileName;

	if (dwRetVal)
	{
		const WORD wPEWord = MAKEWORD('P', 'E');
		const WORD wMZWord = MAKEWORD('M', 'Z');
		const WORD wNEWord = MAKEWORD('N', 'E');
		const WORD wLowWord = LOWORD(dwRetVal);
		const WORD wHiWord = HIWORD(dwRetVal);
		if (wLowWord == wPEWord || wLowWord == wNEWord)
		{
			if (wHiWord == 0)
			{
				return WIN_CONSOLE;
			}
			else
			{
				return  WIN_APP;
			}
		}
		else if (wLowWord == wMZWord && wHiWord == 0)
		{
			return  MS_DOS;
		}
		else
		{
			return UNKNOWN_APP_TYPE;
		}
	}
	return UNKNOWN_APP_TYPE;
}


/*
/* Function: GetProcessPriority
/* Get process priority
/* input:    
/*			hProcess - process handle
/* returns: void
*/
void GetProcessPriority(HANDLE hProcess)
{
	DWORD priority = GetPriorityClass(hProcess);
	processPriority = "";
	switch (priority)
	{
	case NORMAL_PRIORITY_CLASS:
		processPriority = NORMAL;
		break;
	case ABOVE_NORMAL_PRIORITY_CLASS:
		processPriority = ABOVE_NORMAL;
		break;
	case BELOW_NORMAL_PRIORITY_CLASS:
		processPriority = BELOW_NORMAL;
		break;
	case HIGH_PRIORITY_CLASS:
		processPriority = HIGH;
		break;
	case REALTIME_PRIORITY_CLASS:
		processPriority = REALTIME;
		break;
	case IDLE_PRIORITY_CLASS:
		processPriority = IDLE;
		break;
	}
}

/*
/* Function: GetProcessTimes
/* Get process timing information
/* input:    
/*			hProcess - process handle
/* returns: void
*/
void GetProcessTimes(HANDLE hProcess)
{
	FILETIME ftStartTime,ftExitTime,ftKernelModeTime,ftUserModeTime;

	::GetProcessTimes(hProcess, &ftStartTime, &ftExitTime, &ftKernelModeTime, &ftUserModeTime);

	GetFormattedTime(ftStartTime, startTime);
}


/*
/* Function: GetFormattedTime
/* Format time to string
/* input:    
/*			IN  time    - formatted time
/*			OUT timeStr - file system time
/* returns: void
*/
void GetFormattedTime(IN FILETIME& time, OUT string& timeStr)
{
	SYSTEMTIME sysTime = { 0 };

	if (time.dwLowDateTime != 0 || time.dwHighDateTime != 0)
	{
		const FILETIME stftTemp = time;
		FileTimeToLocalFileTime(&stftTemp, &time);
	}

	FileTimeToSystemTime(&time, &sysTime);
	char buffer[256];
	sprintf_s(buffer, 256, "%d-%02d-%02d %02d:%02d:%02d", sysTime.wYear, sysTime.wMonth, sysTime.wDay, sysTime.wHour, sysTime.wMinute, sysTime.wSecond);
	timeStr = buffer;
}

/*
/* Function: SuspendProcess
/* Suspend/resume process
/* input:    
/*			processId	- process ID
/*			bSuspend    - suspend/resume flag
/* returns: void
*/
void SuspendProcess(DWORD processId,BOOL bSuspend)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	THREADENTRY32 threadEntry;
	threadEntry.dwSize = sizeof(THREADENTRY32);

	Thread32First(hSnapshot, &threadEntry);

	do
	{
		if (threadEntry.th32OwnerProcessID == processId)
		{
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE,
				threadEntry.th32ThreadID);

			if (bSuspend)
				SuspendThread(hThread);
			else
				ResumeThread(hThread);
			CloseHandle(hThread);
		}
	} while (Thread32Next(hSnapshot, &threadEntry));

	CloseHandle(hSnapshot);
	processStatus = bSuspend ? SUSPENDED : RUNNING;
}


/*
/* Function: FindProcessByWindow
/* Find process by window handle
/* input:    
/*			pid - process ID
/* returns: process window handle
*/
HWND FindProcessByWindow(DWORD pid)
{
	std::pair<HWND, DWORD> params = { 0, pid };
	BOOL bResult = EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL
	{
		auto pParams = (std::pair<HWND, DWORD>*)(lParam);

		DWORD processId;
		if (GetWindowThreadProcessId(hwnd, &processId) && processId == pParams->second)
		{
			SetLastError(-1);
			pParams->first = hwnd;
			return FALSE;
		}
		return TRUE;
	}, (LPARAM)&params);

	if (!bResult && GetLastError() == -1 && params.first)
	{
		return params.first;
	}
	return 0;
}

/*
/* Function: RegisterFileSystemChanges
/* Register to shell notifications (this includes file system changes)
/* input: none
/* returns: void
*/
void RegisterFileSystemChanges()
{
	SHChangeNotifyEntry shCNE;
	shCNE.pidl = 0;
	shCNE.fRecursive = TRUE;
	ULONG res = SHChangeNotifyRegister(ghWnd, SHCNRF_InterruptLevel | SHCNRF_ShellLevel | SHCNRF_RecursiveInterrupt, SHCNE_ALLEVENTS, WM_FILESYSTEM_CHANGED_MSG, 1, &shCNE);
}

/*
/* Function: RepaintWindow
/* Refresh window
/* input: none
/* returns: void
*/
void RepaintWindow()
{
	if (ghWnd)
	{
		RECT rect;
		GetClientRect(ghWnd, &rect);
		InvalidateRect(ghWnd, &rect, TRUE);
	}
	SetForegroundWindow(ghWnd);
	if (hConsole)
	{
		SetForegroundWindow(hConsole);
		::SetWindowPos(hConsole, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOSIZE | SWP_DRAWFRAME);
		PositionWindow(hConsole, ghWnd);
	}
}



/*
/* Function: PositionWindow
/* Position a window according to its parent window
/* input:
/*       hwndWindow  - window handle
/*		 hwndParent  - parent window handle
/*
/* returns: none
*/
void PositionWindow(HWND hwndWindow, HWND hwndParent)
{
	RECT rectWindow, rectParent;

	if (hwndParent)
	{
		GetWindowRect(hwndWindow, &rectWindow);
		GetWindowRect(hwndParent, &rectParent);

		int nWidth = rectWindow.right - rectWindow.left;
		int nHeight = rectWindow.bottom - rectWindow.top;

		int nX = rectParent.right - nWidth;
		int nY = rectParent.top;

		int nScreenWidth = GetSystemMetrics(SM_CXSCREEN);
		int nScreenHeight = GetSystemMetrics(SM_CYSCREEN);

		if (nX < 0) nX = 0;
		if (nY < 0) nY = 0;
		if (nX + nWidth > nScreenWidth) nX = nScreenWidth - nWidth;
		if (nY + nHeight > nScreenHeight) nY = nScreenHeight - nHeight;

		MoveWindow(hwndWindow, nX, nY, nWidth, nHeight, FALSE);
	}
}

/*
/* Function: OpenProcessByPath
/* Run process by its path
/* input:
/*       exeFullPath - file system path
/*
/* returns: void
*/
void OpenProcessByPath(const char* exeFullPath)
{
	STARTUPINFOA info = { sizeof(info) };
	PROCESS_INFORMATION processInfo;
	if (CreateProcessA(exeFullPath, "", NULL, NULL, TRUE, 0, NULL, NULL, &info, &processInfo))
	{
		WaitForSingleObject(processInfo.hProcess, 1000);
		pid = processInfo.dwProcessId;
		HWND hWnd = FindProcessByWindow(pid);
		if (hWnd)
		{
			InspectEXE(hWnd);
		}
		CloseHandle(processInfo.hProcess);
		CloseHandle(processInfo.hThread);
	}

}

/*
/* Function: HandleFileSystemChange
/* Handle file system changes notifications
/* input:
/*       wParam - shell change parameters
/*		 lParam - shell change ID
/*
/* returns: void
*/
void HandleFileSystemChange(WPARAM wParam, LPARAM lParam)
{
	mutexMessages.lock();
	SetForegroundWindow(ghWnd);
	HWND hConsole = FindWindow(NULL, CONSOLE_TITLE);
	if (hConsole)
	{
		SetForegroundWindow(hConsole);
		PositionWindow(hConsole, ghWnd);
	}
	SHMSGSTRUCT *shns = (SHMSGSTRUCT *)wParam;
	string strPath = GetPathFromPIDL(shns->dwItem1);
	wchar_t buffer[MAX_PATH * 2];
	switch (lParam)
	{
	case SHCNE_RENAMEITEM:
		wprintf_s(L"%S was renamed \n", strPath.c_str());
		if (!strPath.empty())
		{
			wsprintf(buffer, L"%S was renamed \n", strPath.c_str());
			OutputDebugString(buffer);
		}
		break;
	case SHCNE_CREATE:
		wprintf_s(L"%S was created \n", strPath.c_str());
		if (!strPath.empty())
		{
			wsprintf(buffer, L"%S was created \n", strPath.c_str());
			OutputDebugString(buffer);
		}
		break;
	case SHCNE_DELETE:
		wprintf_s(L"%S was deleted \n", strPath.c_str());
		if (!strPath.empty())
		{
			wsprintf(buffer, L"%S was deleted \n", strPath.c_str());
			OutputDebugString(buffer);
		}
		break;
	case SHCNE_MKDIR:
		wprintf_s(L"%S directory was created \n", strPath.c_str());
		if (!strPath.empty())
		{
			wsprintf(buffer, L"%S directory was created \n", strPath.c_str());
			OutputDebugString(buffer);
		}
		break;
	case SHCNE_RMDIR:
		wprintf_s(L"%S directory was deleted \n", strPath.c_str());
		if (!strPath.empty())
		{
			wsprintf(buffer, L"%S directory was deleted \n", strPath.c_str());
			OutputDebugString(buffer);
		}
		break;
	case SHCNE_MEDIAINSERTED:
		wprintf_s(L"%S media inserted \n", strPath.c_str());
		break;
	case SHCNE_DRIVEREMOVED:
		wprintf_s(L"%S driver removed \n", strPath.c_str());
		if (!strPath.empty())
		{
			wsprintf(buffer, L"%S driver removed \n", strPath.c_str());
			OutputDebugString(buffer);
		}
		break;
	case SHCNE_DRIVEADD:
		wprintf_s(L"%S driver added \n", strPath.c_str());
		if (!strPath.empty())
		{
			wsprintf(buffer, L"%S driver added \n", strPath.c_str());
			OutputDebugString(buffer);
		}
		break;
	case SHCNE_UPDATEITEM:
		{	
			 if (strPath.empty())
				 strPath = "A file";
			 wprintf_s(L"%S was updated \n", strPath.c_str());
			 if (!strPath.empty())
			 {
				 wsprintf(buffer, L"%S was updated \n", strPath.c_str());
				 OutputDebugString(buffer);
			 }
		}
		break;
	case SHCNE_UPDATEDIR:
		wprintf_s(L"%S was updated \n", strPath.c_str());
		if (!strPath.empty())
		{
			wsprintf(buffer, L"%S directory was updated \n", strPath.c_str());
			OutputDebugString(buffer);
		}
		break;
	case SHCNE_RENAMEFOLDER:
		wprintf_s(L"%S was renamed \n", strPath.c_str());
		if (!strPath.empty())
		{
			wsprintf(buffer, L"%S folder was renamed \n", strPath.c_str());
			OutputDebugString(buffer);
		}
		break;
	case SHCNE_SERVERDISCONNECT:
		wprintf_s(L"%S server disconnect \n", strPath.c_str());
		break;
	case SHCNE_UPDATEIMAGE:
		wprintf_s(L"%S updated image \n", strPath.c_str());
		break;
	case SHCNE_DRIVEADDGUI:
		wprintf_s(L"%S driver added GUI \n", strPath.c_str());
		break;
	case  SHCNE_FREESPACE:
		wprintf_s(L"freed space %S\n", strPath.c_str());
		break;
	default:
		break;
	}
	mutexMessages.unlock();
}


/*
/* Function: OpenContainingFolder
/* Show EXE's folder on file system
/* input: none
/* returns: void
*/

void OpenContainingFolder()
{
	int size = strlen(szFolderPath) * 2 + 1;
	wchar_t* wszFolderPath = new wchar_t[size];
	if (!wszFolderPath)
		return;

	size_t converted = 0;
	mbstowcs_s(&converted, wszFolderPath, size, szFolderPath, size);
	ShellExecute(0, L"explore", wszFolderPath, NULL, NULL, SW_SHOWNORMAL);
	delete[]wszFolderPath;
}

/*
/* Function: KillTask
/* Kill task by ID
/* input: none
/* returns: void
*/

void KillTask()
{
	if (pid > 0)
	{
		char buffer[MAX_PATH];
		sprintf_s(buffer, 256, TASK_KILL_CMD, pid);
		ShellExecuteA(0, OPEN, CMD_EXE, buffer, 0, SW_HIDE);
		pid = 0;
	}
}


/*
/* Function: Paint
/* Write EXE/process information to screen
/* input:    
/*       hWnd - window handle
/*		 hdc  - device context handle
/*
/* returns: void
*/
void Paint(HWND hWnd,HDC hdc)
{
	if (strlen(szExeFullPath))
	{
		int   pos = 0;
		HFONT hFont = CreateFont(16, 0, 0, 0, FW_BOLD, 0, 0, 0, 0, 0, 0, 2, 0, FONT_NAME);
		HFONT hTmp = (HFONT)SelectObject(hdc, hFont);
		RECT rect;
		GetClientRect(hWnd, &rect);
		SetTextColor(hdc, 0x00000000);
		SetBkMode(hdc, TRANSPARENT);
		rect.left = 10;
		rect.top = 10;
		wchar_t buffer[MAX_PATH * 4];
		swprintf_s(buffer, EXE_NAME_MSG, szExeFullPath);
		DrawText(hdc, buffer, -1, &rect, DT_SINGLELINE | DT_NOCLIP);
		if (!bSigned)
			swprintf_s(buffer, EXE_NOT_SIGNED_MSG);
		else
			swprintf_s(buffer, EXE_SIGNED_MSG);
		rect.top += LINE_OFFSET;
		DrawText(hdc, buffer, -1, &rect, DT_SINGLELINE | DT_NOCLIP);
		if (pid > 0)
		{
			swprintf_s(buffer, RUN_PROC_MSG, iNumOfProcesseses);
			rect.top += LINE_OFFSET;
			DrawText(hdc, buffer, -1, &rect, DT_SINGLELINE | DT_NOCLIP);
		}
		if (pid > 0)
		{
			if (!portNumbers.empty())
				swprintf_s(buffer, LISTEN_PORT_MSG, portNumbers.c_str());
			else
				swprintf_s(buffer, NOT_LISTEN_PORT_MSG);
			rect.top += LINE_OFFSET;
			DrawText(hdc, buffer, -1, &rect, DT_SINGLELINE | DT_NOCLIP);
		}
		if (bHasMainBrowserControl)
			swprintf_s(buffer, IE_BROWSE_MSG);
		else
			swprintf_s(buffer, NO_IE_BROWSE_MSG);
		rect.top += LINE_OFFSET;
		DrawText(hdc, buffer, -1, &rect, DT_SINGLELINE | DT_NOCLIP);
		if (pid > 0)
		{
			if (bAdmin)
				swprintf_s(buffer, RUN_ADMIN_MSG);
			else
				swprintf_s(buffer, NO_RUN_ADMIN_MSG);
			rect.top += LINE_OFFSET;
			DrawText(hdc, buffer, -1, &rect, DT_SINGLELINE | DT_NOCLIP);
		}
		if (pid > 0 && !dllNames.empty())
		{
			swprintf_s(buffer, IMPORT_DLLS_MSG, dllNames.c_str());
			rect.top += LINE_OFFSET;
			DrawText(hdc, buffer, -1, &rect, DT_WORDBREAK);
			pos = dllNames.find(CRLN);
			rect.top += LINE_OFFSET;
		}
		if (pid > 0 && !exportedFunctions.empty())
		{
			swprintf_s(buffer, EXPORT_FUNC_MSG, exportedFunctions.c_str());
			rect.top += LINE_OFFSET;
			DrawText(hdc, buffer, -1, &rect, DT_WORDBREAK);
			pos = exportedFunctions.find(CRLN);
			if (pos > 0)
				rect.top += LINE_OFFSET/2;
		}
		if (!strProductVersion.empty())
		{
			swprintf_s(buffer, PROD_VER_MSG, strProductVersion.c_str());
			rect.top += LINE_OFFSET*3;
			DrawText(hdc, buffer, -1, &rect, DT_SINGLELINE | DT_NOCLIP);
		}
		if (pid > 0)
		{
			swprintf_s(buffer, PROC_ID_MSG, pid);
			rect.top += LINE_OFFSET;
			DrawText(hdc, buffer, -1, &rect, DT_SINGLELINE | DT_NOCLIP);
			rect.top += LINE_OFFSET;
		}
		swprintf_s(buffer, EXE_TYPE_MSG, exeType.c_str());
		rect.top += LINE_OFFSET;
		DrawText(hdc, buffer, -1, &rect, DT_SINGLELINE | DT_NOCLIP);
		if (pid > 0)
		{
			swprintf_s(buffer, PROC_PRIORITY_MSG, processPriority.c_str());
			rect.top += LINE_OFFSET;
			DrawText(hdc, buffer, -1, &rect, DT_SINGLELINE | DT_NOCLIP);
		}
		if (pid > 0)
		{
			swprintf_s(buffer, PROC_START_MSG, startTime.c_str());
			rect.top += LINE_OFFSET;
			DrawText(hdc, buffer, -1, &rect, DT_SINGLELINE | DT_NOCLIP);
		}
		if (pid > 0)
		{
			swprintf_s(buffer, PROC_PEAK_MSG, memCounter.PeakPagefileUsage);
			rect.top += 30;
			DrawText(hdc, buffer, -1, &rect, DT_SINGLELINE | DT_NOCLIP);
		}
		if (pid > 0)
		{
			swprintf_s(buffer, PROC_STATE_MSG, processStatus.c_str());
			rect.top += LINE_OFFSET;
			DrawText(hdc, buffer, -1, &rect, DT_SINGLELINE | DT_NOCLIP);
		}
		swprintf_s(buffer, FILE_SIZE_MSG, dwExeSize);
		rect.top += LINE_OFFSET;
		DrawText(hdc, buffer, -1, &rect, DT_SINGLELINE | DT_NOCLIP);
		if (bSigned && !signerName.empty())
		{
			swprintf_s(buffer, CERT_SUB_MSG, signerName.c_str());
			rect.top += LINE_OFFSET;
			DrawText(hdc, buffer, -1, &rect, DT_SINGLELINE | DT_NOCLIP);
		}
		if (!companyName.empty())
		{
			swprintf_s(buffer, COMP_NAME_MSG, companyName.c_str());
			rect.top += LINE_OFFSET;
			DrawText(hdc, buffer, -1, &rect, DT_SINGLELINE | DT_NOCLIP);
		}
		if (!productName.empty())
		{
			swprintf_s(buffer, PROD_NAME_MSG, productName.c_str());
			rect.top += LINE_OFFSET;
			DrawText(hdc, buffer, -1, &rect, DT_SINGLELINE | DT_NOCLIP);
		}
		if (pid > 0 && !wndClassName.empty())
		{
			swprintf_s(buffer, CLASS_NAME_MSG, wndClassName.c_str());
			rect.top += LINE_OFFSET;
			DrawText(hdc, buffer, -1, &rect, DT_SINGLELINE | DT_NOCLIP);
		}
		if (pid>0 && processCPU>-1.0)
		{
			swprintf_s(buffer, PROCESS_CPU_USAGE, processCPU);
			rect.top += LINE_OFFSET;
			DrawText(hdc, buffer, -1, &rect, DT_SINGLELINE | DT_NOCLIP);
		}
		if (pid == 0)
		{
			if (bRequireAdmin)
				swprintf_s(buffer, REQUIRE_ADMIN_MSG);
			else
				swprintf_s(buffer, NO_REQUIRE_ADMIN_MSG);
			rect.top += LINE_OFFSET;
			DrawText(hdc, buffer, -1, &rect, DT_SINGLELINE | DT_NOCLIP);
		}
		if (hTmp)
			DeleteObject(SelectObject(hdc, hTmp));
	}
}


/*														
/* Function: EnableMenuItems							
/* Enable/disable menu items before menu is displayed   
/* input:    none			
/* 
/* returns: void 
*/
void EnableMenuItems()
{
	HMENU hMenu = GetMenu(ghWnd);
	if (pid == 0)
	{
		EnableMenuItem(hMenu, IDM_RESUME, MF_BYCOMMAND | MF_DISABLED);
		EnableMenuItem(hMenu, IDM_SUSPEND, MF_BYCOMMAND | MF_DISABLED);
		EnableMenuItem(hMenu, IDM_CLOSE, MF_BYCOMMAND | MF_DISABLED);
		if (!strlen(szExeFullPath))
		{
			EnableMenuItem(hMenu, IDM_OPENPROCESS, MF_BYCOMMAND | MF_DISABLED);
			EnableMenuItem(hMenu, IDM_FOLDER, MF_BYCOMMAND | MF_DISABLED);
		}
		else
		{
			EnableMenuItem(hMenu, IDM_OPENPROCESS, MF_BYCOMMAND | MF_ENABLED);
			EnableMenuItem(hMenu, IDM_FOLDER, MF_BYCOMMAND | MF_ENABLED);
		}
	}
	else
	{
		EnableMenuItem(hMenu, IDM_RESUME, MF_BYCOMMAND | MF_ENABLED);
		EnableMenuItem(hMenu, IDM_SUSPEND, MF_BYCOMMAND | MF_ENABLED);
		EnableMenuItem(hMenu, IDM_CLOSE, MF_BYCOMMAND | MF_ENABLED);
		EnableMenuItem(hMenu, IDM_FOLDER, MF_BYCOMMAND | MF_ENABLED);
		EnableMenuItem(hMenu, IDM_OPENPROCESS, MF_BYCOMMAND | MF_ENABLED);
	}
}


/*
/* Function: GetVersionInfo
/* Get version information from EXE file
/* input:    
/*			szFilename	 - file name
/* returns: void
*/
void GetVersionInfo(wchar_t* filename)
{
	DWORD			  dwVerInfoSize = 0;
	DWORD			  dwHandle = 0;
	char*			  fileVersion = NULL;
	UINT			  uLen  = 0; 
	VS_FIXEDFILEINFO *pInfo = NULL;

	companyName = "";
	productName = "";
	dwVerInfoSize = GetFileVersionInfoSize(filename, &dwHandle);
	if (dwVerInfoSize)
	{
		fileVersion = new char[dwVerInfoSize];
		if (fileVersion)
		{
			if (GetFileVersionInfo(filename, dwHandle, dwVerInfoSize, fileVersion))
			{
				if (VerQueryValue(fileVersion, BACKSLASH, (void**)&pInfo, (UINT *)&uLen))
				{
					char buffer[MAX_PATH];
					sprintf_s(buffer, MAX_PATH, "%u.%u.%u.%u", HIWORD(pInfo->dwProductVersionMS), LOWORD(pInfo->dwProductVersionMS),
						HIWORD(pInfo->dwProductVersionLS), LOWORD(pInfo->dwProductVersionLS));
					strProductVersion = buffer;
				}
			}

			WORD*  langInfo = 0;
			UINT   uLang = 0;
			LPVOID info = 0;

			VerQueryValue(fileVersion, _T("\\VarFileInfo\\Translation"),
				(LPVOID*)&langInfo, &uLang);
			char buffer[MAX_PATH];
			sprintf_s(buffer, MAX_PATH, "\\StringFileInfo\\%04x%04x\\%s", langInfo[0], langInfo[1], COMP_NAME);
			if (VerQueryValueA(fileVersion, buffer, &info, &uLen))
				companyName = (char*)info;

			sprintf_s(buffer, MAX_PATH, "\\StringFileInfo\\%04x%04x\\%s", langInfo[0], langInfo[1], PROD_NAME);
			if (VerQueryValueA(fileVersion, buffer, &info, &uLen))
				productName = (char*)info;

			delete[]fileVersion;
		}
	}
}


/*
/* Function: GetClipboardString
/* Get Clipboard Text
/* input:	none
/* returns: clipboard's text
*/
std::string GetClipboardString()
{
	std::string string;
	if (OpenClipboard(nullptr))
	{
		HANDLE hData = GetClipboardData(CF_TEXT);
		if (hData)
		{
			// Lock the handle to get the actual text pointer
			char* pszText = static_cast<char*>(GlobalLock(hData));
			if (pszText)
			{
				string = pszText;
			}
			GlobalUnlock(hData);
		}
		CloseClipboard();
	}
	return string;
}


/*
/* Function: ReadExportTableList
/* Read export table
/* input:	file			 - file data
/*          vraOffset		 - data dictionary virtual address
/*          codeOffset       - offset between code and headers
/*          fileSize		 - file size
/*          pNTHeader		 - NT header
/*          pNTSection       - NT section
/* returns: none
*/
void ReadExportTableList(BYTE * file, DWORD vraOffset, DWORD codeOffset, int fileSize, PIMAGE_NT_HEADERS pNTHeader, PIMAGE_SECTION_HEADER pNTSection)
{
	int nExtended = 0;
	PIMAGE_NT_HEADERS32 pNTHeader32 = (PIMAGE_NT_HEADERS32)pNTHeader;
	PIMAGE_NT_HEADERS64 pNTHeader64 = (PIMAGE_NT_HEADERS64)pNTHeader;

	DWORD dwTemp = (DWORD)-1;

	exportedFunctions = _T("");
	int count = 0;

	if (pNTHeader32->OptionalHeader.Magic == 0x020b)
		nExtended = 1;

	if (0 == nExtended)
	{
		for (int i = 0; i<pNTHeader32->FileHeader.NumberOfSections; i++)
		{
			if ((pNTHeader32->OptionalHeader.DataDirectory[0].VirtualAddress
				>= pNTSection->VirtualAddress)
				&& ((pNTHeader32->OptionalHeader.DataDirectory[0].VirtualAddress + pNTHeader32->OptionalHeader.DataDirectory[1].Size
				<= pNTSection->VirtualAddress + pNTSection->SizeOfRawData)))
			{
				dwTemp = pNTSection->VirtualAddress - pNTSection->PointerToRawData;
				break;
			}
			pNTSection++;
		}

		if (dwTemp != -1)
			codeOffset = dwTemp;
		else
		{
			if ((fileSize + pNTHeader32->OptionalHeader.DataDirectory[0].Size)
				< pNTHeader32->OptionalHeader.DataDirectory[0].VirtualAddress)
				return;
		}
	}
	else
	{
		for (int i = 0; i<pNTHeader64->FileHeader.NumberOfSections; i++)
		{
			if ((pNTHeader64->OptionalHeader.DataDirectory[0].VirtualAddress
				>= pNTSection->VirtualAddress)
				&& ((pNTHeader64->OptionalHeader.DataDirectory[0].VirtualAddress + pNTHeader64->OptionalHeader.DataDirectory[1].Size
				<= pNTSection->VirtualAddress + pNTSection->SizeOfRawData)))
			{
				dwTemp = pNTSection->VirtualAddress - pNTSection->PointerToRawData;
				break;
			}
			pNTSection++;
		}

		if (dwTemp != -1)
			codeOffset = dwTemp;
		else
		{
			if ((fileSize + pNTHeader64->OptionalHeader.DataDirectory[0].Size)
				< pNTHeader64->OptionalHeader.DataDirectory[0].VirtualAddress)
				return;
		}
	}
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)&file[vraOffset - codeOffset];
	int nCount = pExport->NumberOfFunctions;
	short * pOrdinal = (short *)&file[pExport->AddressOfNameOrdinals - codeOffset];
	DWORD * pstrFunctionName = (DWORD *)&file[pExport->AddressOfNames - codeOffset];
	DWORD * pdwAdd = (DWORD *)&file[pExport->AddressOfFunctions - codeOffset];
	TCHAR funcName[MAX_PATH];
	int nNames = pExport->NumberOfNames, j = 0;
	for (int i = 0; i<nCount; i++)
	{
		int nOffset = (int)(pstrFunctionName[0] - codeOffset);
		if ((j < nNames)
			&& (nOffset > 0)
			&& (nOffset < fileSize))
		{
			wsprintf(funcName, _T("%S"), (TCHAR *)&file[nOffset]);
			j++;
		}
		else
			memset(funcName, 0, MAX_PATH);

		if (exportedFunctions.length())
			exportedFunctions += _T(",");
		exportedFunctions += funcName;
		count++;
		if (count == 10){
			exportedFunctions += CRLN;
			count = 0;
		}

		pdwAdd++;
		pOrdinal++;
		pstrFunctionName++;
	}
}

/*
/* Function: ReadImportTable
/* Read Import table
/* input:	file			 - file data
/*          vraOffset		 - data dictionary virtual address
/*          codeOffset       - offset between code and headers 
/*          fileSize		 - file size
/*          pNTHeader		 - NT header
/*          pNTSection       - NT section
/* returns: none
*/
void ReadImportTable(BYTE * file, DWORD vraOffset, DWORD codeOffset, int fileSize, PIMAGE_NT_HEADERS pNTHeader, PIMAGE_SECTION_HEADER pNTSection)
{
	int nExtended = 0;
	PIMAGE_NT_HEADERS32 pNTHeader32 = (PIMAGE_NT_HEADERS32)pNTHeader;
	PIMAGE_NT_HEADERS64 pNTHeader64 = (PIMAGE_NT_HEADERS64)pNTHeader;

	DWORD dwTemp = (DWORD)-1;

	if (pNTHeader32->OptionalHeader.Magic == 0x020b)
		nExtended = 1;

	dllNames = _T("");
	int count = 0;
	if (0 == nExtended)
	{
		for (int i = 0; i<pNTHeader32->FileHeader.NumberOfSections; i++)
		{
			if ((pNTHeader32->OptionalHeader.DataDirectory[1].VirtualAddress
				>= pNTSection->VirtualAddress)
				&& ((pNTHeader32->OptionalHeader.DataDirectory[1].VirtualAddress + pNTHeader32->OptionalHeader.DataDirectory[1].Size
				<= pNTSection->VirtualAddress + pNTSection->SizeOfRawData)))
			{
				dwTemp = pNTSection->VirtualAddress - pNTSection->PointerToRawData;
				break;
			}
			pNTSection++;
		}

		if (dwTemp != -1)			
			codeOffset = dwTemp;
		else
		{
			if ((fileSize + pNTHeader32->OptionalHeader.DataDirectory[1].Size)
				< pNTHeader32->OptionalHeader.DataDirectory[1].VirtualAddress)
				return;
		}
	}
	else
	{
		for (int i = 0; i<pNTHeader64->FileHeader.NumberOfSections; i++)
		{
			if ((pNTHeader64->OptionalHeader.DataDirectory[1].VirtualAddress
				>= pNTSection->VirtualAddress)
				&& ((pNTHeader64->OptionalHeader.DataDirectory[1].VirtualAddress + pNTHeader64->OptionalHeader.DataDirectory[1].Size
				<= pNTSection->VirtualAddress + pNTSection->SizeOfRawData)))
			{
				dwTemp = pNTSection->VirtualAddress - pNTSection->PointerToRawData;
				break;
			}
			pNTSection++;
		}

		if (dwTemp != -1)		
			codeOffset = dwTemp;
		else
		{
			if ((fileSize + pNTHeader64->OptionalHeader.DataDirectory[1].Size)
				< pNTHeader64->OptionalHeader.DataDirectory[1].VirtualAddress)
				return;
		}
	}

	TCHAR funcName[MAX_PATH];

	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)&file[vraOffset - codeOffset];
	IMAGE_THUNK_DATA32 * pImageThunk = NULL;

	while ((pImport->OriginalFirstThunk) || (pImport->FirstThunk))
	{
		wsprintf(funcName, _T("%S"), (TCHAR *)&file[pImport->Name - codeOffset]);
		if (dllNames.length())
			dllNames += _T(",");
		dllNames += funcName;
		count++;
		if (count == 10){
			dllNames += CRLN;
			count = 0;
		}

		if (pImport->OriginalFirstThunk)
			pImageThunk = (IMAGE_THUNK_DATA32 *)&file[pImport->OriginalFirstThunk - codeOffset];
		else
			pImageThunk = (IMAGE_THUNK_DATA32 *)&file[pImport->FirstThunk - codeOffset];

		while (pImageThunk->u1.Ordinal)
		{
			DWORD dwOffset = (0x7FFFFFFF & pImageThunk->u1.Function);

			int nOffset = dwOffset - codeOffset;
			if ((nOffset > 0)
				&& (nOffset < fileSize))
			{
				short * pOrdinal = (short *)&file[nOffset];
				pOrdinal++;
				if (!(0x80000000 & pImageThunk->u1.Function))
				{
					wsprintf(funcName, _T("%S"), (TCHAR *)(pOrdinal));
				}
			}
			pImageThunk++;
		}
		pImport++;
	}
}


/*
/* Function: ReadImportAndExportTables
/* Read Import And Export Tables
/* input:	strFileName - EXE file name
/* returns: none
*/
BOOL ReadImportAndExportTables(wstring strFileName)
{
	IMAGE_DOS_HEADER                stImageDosHeader;
	IMAGE_NT_HEADERS32              stImageNtHeaders32;
	IMAGE_NT_HEADERS64              stImageNtHeaders64;

	memset(&stImageDosHeader, 0, sizeof(IMAGE_DOS_HEADER));
	memset(&stImageNtHeaders32, 0, sizeof(IMAGE_DOS_HEADER));
	memset(&stImageNtHeaders64, 0, sizeof(IMAGE_DOS_HEADER));

	BYTE * pBuffer = NULL;
	HANDLE hFile = CreateFile(strFileName.data(), GENERIC_READ, FILE_SHARE_READ, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;

	DWORD dwFileSize = 0;
	dwFileSize = GetFileSize(hFile, NULL);
	if (dwFileSize)
	{
		pBuffer = new BYTE[dwFileSize + 2];
		if (pBuffer)
		{
			pBuffer[dwFileSize] = 0;
			pBuffer[dwFileSize + 1] = 0;
			DWORD dwRead = 0;
			ReadFile(hFile, pBuffer, dwFileSize, &dwRead, NULL);
			if (dwRead == dwFileSize)
			{
				PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pBuffer;
				if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE)
				{
					memcpy(&stImageDosHeader, dosHeader, sizeof(IMAGE_DOS_HEADER));
					PIMAGE_NT_HEADERS32 pNTHeader32 = (PIMAGE_NT_HEADERS32)(pBuffer + dosHeader->e_lfanew);
					if (pNTHeader32->Signature == IMAGE_NT_SIGNATURE)
					{
						PIMAGE_SECTION_HEADER pNTSection;
						int nOffsetBuf = pNTHeader32->OptionalHeader.BaseOfCode - pNTHeader32->OptionalHeader.SizeOfHeaders;
						memcpy(&stImageNtHeaders32, pNTHeader32, sizeof(IMAGE_NT_HEADERS32));
						//According to the specification, a value of 0x10b indicates 32-bit
						if (pNTHeader32->OptionalHeader.Magic == 0x010b)
						{
							pNTSection = (PIMAGE_SECTION_HEADER)(pNTHeader32 + 1);

							if (pNTHeader32->OptionalHeader.DataDirectory[0].Size)	
							{
								ReadExportTableList(pBuffer, pNTHeader32->OptionalHeader.DataDirectory[0].VirtualAddress
									, nOffsetBuf, dwFileSize, pNTHeader32, pNTSection);
							}
							if (pNTHeader32->OptionalHeader.DataDirectory[1].Size)	
							{
								ReadImportTable(pBuffer, pNTHeader32->OptionalHeader.DataDirectory[1].VirtualAddress
									, nOffsetBuf, dwFileSize, pNTHeader32, pNTSection);
							}

						}
					}
				}
			}
		}
	}
	if (hFile)
		CloseHandle(hFile);
	hFile = NULL;
	return TRUE;
}


