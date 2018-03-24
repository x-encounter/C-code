
// DLL注射器Dlg.cpp : 实现文件
//

#include "stdafx.h"
#include "DLL注射器.h"
#include "DLL注射器Dlg.h"
#include "afxdialogex.h"
#include <windows.h>
#include <TlHelp32.h>
#include <afxpriv.h>
#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CDLL注射器Dlg 对话框



CDLL注射器Dlg::CDLL注射器Dlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CDLL注射器Dlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CDLL注射器Dlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CDLL注射器Dlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDOK, &CDLL注射器Dlg::OnBnClickedOk)
	ON_BN_CLICKED(IDCANCEL, &CDLL注射器Dlg::OnBnClickedCancel)
END_MESSAGE_MAP()


// CDLL注射器Dlg 消息处理程序

BOOL CDLL注射器Dlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO:  在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CDLL注射器Dlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CDLL注射器Dlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CDLL注射器Dlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CDLL注射器Dlg::OnBnClickedOk()
{
	CString szDllName;
	CString szProcessName;
	DWORD dwpid = 0;
	// TODO:  在此添加控件通知处理程序代码

//	char szDllName[MAX_PATH] = { 0 };
	//char *szProcessNameC;
	GetDlgItemText(IDC_EDIT1,szDllName);
	GetDlgItemText(IDC_EDIT2, szProcessName);

	
	DWORD dwNum = WideCharToMultiByte(CP_OEMCP, NULL, szProcessName, -1, NULL, NULL, 0, NULL);
	char *szProcessNameC = new char[dwNum];
	WideCharToMultiByte(CP_OEMCP, NULL, szProcessName, -1, szProcessNameC, dwNum, 0, NULL);
	
	DWORD dwNum1 = WideCharToMultiByte(CP_OEMCP, NULL, szDllName, -1, NULL, NULL, 0, NULL);
	char *szDllNameC = new char[dwNum1];
	WideCharToMultiByte(CP_OEMCP, NULL, szDllName, -1, szDllNameC, dwNum1, 0, NULL);
	//获取进程PID
	dwpid = GetProcId(szProcessNameC);


	//注入进程
	InjectDll(dwpid, szDllName);


}
DWORD CDLL注射器Dlg::GetProcId(char *szProcessName)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hSnapshot, &pe))
	{
		MessageBox((LPWSTR)pe.dwSize);
		return 0;
	}

	while (Process32Next(hSnapshot, &pe))
	{
		CString a = pe.szExeFile;
		DWORD dwNum2 = WideCharToMultiByte(CP_OEMCP, NULL, a, -1, NULL, NULL, 0, NULL);
		char *b = new char[dwNum2];
		WideCharToMultiByte(CP_OEMCP, NULL, a, -1, b, dwNum2, 0, NULL);
		if (!strcmp(szProcessName, b))
		{
			return pe.th32ProcessID;
		}
	}
	return 0;
}
VOID CDLL注射器Dlg::InjectDll(DWORD dwPid, CString szDllName)
{
	enableDebugPriv();
	if (dwPid == 0 || lstrlen(szDllName)==0)
	{
		return;
	}
	//打开目标进程
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, dwPid);
	if (hProcess ==NULL)
	{
		return;
	}
	//计算欲注入DLL文件完整路径的长度
	DWORD dwNum3 = WideCharToMultiByte(CP_OEMCP, NULL, szDllName, -1, NULL, NULL, 0, NULL);
	char *szProcessNameC = new char[dwNum3];
	WideCharToMultiByte(CP_OEMCP, NULL, szDllName, -1, szProcessNameC, dwNum3, 0, NULL);
	//int nDllLen = lstrlen(szDllName) + sizeof(CString);
	//在目标进程申请一块长度为nDllLen大小的内存
	LPVOID pDllAddr = VirtualAllocEx(hProcess, NULL, strlen(szProcessNameC), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (pDllAddr == NULL)
	{
		CloseHandle(hProcess);
		return;
	}
	//DWORD dwWriteNum = 0;
	//将欲注入DLL文件的完整路径写入在目标进程中申请的空间内
	WriteProcessMemory(hProcess, pDllAddr, szProcessNameC, strlen(szProcessNameC), NULL);
	//获得loadlibraryA()函数的地址
	HMODULE hModule = GetModuleHandle(L"kernel32.dll");
	LPVOID lpBaseAddress = (LPVOID)GetProcAddress(hModule, "LoadLibraryA");
	//FARPROC pFunAddr = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
	//创建远程线程
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpBaseAddress, pDllAddr, NULL, NULL);
	WaitForSingleObject(hThread,INFINITE);
	CloseHandle(hThread);
	CloseHandle(hProcess);
}
BOOL CDLL注射器Dlg::enableDebugPriv()
{
	HANDLE  hToken;
	LUID    sedebugnameValue;
	TOKEN_PRIVILEGES tkp;
	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)
		)
	{
		return false;
	}
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue))
	{
		CloseHandle(hToken);
		return false;
	}
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = sedebugnameValue;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL))
	{
		CloseHandle(hToken);
		return false;
	}
	return true;
}

void CDLL注射器Dlg::OnBnClickedCancel()
{
	// TODO:  在此添加控件通知处理程序代码
	CString szDllName;
	CString szProcessName;
	DWORD dwpid = 0;
	// TODO:  在此添加控件通知处理程序代码

	//	char szDllName[MAX_PATH] = { 0 };
	//char *szProcessNameC;
	GetDlgItemText(IDC_EDIT1, szDllName);
	GetDlgItemText(IDC_EDIT2, szProcessName);


	DWORD dwNum = WideCharToMultiByte(CP_OEMCP, NULL, szProcessName, -1, NULL, NULL, 0, NULL);
	char *szProcessNameC = new char[dwNum];
	WideCharToMultiByte(CP_OEMCP, NULL, szProcessName, -1, szProcessNameC, dwNum, 0, NULL);


	//获取进程PID
	dwpid = GetProcId(szProcessNameC);
	UnInjectDll(dwpid, szDllName);
	CDialogEx::OnCancel();
}
VOID CDLL注射器Dlg::UnInjectDll(DWORD dwpid, CString szDllName)
{
	CString a1 = szDllName;
	DWORD dwNum5 = WideCharToMultiByte(CP_OEMCP, NULL, a1, -1, NULL, NULL, 0, NULL);
	char *b1 = new char[dwNum5];
	WideCharToMultiByte(CP_OEMCP, NULL, a1, -1, b1, dwNum5, 0, NULL);
	if (dwpid == 0 || lstrlen(szDllName) == 0)
	{
		return;
	}
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,dwpid);
	MODULEENTRY32 me32;
	me32.dwSize = sizeof(me32);
	//查找匹配的进程名称
	BOOL bRet = Module32First(hSnap,&me32);
	while (bRet)
	{
		CString a = me32.szExePath;
		DWORD dwNum4 = WideCharToMultiByte(CP_OEMCP, NULL, a, -1, NULL, NULL, 0, NULL);
		char *b = new char[dwNum4];
		WideCharToMultiByte(CP_OEMCP, NULL, a, -1, b, dwNum4, 0, NULL);
		if (!strcmp(b, b1))
		{
			break;
		}
		bRet = Module32Next(hSnap,&me32);
	}
	CloseHandle(hSnap);
	char * pFunName = "FreeLibrary";
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwpid);
	if (hProcess == NULL)
	{
		return;
	}
	FARPROC pFunAddr = GetProcAddress(GetModuleHandle(L"kernel32.dll"),pFunName);
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pFunAddr,me32.hModule,0,NULL);
	WaitForSingleObject(hThread,INFINITE);
	CloseHandle(hThread);
	CloseHandle(hProcess);
}
