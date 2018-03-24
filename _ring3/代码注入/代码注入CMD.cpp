// 代码注入CMD.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "afxdialogex.h"
#include <windows.h>
#include <TlHelp32.h>
#include <afxpriv.h>
//MessageBox的参数结构体
typedef struct _REMOTE_PARAMETER
{
	CHAR m_msgContent[MAX_PATH];
	CHAR m_msgTitle[MAX_PATH];
	DWORD m_dwMessageBoxAddr;

}RemotePara, *PRemotePara;

DWORD WINAPI RemoteThreadProc(PRemotePara pRemotePara)
{
    //这个 MessageBox 的地址必须由外部参数传入，因为在其他进程中需要重定向
typedef int (WINAPI *MESSAGEBOXA)(HWND, LPCSTR, LPCSTR, UINT);

 MESSAGEBOXA MessageBoxA;
    MessageBoxA = (MESSAGEBOXA)pRemotePara->m_dwMessageBoxAddr;

   //调用 MessageBoxA 来打印消息
 MessageBoxA(NULL, pRemotePara->m_msgContent, pRemotePara->m_msgTitle, MB_OK);

 return 0;
 }
//ring3层提权代码
BOOL enableDebugPriv()
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

//获取MessageBox的参数
void GetMessageBoxParameter(PRemotePara pRemotePara)
 {
    HMODULE hUser32 = LoadLibrary(L"User32.dll");

	pRemotePara->m_dwMessageBoxAddr = (DWORD)GetProcAddress(hUser32, "MessageBoxA");
    strcat_s(pRemotePara->m_msgContent, "Hello,x-encounter !\0");
    strcat_s(pRemotePara->m_msgTitle, "Hello\0");

   //注意要释放掉 User32
    FreeLibrary(hUser32);
}

int _tmain(int argc, _TCHAR* argv[])
{
	DWORD THREAD_SIZE  = 0x4000;
	enableDebugPriv();
	//注入目标进程的PID，可以通过tasklist查看，当然你也可以写一个进程枚举函数
	DWORD dwPid = 1000;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, dwPid);
	if (hProcess == NULL)
	{
		return -1;
	}
	//为注入函数分配空间，并写入进程
	PVOID pRemoteThread = VirtualAllocEx(hProcess, NULL, THREAD_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(hProcess, pRemoteThread, &RemoteThreadProc, THREAD_SIZE, NULL);
	
	//MessageBox参数结构体的初始化
	RemotePara remotePara;
	ZeroMemory(&remotePara, sizeof(RemotePara));
	GetMessageBoxParameter(&remotePara);


	//为参数分配空间，并写入进程
	PRemotePara pRemotePara = (PRemotePara)VirtualAllocEx(hProcess, NULL, sizeof(RemotePara), MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(hProcess, pRemotePara, &remotePara, sizeof(RemotePara), 0);


	HANDLE hThread;
	DWORD dwThreadId;
	hThread = NULL;
	dwThreadId = 0;
	hThread = CreateRemoteThread(hProcess, NULL, 0, (DWORD(WINAPI *)(LPVOID))pRemoteThread, pRemotePara, 0, &dwThreadId);
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	VirtualFreeEx(hProcess, pRemoteThread, 0, MEM_RELEASE);
	VirtualFreeEx(hProcess, pRemotePara, 0, MEM_RELEASE);
	CloseHandle(hProcess);
	return 0;
}

