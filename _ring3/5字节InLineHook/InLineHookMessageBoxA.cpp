// InLineHookMessageBoxA.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include<windows.h>
#include "ILHook.h"

CILHook MsgHook;

int WINAPI MyMessageBoxA(HWND hWnd,LPCSTR lpText,LPCSTR lpCaption,UINT uType)
{
	MsgHook.UnHook();
	MessageBoxA(hWnd,"Hook流程",lpCaption,uType);
	MessageBoxA(hWnd, lpText, lpCaption, uType);
	MsgHook.ReHook();
	return 0;
}
int main(int argc, char* argv[])
{
	MessageBoxA(NULL,"正常流程1","test",MB_OK);
	MsgHook.Hook(L"User32.dll","MessageBoxA",(PROC)MyMessageBoxA);
	MessageBoxA(NULL,"被HOOK了1","test",MB_OK);
	MessageBoxA(NULL,"被HOOK了2","test",MB_OK);
	MsgHook.UnHook();
	MessageBoxA(NULL, "正常流程2", "test", MB_OK);
	return 0;
}

