#ifndef __ILHOOK_H__F47BF581_8D85_49ef_923D_895DCC9E4471_
#define __ILHOOK_H__F47BF581_8D85_49ef_923D_895DCC9E4471_

#include <Windows.h>

class CILHook
{
public:
	CILHook();      // 构造
	~CILHook();     // 析构

	// HOOK函数
	BOOL Hook(LPCWSTR pszModuleName, LPSTR pszFuncName, PROC pfnHookFunc);
	// 取消HOOK函数
	VOID UnHook();
	// 重新进行HOOK函数
	BOOL ReHook();

private:
	PROC m_pfnOrig; // 函数地址
	BYTE m_bOldBytes[7];    // 函数入口代码
	BYTE bJmpCode[7];    // Inline代码
};

#endif