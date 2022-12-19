// Patch.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <string>
#include <vector>
#include <Windows.h>

int SeekInTextSection(IMAGE_SECTION_HEADER* pTextSectionHeader, unsigned char* pTextSection, unsigned char const* seekPattern, int seekPatternLength)
{
	int matchesFound = 0;
	int matchIndex = -1;
	for (int i = 0; i < pTextSectionHeader->SizeOfRawData - seekPatternLength + 1; ++i)
	{
		bool matchFound = true;
		for (int j = 0; j < seekPatternLength; ++j)
		{
			if (pTextSection[i + j] != seekPattern[j])
			{
				matchFound = false;
				break;
			}
		}
		if (matchFound)
		{
			matchesFound++;
			matchIndex = i;
		}
	}

	if (matchesFound != 1)
	{
		return -1;
	}

	return matchIndex;
}

bool ChangeIterationCount(IMAGE_SECTION_HEADER* pTextSectionHeader, unsigned char* pTextSection)
{
	// Look for
	// 46				inc		esi
	// 83 FE 0A			cmp		esi, 0Ah
	int matchesFound = 0;
	for (int i = 0; i < pTextSectionHeader->SizeOfRawData - 3; ++i)
	{
		if (pTextSection[i] == 0x46 && pTextSection[i + 1] == 0x83 && pTextSection[i + 2] == 0xFE && pTextSection[i + 3] == 0x0A)
		{
			pTextSection[i + 3] = 0x10;
			matchesFound++;
		}
	}

	if (matchesFound != 1)
	{
		return false;
	}

	return true;
}

int main()
{
	// Open the source exe
	std::string sourcePath = "D:\\repos\\PETests\\HelloWorld\\Release\\HelloWorld.exe";
	std::vector<unsigned char> peFileBytes;
	{
		FILE* pFile;
		fopen_s(&pFile, sourcePath.c_str(), "rb");
		fseek(pFile, 0, SEEK_END);
		long fileSize = ftell(pFile);
		fseek(pFile, 0, SEEK_SET);
		peFileBytes.resize(fileSize);
		fread(peFileBytes.data(), 1, fileSize, pFile);
		fclose(pFile);
	}

	// Look up .text
	IMAGE_DOS_HEADER* pDosHeader{};
	pDosHeader = (IMAGE_DOS_HEADER*)(peFileBytes.data());
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return -1;
	}

	IMAGE_NT_HEADERS* pNTHeader{};
	pNTHeader = (IMAGE_NT_HEADERS*)((unsigned char*)(pDosHeader) +pDosHeader->e_lfanew);

	unsigned char* pSignature = (unsigned char*)(&(pNTHeader->Signature));
	if (pSignature[0] != 'P' || pSignature[1] != 'E' || pSignature[2] != 0 || pSignature[3] != 0)
	{
		return -1;
	}

	int numberOfSections = pNTHeader->FileHeader.NumberOfSections;
	int sizeOfCode = pNTHeader->OptionalHeader.SizeOfCode;
	int entrypoint = pNTHeader->OptionalHeader.AddressOfEntryPoint;

	std::vector<IMAGE_SECTION_HEADER*> sectionHeaders;
	unsigned char* pSectionHeader = pSignature + sizeof(IMAGE_NT_HEADERS);
	for (int i = 0; i < numberOfSections; ++i)
	{
		sectionHeaders.push_back((IMAGE_SECTION_HEADER*)pSectionHeader);
		pSectionHeader += sizeof(IMAGE_SECTION_HEADER);
	}

	IMAGE_SECTION_HEADER* pTextSectionHeader{};
	unsigned char* pTextSection = nullptr;
	for (int i = 0; i < numberOfSections; ++i)
	{
		unsigned char* pName = sectionHeaders[i]->Name;
		if (pName[0] == '.' && pName[1] == 't' && pName[2] == 'e' && pName[3] == 'x' && pName[4] == 't' && pName[5] == 0 && pName[6] == 0 && pName[7] == 0)
		{
			if (pTextSection)
			{
				return -1;
			}
			pTextSectionHeader = sectionHeaders[i];
			pTextSection = peFileBytes.data() + sectionHeaders[i]->PointerToRawData;
			break;
		}
	}

	if (!pTextSection)
	{
		return -1;
	}

	bool result = true;

	// Insert an extra call into the iteration body
	// These call-relatives are cout:
	// 00A31013 E8 18 01 00 00       call        std::operator<<<std::char_traits<char> > (0A31130h) 
	// 00A31044 E8 E7 00 00 00       call        std::operator<<<std::char_traits<char> > (0A31130h)
	// 00A3105A E8 D1 00 00 00       call        std::operator<<<std::char_traits<char> > (0A31130h)

	// Look for empty space to jump out
	// First, look for this pattern
	// 002B105A E8 D1 00 00 00       call        std::operator<<<std::char_traits<char> > (02B1130h)
	// 002B105F 33 C0 xor eax, eax
	// 002B1061 5E                   pop         esi
	// 002B1062 8B E5                mov         esp, ebp
	// 002B1064 5D                   pop         ebp
	// 002B1065 C3                   ret
	const unsigned char seekPattern[] = {0xE8, 0xD1, 0x00, 0x00, 0x00, 0x33, 0xC0, 0x5E, 0x8B, 0xE5, 0x5D, 0xC3};
	int matchIndex = SeekInTextSection(pTextSectionHeader, pTextSection, seekPattern, _countof(seekPattern));

	if (!result)
	{
		return -1;
	}

	std::string destPath = "D:\\repos\\PETests\\HelloWorld\\Release\\HelloWorld2.exe";

	{
		FILE* pFile;
		fopen_s(&pFile, destPath.c_str(), "wb");
		fwrite(peFileBytes.data(), 1, peFileBytes.size(), pFile);
		fclose(pFile);
	}
}
