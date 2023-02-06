// Patch.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <string>
#include <vector>
#include <Windows.h>
#include <assert.h>

std::vector<unsigned char> ExpandText(std::vector<unsigned char> const& sourceFileBytes)
{
	std::vector<unsigned char> destFileBytes;

	IMAGE_DOS_HEADER* pDosHeader{};
	pDosHeader = (IMAGE_DOS_HEADER*)(sourceFileBytes.data());
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return destFileBytes;
	}

	IMAGE_NT_HEADERS* pNTHeader{};
	pNTHeader = (IMAGE_NT_HEADERS*)((unsigned char*)(pDosHeader)+pDosHeader->e_lfanew);

	unsigned char* pSignature = (unsigned char*)(&(pNTHeader->Signature));
	if (pSignature[0] != 'P' || pSignature[1] != 'E' || pSignature[2] != 0 || pSignature[3] != 0)
	{
		return destFileBytes;
	}

	assert((void*)&pNTHeader->Signature == pNTHeader);

	int sourceOffset = 0;

	// Rip DOS info
	std::vector<unsigned char> dosHeaderBytes;
	std::fill(dosHeaderBytes.begin(), dosHeaderBytes.end(), 0);
	for (int i = 0; i < pDosHeader->e_lfanew; ++i)
	{
		dosHeaderBytes.push_back(sourceFileBytes[sourceOffset]);
		sourceOffset++;
	}

	// Rip NT info
	std::vector<unsigned char> ntHeaderBytes;
	std::fill(ntHeaderBytes.begin(), ntHeaderBytes.end(), 0);
	for (int i = 0; i < sizeof(IMAGE_NT_HEADERS); ++i)
	{
		ntHeaderBytes.push_back(sourceFileBytes[sourceOffset]);
		sourceOffset++;
	}

	struct Section
	{
		IMAGE_SECTION_HEADER* pSourceHeader;
		std::vector<unsigned char> Data;
	};

	std::vector<Section> sections;
	int numberOfSections = pNTHeader->FileHeader.NumberOfSections;
	sections.resize(numberOfSections);

	Section* pFirstTextSection = nullptr;
	unsigned char* pStartOfSectionHeaders = pSignature + sizeof(IMAGE_NT_HEADERS);
	unsigned char* pSectionHeader = pStartOfSectionHeaders;
	for (int i = 0; i < numberOfSections; ++i)
	{
		sections[i].pSourceHeader = (IMAGE_SECTION_HEADER*)pSectionHeader;
		pSectionHeader += sizeof(IMAGE_SECTION_HEADER);

		if (!pFirstTextSection && strcmp((char*)sections[i].pSourceHeader->Name, ".text") == 0)
		{
			pFirstTextSection = &sections[i];
		}

		int sectionSize = sections[i].pSourceHeader->SizeOfRawData;
		sections[i].Data.resize(sectionSize);
		std::fill(sections[i].Data.begin(), sections[i].Data.end(), 0);
		unsigned char const* pStartOfSectionData = sourceFileBytes.data() + sections[i].pSourceHeader->PointerToRawData;
		for (int j = 0; j < sectionSize; ++j)
		{
			sections[i].Data[j] = *(pStartOfSectionData + j);
		}
	}

	// Assert sections are in order
	for (int i = 0; i < numberOfSections - 1; ++i)
	{
		assert(sections[i].pSourceHeader->PointerToRawData < sections[i + 1].pSourceHeader->PointerToRawData);
	}

	// Do expansion
	int extraSize = 1000;
	for (int i = 0; i < extraSize; ++i)
	{
		pFirstTextSection->Data.push_back(0);
	}

	int targetSize = sourceFileBytes.size() + extraSize;
	destFileBytes.resize(targetSize);
	std::fill(destFileBytes.begin(), destFileBytes.end(), 0);

	// Expand the first text section


	{
		int destOffset = 0;

		memcpy(destFileBytes.data() + destOffset, dosHeaderBytes.data(), dosHeaderBytes.size());
		destOffset += dosHeaderBytes.size();

		memcpy(destFileBytes.data() + destOffset, ntHeaderBytes.data(), ntHeaderBytes.size());
		destOffset += ntHeaderBytes.size();

		for (int i = 0; i < sections.size(); ++i)
		{
			memcpy(destFileBytes.data() + destOffset, sections[i].pSourceHeader, sizeof(IMAGE_SECTION_HEADER));
			destOffset += sizeof(IMAGE_SECTION_HEADER);
		}

		for (int i = 0; i < sections.size(); ++i)
		{
			destOffset = sections[i].pSourceHeader->PointerToRawData;
			memcpy(destFileBytes.data() + destOffset, sections[i].Data.data(), sections[i].Data.size());
		}
	}

	return destFileBytes;
}

int main()
{
	// Open the source exe
	std::string sourcePath = "D:\\repos\\PETests\\HelloWorld\\Release\\HelloWorld.exe";
	std::vector<unsigned char> sourceFileBytes;
	{
		FILE* pFile;
		fopen_s(&pFile, sourcePath.c_str(), "rb");
		fseek(pFile, 0, SEEK_END);
		long fileSize = ftell(pFile);
		fseek(pFile, 0, SEEK_SET);
		sourceFileBytes.resize(fileSize);
		fread(sourceFileBytes.data(), 1, fileSize, pFile);
		fclose(pFile);
	}

	std::vector<unsigned char> destFileBytes = ExpandText(sourceFileBytes);
	if (destFileBytes.size() == 0)
	{
		return -1;
	}

	// Dump the result file
	std::string destPath = "D:\\repos\\PETests\\HelloWorld\\Release\\HelloWorld2.exe";

	{
		FILE* pFile;
		fopen_s(&pFile, destPath.c_str(), "wb");

		fwrite(destFileBytes.data(), 1, destFileBytes.size(), pFile);
		
		fclose(pFile);
	}
}
