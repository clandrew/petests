// Patch.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <string>
#include <vector>
#include <Windows.h>
#include <assert.h>

class Executable
{
	std::vector<unsigned char> const* m_pSourceFileBytes;
	int m_size;
	std::vector<unsigned char> m_dosHeaderBytes;
	std::vector<unsigned char> m_ntHeaderBytes;

	struct Section
	{
		IMAGE_SECTION_HEADER* pSourceHeader;
		std::vector<unsigned char> Data;
	};
	std::vector<Section> m_sections;
	Section* m_pSingleTextSection;

public:

	bool LoadSections(std::vector<unsigned char> const* pSourceFileBytes)
	{
		m_pSourceFileBytes = pSourceFileBytes;
		m_size = m_pSourceFileBytes->size();

		IMAGE_DOS_HEADER* pDosHeader{};
		pDosHeader = (IMAGE_DOS_HEADER*)(pSourceFileBytes->data());
		if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			return false;
		}

		IMAGE_NT_HEADERS* pNTHeader{};
		pNTHeader = (IMAGE_NT_HEADERS*)((unsigned char*)(pDosHeader)+pDosHeader->e_lfanew);

		unsigned char* pSignature = (unsigned char*)(&(pNTHeader->Signature));
		if (pSignature[0] != 'P' || pSignature[1] != 'E' || pSignature[2] != 0 || pSignature[3] != 0)
		{
			return false;
		}

		assert((void*)&pNTHeader->Signature == pNTHeader);

		int sourceOffset = 0;

		for (int i = 0; i < pDosHeader->e_lfanew; ++i)
		{
			m_dosHeaderBytes.push_back((*pSourceFileBytes)[sourceOffset]);
			sourceOffset++;
		}

		for (int i = 0; i < sizeof(IMAGE_NT_HEADERS); ++i)
		{
			m_ntHeaderBytes.push_back((*pSourceFileBytes)[sourceOffset]);
			sourceOffset++;
		}

		int numberOfSections = pNTHeader->FileHeader.NumberOfSections;
		m_sections.resize(numberOfSections);

		unsigned char* pStartOfSectionHeaders = pSignature + sizeof(IMAGE_NT_HEADERS);
		unsigned char* pSectionHeader = pStartOfSectionHeaders;
		for (int i = 0; i < numberOfSections; ++i)
		{
			m_sections[i].pSourceHeader = (IMAGE_SECTION_HEADER*)pSectionHeader;
			pSectionHeader += sizeof(IMAGE_SECTION_HEADER);

			int sectionSize = m_sections[i].pSourceHeader->SizeOfRawData;
			m_sections[i].Data.resize(sectionSize);
			std::fill(m_sections[i].Data.begin(), m_sections[i].Data.end(), 0);
			unsigned char const* pStartOfSectionData = pSourceFileBytes->data() + m_sections[i].pSourceHeader->PointerToRawData;
			for (int j = 0; j < sectionSize; ++j)
			{
				m_sections[i].Data[j] = *(pStartOfSectionData + j);
			}

			if (strcmp((char*)m_sections[i].pSourceHeader->Name, ".text") == 0)
			{
				if (!m_pSingleTextSection)
				{
					m_pSingleTextSection = &m_sections[i];
				}
				else
				{
					m_pSingleTextSection = nullptr; // Multiple text sections. Ambiguous
				}
			}
		}

		// Assert sections are in order
		for (int i = 0; i < numberOfSections - 1; ++i)
		{
			assert(m_sections[i].pSourceHeader->PointerToRawData < m_sections[i + 1].pSourceHeader->PointerToRawData);
		}

		return true;
	}

	bool ExpandText(int amountToExpandBy)
	{
		// Do expansion
		for (int i = 0; i < amountToExpandBy; ++i)
		{
			m_pSingleTextSection->Data.push_back(0);
		}

		m_size += amountToExpandBy;
		return true;
	}

	std::vector<unsigned char> SaveSections()
	{
		std::vector<unsigned char> destFileBytes;
		destFileBytes.resize(m_size);

		int destOffset = 0;

		memcpy(destFileBytes.data() + destOffset, m_dosHeaderBytes.data(), m_dosHeaderBytes.size());
		destOffset += m_dosHeaderBytes.size();

		memcpy(destFileBytes.data() + destOffset, m_ntHeaderBytes.data(), m_ntHeaderBytes.size());
		destOffset += m_ntHeaderBytes.size();

		for (int i = 0; i < m_sections.size(); ++i)
		{
			memcpy(destFileBytes.data() + destOffset, m_sections[i].pSourceHeader, sizeof(IMAGE_SECTION_HEADER));
			destOffset += sizeof(IMAGE_SECTION_HEADER);
		}

		for (int i = 0; i < m_sections.size(); ++i)
		{
			destOffset = m_sections[i].pSourceHeader->PointerToRawData;
			memcpy(destFileBytes.data() + destOffset, m_sections[i].Data.data(), m_sections[i].Data.size());
		}

		return destFileBytes;
	}
};

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

	Executable e;
	e.LoadSections(&sourceFileBytes);
	e.ExpandText(1000);


	std::vector<unsigned char> destFileBytes = e.SaveSections();

	// Dump the result
	std::string destPath = "D:\\repos\\PETests\\HelloWorld\\Release\\HelloWorld2.exe";

	{
		FILE* pFile;
		fopen_s(&pFile, destPath.c_str(), "wb");
		fwrite(destFileBytes.data(), 1, destFileBytes.size(), pFile);		
		fclose(pFile);
	}
}
