// Patch.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <string>
#include <vector>
#include <fstream>
#include <Windows.h>
#include <assert.h>

class Executable
{
	std::vector<unsigned char> const* m_pSourceFileBytes;
	int m_size;
	std::vector<unsigned char> m_dosHeaderBytes;
	std::vector<unsigned char> m_ntHeaderBytes;
	int m_fileAlignment;

	struct Section
	{
		IMAGE_SECTION_HEADER* pSourceHeader;
		std::vector<unsigned char> Data;
	};
	std::vector<Section> m_sections;
	Section* m_pTextSection;
	Section* m_pRelocSection;

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

		m_fileAlignment = pNTHeader->OptionalHeader.FileAlignment;

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

			m_pTextSection = nullptr;
			m_pRelocSection = nullptr;
			if (strcmp((char*)m_sections[i].pSourceHeader->Name, ".text") == 0)
			{
				if (!m_pTextSection)
				{
					m_pTextSection = &m_sections[i];
				}
				else
				{
					m_pTextSection = nullptr; // Multiple text sections. Ambiguous
				}
			}

			if (strcmp((char*)m_sections[i].pSourceHeader->Name, ".reloc") == 0)
			{
				if (!m_pRelocSection)
				{
					m_pRelocSection = &m_sections[i];
				}
				else
				{
					m_pRelocSection = nullptr; 
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

	void DumpSectionHeaderInfoToTextFile(char const* pDestFilename)
	{
		std::ofstream strm(pDestFilename);
		for (int i = 0; i < m_sections.size(); ++i)
		{
			strm << "Section #" << i << "\n";
			strm << "\tName: " << m_sections[i].pSourceHeader->Name << "\n";

			// Since this is an executable, we pay attention to VirtualSize not PhysicalAddress.
			strm << "\tVirtualSize: " << std::hex << "0x" << m_sections[i].pSourceHeader->Misc.VirtualSize << "\n";
			
			strm << "\tVirtualAddress: " << std::hex << "0x" << m_sections[i].pSourceHeader->VirtualAddress << "\n";
			strm << "\tSizeOfRawData: " << m_sections[i].pSourceHeader->SizeOfRawData << "\n";
			strm << "\tPointerToRawData: " << std::hex << "0x" << m_sections[i].pSourceHeader->PointerToRawData << "\n";
			strm << "\tPointerToRelocations: " << std::hex << "0x" << m_sections[i].pSourceHeader->PointerToRelocations << "\n";
			strm << "\tPointerToLinenumbers: " << m_sections[i].pSourceHeader->PointerToLinenumbers << "\n";
			strm << "\tNumberOfRelocations: " << m_sections[i].pSourceHeader->NumberOfRelocations << "\n";
			strm << "\tNumberOfLinenumbers: " << m_sections[i].pSourceHeader->NumberOfLinenumbers << "\n";
			strm << "\tCharacteristics: " << std::hex << "0x" << m_sections[i].pSourceHeader->Characteristics << "\n";
			strm << "\n";
		}
	}

	void DumpText(char const* pDestFilename)
	{
		FILE* pFile;
		fopen_s(&pFile, pDestFilename, "wb");
		fwrite(m_pTextSection->Data.data(), 1, m_pTextSection->Data.size(), pFile);
		fclose(pFile);
	}

	void DumpReloc(char const* pDestFilename)
	{
		FILE* pFile;
		fopen_s(&pFile, pDestFilename, "wb");
		fwrite(m_pRelocSection->Data.data(), 1, m_pRelocSection->Data.size(), pFile);
		fclose(pFile);
	}

	// Returns a pointer to the expanded space, valid if code is not expanded again
	unsigned char* ExpandText(int amountToExpandBy)
	{
		if (amountToExpandBy == 0)
		{
			return nullptr;
		}

		unsigned char* pOriginalRegion = m_pTextSection->Data.data();

		// Do expansion
		for (int i = 0; i < amountToExpandBy; ++i)
		{
			m_pTextSection->Data.push_back(0);
		}

		// This assumes that the text section is the first one.
		assert(m_pTextSection == &m_sections[0]);

		// Update header of the first section (the text section) and subsequent ones
		m_sections[0].pSourceHeader->Misc.VirtualSize += amountToExpandBy; // Unaligned

		int alignedSize = m_sections[0].pSourceHeader->Misc.VirtualSize;

		alignedSize = ((alignedSize + 0x200) / 0x200) * 0x200;
		int shiftAmount = alignedSize - m_sections[0].pSourceHeader->SizeOfRawData;
		m_sections[0].pSourceHeader->SizeOfRawData = alignedSize;

		// Move pointers of all subsequent sections forward
		for (int i = 1; i < m_sections.size(); ++i)
		{
			m_sections[i].pSourceHeader->PointerToRawData += shiftAmount;
		}

		m_size += amountToExpandBy;

		unsigned char* pExpandedRegion = m_pTextSection->Data.data() + m_pTextSection->Data.size() - amountToExpandBy;

		return pExpandedRegion;
	}

	void WipeReloc()
	{
		for (int i = 0; i < m_pRelocSection->Data.size(); ++i)
		{
			m_pRelocSection->Data[i] = 0;
		}
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

	//e.DumpText("text.bin");
	//e.DumpReloc("reloc.bin");

	/*unsigned char* pSpace = e.ExpandText(0x200);
	for (int i = 0; i < 0x200; ++i)
	{
		pSpace[i] = 0xCC; // fill with breaks
	}
	pSpace[0] = 0x90; // NOP

	// 8B 0D 50 30 4E 00    mov         ecx,dword ptr [__imp_std::cout (04E3050h)]
	pSpace[0] = 0x8B;
	pSpace[1] = 0x0D; 
	pSpace[2] = 0x50;
	pSpace[3] = 0x30; 
	pSpace[4] = 0x4E;
	pSpace[5] = 0x00; 

	// BA 20 31 4E 00       mov         edx,offset string "Hello World!\n" (04E3120h)  
	pSpace[6] = 0xBA;
	pSpace[7] = 0x20;
	pSpace[8] = 0x31;
	pSpace[9] = 0x4E;
	pSpace[10] = 0x00;
	
	// 56                   push        esi  
	pSpace[11] = 0x56;

	// E8 18 01 00 00       call        std::operator<<<std::char_traits<char> > (04E1130h) 
	pSpace[12] = 0xE8;
	pSpace[13] = 0x18;
	pSpace[14] = 0x01;
	pSpace[15] = 0x00;
	pSpace[16] = 0x00;*/

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
