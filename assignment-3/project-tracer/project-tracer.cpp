// RunETW.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <stdio.h>
#include <tdh.h>
#include <vector>
#include <assert.h>
#include <memory>
#include <atltime.h>
#include <in6addr.h>
#include <time.h>
#include <locale.h>
#include <string>
#include <map>
#include <comdef.h>
#include <iostream>
#include <set>
#include <tlhelp32.h>

#include "stdafx.h"

#pragma comment(lib, "tdh")

#define PRINT_ALL false

int Run();
bool RunSession(const std::vector<GUID>& providers, PCWSTR filename, bool realTime);
void CALLBACK OnEvent(PEVENT_RECORD rec);
void DisplayGeneralEventInfo(PEVENT_RECORD rec);
void DisplayEventInfo(PEVENT_RECORD rec, PTRACE_EVENT_INFO info);
void DisplayPowerShellEventInfo(PEVENT_RECORD rec, PWSTR cmd);
void DisplayRansomwareEventInfo(PEVENT_RECORD rec, std::wstring path);
void WriteTimeInSharedMemory(CTimeSpan time_);

void GetSharedMemoryHandle(int argc, const wchar_t* argv[]);
void PrintInfo();
void PrintLine();
void DisplaySuspiciousEventInfo(PEVENT_RECORD rec);
void ColorPrint(PCWSTR str, PCWSTR color);
int ProcessIdToName(DWORD processId, LPWSTR buffer, DWORD buffSize);
int base64_decode(char* text, unsigned char* dst, int numBytes);
DWORD getppid(DWORD pid);
int PidDfs(DWORD pid, int count);

HANDLE g_hStop;

wil::unique_handle m_hSharedMem;
std::map< std::pair<int, int>, void*> chkId;
std::map< std::wstring, std::set< std::wstring> > countPath;

/*------ Base64 Decoding Table ------*/
static int DecodeMimeBase64[256] = {
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 00-0F */
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 10-1F */
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,  /* 20-2F */
	52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,  /* 30-3F */
	-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,  /* 40-4F */
	15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,  /* 50-5F */
	-1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,  /* 60-6F */
	41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,  /* 70-7F */
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 80-8F */
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 90-9F */
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* A0-AF */
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* B0-BF */
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* C0-CF */
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* D0-DF */
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* E0-EF */
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1   /* F0-FF */
};

std::vector<GUID> GetProviders(std::vector<PCWSTR> names) {
	std::vector<GUID> providers;
	providers.reserve(names.size());

	auto count = names.size();
	for(size_t i = 0; i < count; i++) {
		auto name = names[i];
		if(name[0] == L'{') {	// GUID rather than name
			GUID guid;
			if(S_OK == ::CLSIDFromString(name, &guid)) {
				providers.push_back(guid);
				names.erase(names.begin() + i);
				i--;
				count--;
			}
		}
	}

	if(names.empty())
		return providers;

	ULONG size = 0;
	auto error = ::TdhEnumerateProviders(nullptr, &size);
	assert(error == ERROR_INSUFFICIENT_BUFFER);

	// allocate with the required size
	auto buffer = std::make_unique<BYTE[]>(size);
	if(!buffer)
		return providers;

	auto data = reinterpret_cast<PROVIDER_ENUMERATION_INFO*>(buffer.get());
	// second call
	error = ::TdhEnumerateProviders(data, &size);
	assert(error == ERROR_SUCCESS);
	if(error != ERROR_SUCCESS)
		return providers;

	int found = 0;
	for(ULONG i = 0; i < data->NumberOfProviders && found < names.size(); i++) {
		const auto& item = data->TraceProviderInfoArray[i];
		auto name = (PCWSTR)(buffer.get() + item.ProviderNameOffset);
		for(auto n : names) {
			if(_wcsicmp(name, n) == 0) {
				providers.push_back(item.ProviderGuid);
				found++;
				break;
			}
		}
	}

	return providers;
}

int Run() {
	PCWSTR filename = nullptr;
	bool realTime = false;

	std::vector<PCWSTR> names;

	//filename = L"result.etl";								// 저장할 파일 이름
	realTime = true;										// -r 옵션

	// provider 종류
//	names.push_back(L"Microsoft-Windows-Kernel-File");
	names.push_back(L"Microsoft-Windows-FileInfoMinifilter");
//	names.push_back(L"Microsoft-Windows-FileServices-ServerManager-EventProvider");
//	names.push_back(L"Microsoft-Windows-FileShareShadowCopyProvider");
//	names.push_back(L"Microsoft-Windows-Kernel-Network");
	names.push_back(L"Microsoft-Windows-PowerShell");
//	names.push_back(L"Microsoft-Windows-DNS-Client");


	auto providers = GetProviders(names);
	if(providers.size() < names.size()) {
		wprintf(L"Not all providers found");
		return 1;
	}

	if(!RunSession(providers, filename, realTime)) {
		wprintf(L"Failed to run session\n");
		return 1;
	}

	return 0;
}

bool RunSession(const std::vector<GUID>& providers, PCWSTR filename, bool realTime) {
	// {CE9FA182-A0CC-4BEE-ACFB-F570E6744AAF}
	static const GUID sessionGuid =
	{ 0xce9fa182, 0xa0cc, 0x4bee, { 0xac, 0xfb, 0xf5, 0x70, 0xe6, 0x74, 0x4a, 0xaf } };

	const WCHAR sessionName[] = L"LeeYuseop";

	auto size = sizeof(EVENT_TRACE_PROPERTIES)
		+ (filename ? ((::wcslen(filename) + 1) * sizeof(WCHAR)) : 0)
		+ sizeof(sessionName);

	auto buffer = std::make_unique<BYTE[]>(size);
	if(!buffer)
		return false;

	auto props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.get());
	DWORD status;
	TRACEHANDLE hTrace = 0;

	do {
		::ZeroMemory(buffer.get(), size);

		props->Wnode.BufferSize = (ULONG)size;
		props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
		props->Wnode.ClientContext = 1;	// QueryPerformanceCounter
		props->Wnode.Guid = sessionGuid;
		props->LogFileMode = (filename ? EVENT_TRACE_FILE_MODE_SEQUENTIAL : 0) | (realTime ? EVENT_TRACE_REAL_TIME_MODE : 0);
		props->MaximumFileSize = 1000;	// 1000 MB
		props->LoggerNameOffset = sizeof(*props);
		props->LogFileNameOffset = filename ? sizeof(*props) + sizeof(sessionName) : 0;

		// copy session name
		::wcscpy_s((PWSTR)(props + 1), ::wcslen(sessionName) + 1, sessionName);

		// copy filename
		if(filename)
			::wcscpy_s((PWSTR)(buffer.get() + sizeof(*props) + sizeof(sessionName)), ::wcslen(filename) + 1, filename);

		status = ::StartTrace(&hTrace, sessionName, props);
		if(status == ERROR_ALREADY_EXISTS) {
			status = ::ControlTrace(hTrace, sessionName, props, EVENT_TRACE_CONTROL_STOP);
			continue;
		}
		break;
	} while(true);

	if(ERROR_SUCCESS != status)
		return false;

	TRACEHANDLE hParse = 0;
	HANDLE hThread = nullptr;

	if(realTime) {
		g_hStop = ::CreateEvent(nullptr, TRUE, FALSE, nullptr);

		EVENT_TRACE_LOGFILE etl{};
		etl.LoggerName = (PWSTR)sessionName;
		etl.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
		etl.EventRecordCallback = OnEvent;
		hParse = ::OpenTrace(&etl);
		if(hParse == INVALID_PROCESSTRACE_HANDLE) {
			wprintf(L"Failed to open a read-time session\n");
		}
		else {
			hThread = ::CreateThread(nullptr, 0, [](auto param) -> DWORD {
				FILETIME now;
				::GetSystemTimeAsFileTime(&now);
				::ProcessTrace(static_cast<TRACEHANDLE*>(param), 1, &now, nullptr);
				return 0;
				}, &hParse, 0, nullptr);

		}
	}

	for(auto& guid : providers) {
		status = ::EnableTraceEx(&guid, nullptr, hTrace, TRUE, 
			TRACE_LEVEL_VERBOSE, 0, 0, 
			EVENT_ENABLE_PROPERTY_STACK_TRACE, nullptr);
		if(ERROR_SUCCESS != status) {
			::StopTrace(hTrace, sessionName, props);
			return false;
		}
	}

	if(realTime) {
		::SetConsoleCtrlHandler([](auto code) {
			if(code == CTRL_C_EVENT) {
				::SetEvent(g_hStop);
				return TRUE;
			}
			return FALSE;
			}, TRUE);
		::WaitForSingleObject(g_hStop, INFINITE);
		::CloseTrace(hParse);
		::WaitForSingleObject(hThread, INFINITE);
		::CloseHandle(g_hStop);
		::CloseHandle(hThread);
	}
	else {
		wprintf(L"Session running... press ENTER to stop\n");

		char dummy[4];
		gets_s(dummy);
	}

	::StopTrace(hTrace, sessionName, props);

	return true;
}

void CALLBACK OnEvent(PEVENT_RECORD rec) {
	if(PRINT_ALL) DisplayGeneralEventInfo(rec);

	ULONG size = 0;
	auto status = ::TdhGetEventInformation(rec, 0, nullptr, nullptr, &size);
	assert(status == ERROR_INSUFFICIENT_BUFFER);

	auto buffer = std::make_unique<BYTE[]>(size);
	if(!buffer) {
		wprintf(L"Out of memory!\n");
		::ExitProcess(1);
	}

	auto info = reinterpret_cast<PTRACE_EVENT_INFO>(buffer.get());
	status = ::TdhGetEventInformation(rec, 0, nullptr, info, &size);
	if(status != ERROR_SUCCESS) {
		wprintf(L"Error processing event!\n");
		return;
	}

	DisplayEventInfo(rec, info);
}

int wmain(int argc, const wchar_t* argv[]) {
	// 프로그램 시작 시간 측정
	CTime startTime = CTime::GetCurrentTime();

	// 한글 설정
	setlocale(LC_ALL, "korean");
	_wsetlocale(LC_ALL, L"korean");

	// 공유 메모리 설정
	GetSharedMemoryHandle(argc, argv);

	PrintInfo();

	int res = Run();

	// 프로그램 종료 시간 측정
	CTime endTime = CTime::GetCurrentTime();

	// 공유 메모리에 프로그램 실행 시간 입력
	WriteTimeInSharedMemory(endTime - startTime);

	return 0;
}

// m_sharedMem 변수에 공유 메모리 설정을 해주는 함수
void GetSharedMemoryHandle(int argc, const wchar_t* argv[])
{
	if (argc == 1) {
		// 단독 실행 시 공유 메모리 생성
		m_hSharedMem.reset(::CreateFileMapping(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, 1 << 16, nullptr));
	}
	else {
		// launcher를 통해 실행 시, launcher에서 넘겨준 핸들 값으로 공유 메모리 설정
		m_hSharedMem.reset((HANDLE)(ULONG_PTR)::_wtoi(argv[argc - 1]));
	}
}

void DisplayEventInfo(PEVENT_RECORD rec, PTRACE_EVENT_INFO info) {
	if (PRINT_ALL) {
		if (info->KeywordsNameOffset)
			wprintf(L"Keywords: %ws ", (PCWSTR)((BYTE*)info + info->KeywordsNameOffset));
		if (info->OpcodeNameOffset)
			wprintf(L"Opcode: %ws ", (PCWSTR)((BYTE*)info + info->OpcodeNameOffset));
		if (info->LevelNameOffset)
			wprintf(L"Level: %ws ", (PCWSTR)((BYTE*)info + info->LevelNameOffset));
		if (info->TaskNameOffset)
			wprintf(L"Task: %ws ", (PCWSTR)((BYTE*)info + info->TaskNameOffset));
		if (info->EventMessageOffset)
			wprintf(L"\nMessage: %ws", (PCWSTR)((BYTE*)info + info->EventMessageOffset));

		wprintf(L"\nProperties: %u\n", info->TopLevelPropertyCount);
	}

	// properties data length and pointer
	auto userlen = rec->UserDataLength;
	auto data = (PBYTE)rec->UserData;

	auto pointerSize = (rec->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;
	ULONG len;
	WCHAR value[512000];

	for(DWORD i = 0; i < info->TopLevelPropertyCount; i++) {
		auto& pi = info->EventPropertyInfoArray[i];
		auto propName = (PCWSTR)((BYTE*)info + pi.NameOffset);
		if(PRINT_ALL) wprintf(L" Name: %ws ", propName);

		len = pi.length;
		if((pi.Flags & (PropertyStruct | PropertyParamCount)) == 0) {
			//
			// deal with simple properties only
			//
			PEVENT_MAP_INFO mapInfo = nullptr;
			std::unique_ptr<BYTE[]> mapBuffer;
			PWSTR mapName = nullptr;
			//
			// retrieve map information (if any)
			//
			if(pi.nonStructType.MapNameOffset) {
				ULONG size = 0;
				mapName = (PWSTR)((BYTE*)info + pi.nonStructType.MapNameOffset);
				if(ERROR_INSUFFICIENT_BUFFER == ::TdhGetEventMapInformation(rec, mapName, mapInfo, &size)) {
					mapBuffer = std::make_unique<BYTE[]>(size);
					mapInfo = reinterpret_cast<PEVENT_MAP_INFO>(mapBuffer.get());
					if(ERROR_SUCCESS != ::TdhGetEventMapInformation(rec, mapName, mapInfo, &size))
						mapInfo = nullptr;
				}
			}

			ULONG size = sizeof(value);
			USHORT consumed;
			// special case for IPv6 address
			if(pi.nonStructType.InType == TDH_INTYPE_BINARY && pi.nonStructType.OutType == TDH_OUTTYPE_IPV6)
				len = sizeof(IN6_ADDR);

			if(pi.Flags & PropertyParamLength) {
				// property length is stored elsewhere
				auto index = pi.lengthPropertyIndex;
				PROPERTY_DATA_DESCRIPTOR desc;
				desc.ArrayIndex = ULONG_MAX;
				desc.PropertyName = (ULONGLONG)propName;
				desc.Reserved = 0;
				::TdhGetPropertySize(rec, 0, nullptr, 1, &desc, &len);
			}

			auto error = ::TdhFormatProperty(info, mapInfo, pointerSize,
				pi.nonStructType.InType, pi.nonStructType.OutType,
				(USHORT)len, userlen, data, &size, value, &consumed);
			if(ERROR_SUCCESS == error) {
				if(PRINT_ALL) wprintf(L"Value: %ws", value);
				len = consumed;
				if(mapName)
					if(PRINT_ALL) wprintf(L" (%ws)", (PCWSTR)mapName);
				if(PRINT_ALL) wprintf(L"\n");
			}
			else if(mapInfo) {
				error = ::TdhFormatProperty(info, nullptr, pointerSize,
					pi.nonStructType.InType, pi.nonStructType.OutType,
					(USHORT)len, userlen, data, &size, value, &consumed);
				if(ERROR_SUCCESS == error)
					if(PRINT_ALL) wprintf(L"Value: %ws\n", value);
			}
			if (ERROR_SUCCESS != error) {
				lstrcpynW(value, (PWSTR)data, len);
				if(PRINT_ALL) wprintf(L"Value: %ws\n", value);
				//if (PRINT_ALL) wprintf(L"(failed to get value)\n");
			}

			// path 확인
			if (lstrcmpW(propName, L"Path") == 0) {
				PWSTR idx, tempIdx;
				for (idx = value + len - 1; *idx != L'\\'; idx--);

				if (tempIdx = wcsstr(value, L"Temp"));	// Temp 폴더
				else {
					// 경로와 파일명 추출
					*idx = L'\0';
					std::wstring path = value;
					std::wstring fileName = idx + 1;

					countPath[path].insert(fileName);

					// 특정 경로에서의 작업이 30번 이상 일어나면 ransomware 의심.
					if (countPath[path].size() == 30) {
						DisplayRansomwareEventInfo(rec, path);
					}
				}
			}

			// property name이 contextInfo의 경우 많은 정보를 가지고 있으므로 contextInfo인지 확인한다.
			if (lstrcmpW(propName, L"ContextInfo") == 0) {
				// "호스트 응용 프로그램 = " 뒷 부분의 문자열 가져오기
				PWSTR idx1, idx2;
				idx1 = wcsstr(value, L"호스트 응용 프로그램 =");
				idx1 = wcsstr(idx1, L"=");
				idx1 += 2;
				idx2 = wcsstr(idx1, L"\n");

				if (idx2 - idx1 > 1) {	// 의미 있는 정보를 얻었다면
					ULONG pid, tid;
					pid = rec->EventHeader.ProcessId;
					tid = 0;// rec->EventHeader.ThreadId;

					if (chkId.find({ pid,tid }) == chkId.end()) {
						chkId[{pid, tid}] = nullptr;

						WCHAR cmd[1000];
						wcsncpy_s(cmd, idx1, idx2 - idx1);

						DisplayPowerShellEventInfo(rec, cmd);
					}
				}
			}

		}
		else {
			if(PRINT_ALL) wprintf(L"(not a simple property)\n");
		}
		userlen -= (USHORT)len;
		data += len;
	}

	if(PRINT_ALL) wprintf(L"\n");
}

void DisplayGeneralEventInfo(PEVENT_RECORD rec) {
	WCHAR sguid[64];
	auto& header = rec->EventHeader;
	::StringFromGUID2(header.ProviderId, sguid, _countof(sguid));

	wprintf(L"Provider: %ws Time: %ws PID: %u TID: %u\n",
		sguid, (PCWSTR)CTime(*(FILETIME*)&header.TimeStamp).Format(L"%c"),
		header.ProcessId, header.ThreadId);
}

void PrintInfo()
{
	// 공유 메모리에서 이름과 학번 가져오기
	// 공유 메모리 읽기 권한으로 매핑
	void* buffer = ::MapViewOfFile(m_hSharedMem.get(), FILE_MAP_READ, 0, 0, 0);
	WCHAR name[100], studentID[100];

	if (!buffer) {	// 매핑 실패 시
		::wcscpy_s((PWSTR)name, 5, L"None\0");	// 이름 = None
		::wcscpy_s(studentID, 5, L"null\0");	// 학번 = null
	}
	else {
		// 공유 메모리 : "[Name]\0[Student ID]\0"
		int len1, len2;

		// 이름 저장
		for (len1 = 0; *((PCWSTR)buffer + len1) != L'\0'; len1++);
		if(len1 ==  0) ::wcscpy_s((PWSTR)name, 5, L"None\0");	// 이름이 없으면 None으로 설정
		else ::wcscpy_s((PWSTR)name, len1 + 1, (PCWSTR)buffer);

		// 학번 저장
		for (len2 = len1 + 1; *((PCWSTR)buffer + len2) != L'\0'; len2++);
		if(len2-len1-1 == 0) ::wcscpy_s(studentID, 5, L"null\0");					// 학번이 없으면 none으로 설정
		else ::wcscpy_s((PWSTR)studentID, len2 - len1, (PCWSTR)buffer + len1 + 1);
	}

	// 공유 메모리 매핑 해제
	::UnmapViewOfFile(buffer);

	// 정보 출력
	wprintf(L"╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋┏┓╋╋┏┓\n");
	wprintf(L"╋╋╋╋╋╋╋╋┏┓╋╋╋╋┏┛┗┓┏┛┗┓\n");
	wprintf(L"┏━━┳━┳━━╋╋━━┳━┻┓┏┛┗┓┏╋━┳━━┳━━┳━━┳━┓\n");
	wprintf(L"┃┏┓┃┏┫┏┓┣┫┃━┫┏━┫┣━━┫┃┃┏┫┏┓┃┏━┫┃━┫┏┛\n");
	wprintf(L"┃┗┛┃┃┃┗┛┃┃┃━┫┗━┫┗┳━┫┗┫┃┃┏┓┃┗━┫┃━┫┃\n");
	wprintf(L"┃┏━┻┛┗━━┫┣━━┻━━┻━┛╋┗━┻┛┗┛┗┻━━┻━━┻┛\n");
	wprintf(L"┃┃╋╋╋╋╋┏┛┃\n");
	wprintf(L"┗┛╋╋╋╋╋┗━┛\n");
	wprintf(L"\n");
	PrintLine();
	wprintf(L"Written by %s (%s)\n", name, studentID);
	wprintf(L"\n");
	wprintf(L"Description\n");
	wprintf(L"- 본 프로그램은 Ransomware 위험과 PowerShell 명령어를 통한 위험을 탐지하는 프로그램이다.\n");
	wprintf(L"- 특정 폴더에서 많은 파일들이 삭제되고 생성될 경우 해당 폴더에서 Ransomware를 의심한다.\n");
	wprintf(L"- PowerShell를 통해 실행되는 명령어를 잡아내며, 암호화된 명령어의 경우 복호화하여 보여준다.\n");
	wprintf(L"- 본 프로그램은 우리도 모르게 돌아가고 있는 컴퓨터의 취약점을 찾아주며, 추후 이를 보완하기 쉽도록 정보를 제공한다.\n");
	PrintLine();
	wprintf(L"\n");
}

void PrintLine()
{
	wprintf(L"-------------------------------------------------------\n");
}

void WriteTimeInSharedMemory(CTimeSpan time_)
{
	void* buffer = ::MapViewOfFile(m_hSharedMem.get(), FILE_MAP_WRITE, 0, 0, 0);
	if (!buffer) return;	// 공유 메모리 매핑 실패 시, return

	// 시간을 공유 메모리에 입력
	::wcscpy_s((PWSTR)buffer, 100, time_.Format(L"%H:%M:%S"));

	// 공유 메모리 매핑 해제
	::UnmapViewOfFile(buffer);
}

void DisplaySuspiciousEventInfo(PEVENT_RECORD rec)
{
	// 이벤트 헤더 정보 가져오기
	WCHAR sguid[64];
	auto& header = rec->EventHeader;
	::StringFromGUID2(header.ProviderId, sguid, _countof(sguid));
	
	// Timestamp 출력
	wprintf(L"   Timestamp\t|  %ws\n", (PCWSTR)CTime(*(FILETIME*)&header.TimeStamp).Format(L"%c"));

	// process 이름을 얻을 수 있으면 출력
	wprintf(L"   Process Info\t|  ");
	if(PidDfs((DWORD)header.ProcessId, 0) == 6) printf("(%d)\n", (DWORD)header.ProcessId);

	if (PRINT_ALL) wprintf(L"Provider: %ws Time: %ws PID: %u TID: %u\n",
		sguid, (PCWSTR)CTime(*(FILETIME*)&header.TimeStamp).Format(L"%c"),
		header.ProcessId, header.ThreadId);
}

// ex, powershell -EncodedCommand UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgACcALgBcAHAAcgBvAGoAZQBjAHQALQBsAGEAdQBuAGMAaABlAHIALgBlAHgAZQAnAA==
void DisplayPowerShellEventInfo(PEVENT_RECORD rec, PWSTR cmd)
{
	// [!] Suspicious - Event Detected - [suspicious event type] 출력
	ColorPrint(L"[!] Suspicious", L"red");
	wprintf(L" Event Detected - ");
	ColorPrint(L"PowerShell Script\n", L"blue");

	DisplaySuspiciousEventInfo(rec);

	// command 출력
	PWSTR encOptIdx = wcsstr(cmd, L"-EncodedCommand");	// base64 인코딩 명령어 확인
	if (encOptIdx == nullptr) {	// 인코딩 X
		wprintf(L"   Commands\t|  %s\n", cmd);
	}
	else {					// 인코딩 O
		// 인코딩 된 명령어 출력
		wprintf(L"   Commands\t|  ");
		ColorPrint(L"Encoded command\n", L"green");
		ColorPrint(L"      (original) ", L"green");
		wprintf(L"%s\n", cmd);

		// enc를 인코딩 된 명령어 위치로 이동
		PWSTR encIdx = wcsstr(encOptIdx, L" ");
		encIdx++;

		// 디코딩 과정
		char encode[1000];
		unsigned char decode[1000];

		//		wchar를 char로 바꿈
		_bstr_t wb(encIdx);
		const char* c = wb;
		strcpy_s(encode, c);

		//		디코딩 진행
		int space_idx = base64_decode(encode, decode, strlen(encode));

		// 디코딩 된 명령어 출력
		ColorPrint(L"      (decode) ", L"green");
		*encOptIdx = L'\0';
		wprintf(L"%s", cmd);
		for (int i = 0; i < space_idx; i+=2) wprintf(L"%wc", *(PWSTR)(decode+i));
		printf("\n");
	}

	wprintf(L"\n");
}

void DisplayRansomwareEventInfo(PEVENT_RECORD rec, std::wstring path)
{
	// [!] Suspicious - Event Detected - [suspicious event type] 출력
	ColorPrint(L"[!] Suspicious", L"red");
	wprintf(L" Event Detected - ");
	ColorPrint(L"Ransomware\n", L"blue");

	DisplaySuspiciousEventInfo(rec);

	// Process Path 출력
	std::wcout << L"   Process Path\t|  " << path << L"\n";

	auto it = countPath[path].begin();
	std::wcout << L"   Target File\t|\n";
	for (int i = 0; i < 5; i++) {
		std::wcout << L"      " << *it++ << L"\n";
	}
	std::wcout << L"      etc.\n";

	std::wcout << L"   Reasons\t|\n";
	std::wcout << L"      More than 30 of files were deleted and created.\n";
	std::wcout << L"      Ransomware is suspected in " << path << L".\n";

	wprintf(L"\n");
}

void ColorPrint(PCWSTR str, PCWSTR color)
{
	// 원하는 색으로 변경
	if (lstrcmpW(color, L"red") == 0) SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12);
	if (lstrcmpW(color, L"blue") == 0) SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 9);
	if (lstrcmpW(color, L"green") == 0) SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 10);

	// 출력하고자 하는 문구 출력
	wprintf(L"%s", str);

	// 흰색으로 재변경
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
}

// PID로부터 process 이름 가져오기
// 성공 시, return 1
// 실패 시, return 0
int ProcessIdToName(DWORD processId, LPWSTR buffer, DWORD buffSize)
{
	std::string ret;
	// PID로 process 열기
	HANDLE handle = OpenProcess(
		PROCESS_QUERY_LIMITED_INFORMATION,
		FALSE,
		processId /* This is the PID, you can find one from windows task manager */
	);
	if (handle)
	{
		if (QueryFullProcessImageNameW(handle, 0, buffer, &buffSize))
		{
			// Success to get process Name
			return 1;
		}
		else
		{
			//printf("Error GetModuleBaseNameA : %lu", GetLastError());
		}
		CloseHandle(handle);
	}
	else
	{
		//printf("Error OpenProcess : %lu", GetLastError());
	}

	return 0;
}

// base64 decoding 함수
int base64_decode(char* text, unsigned char* dst, int numBytes)
{
	const char* cp;
	int space_idx = 0, phase;
	int d, prev_d = 0;
	unsigned char c;
	space_idx = 0;
	phase = 0;
	for (cp = text; *cp != '\0'; ++cp) {
		d = DecodeMimeBase64[(int)*cp];
		if (d != -1) {
			switch (phase) {
			case 0:
				++phase;
				break;
			case 1:
				c = ((prev_d << 2) | ((d & 0x30) >> 4));
				if (space_idx < numBytes)
					dst[space_idx++] = c;
				++phase;
				break;
			case 2:
				c = (((prev_d & 0xf) << 4) | ((d & 0x3c) >> 2));
				if (space_idx < numBytes)
					dst[space_idx++] = c;
				++phase;
				break;
			case 3:
				c = (((prev_d & 0x03) << 6) | d);
				if (space_idx < numBytes)
					dst[space_idx++] = c;
				phase = 0;
				break;
			}
			prev_d = d;
		}
	}
	return space_idx;
}

DWORD getppid(DWORD pid)
{
	HANDLE hSnapshot;
	PROCESSENTRY32 pe32;
	DWORD ppid = 0;// , pid = GetCurrentProcessId();

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	__try {
		if (hSnapshot == INVALID_HANDLE_VALUE) __leave;

		ZeroMemory(&pe32, sizeof(pe32));
		pe32.dwSize = sizeof(pe32);
		if (!Process32First(hSnapshot, &pe32)) __leave;

		do {
			if (pe32.th32ProcessID == pid) {
				ppid = pe32.th32ParentProcessID;
				break;
			}
		} while (Process32Next(hSnapshot, &pe32));

	}
	__finally {
		if (hSnapshot != INVALID_HANDLE_VALUE) CloseHandle(hSnapshot);
	}
	return ppid;
}

int PidDfs(DWORD pid, int count)
{
	if (pid == 0) return 6;

	DWORD ppid = getppid(pid);

	DWORD buffSize = 1024;
	WCHAR buffer[1024];
	int res = ProcessIdToName(pid, buffer, buffSize);

	int space = PidDfs(ppid, count+res);

	if (space == 6 && count + res <= 1) {
		if (res == 0) return 6;

		PWSTR fileIdx;
		for (fileIdx = buffer + lstrlenW(buffer) - 1; *fileIdx != L'\\'; fileIdx--);
		wprintf(L"%s (%d)\n", fileIdx + 1, pid);
	}
	else if(res){
		if (space == 6) printf("\n");
		for (int i = 0; i < space; i++) printf(" ");

		PWSTR fileIdx;
		for (fileIdx = buffer + lstrlenW(buffer) - 1; *fileIdx != L'\\'; fileIdx--);
		wprintf(L"%s (%d)\n", fileIdx+1, pid);
	}

	return space + 3*res;
}