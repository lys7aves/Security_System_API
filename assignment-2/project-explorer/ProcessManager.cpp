#include "stdafx.h"
#include "ProcessManager.h"
#include <wil\resource.h>
#include <unordered_set>
#include "NtDll.h"

void ProcessManager::Refresh() {
	std::unique_ptr<BYTE[]> buffer;
	ULONG size = 1 << 20;
	NTSTATUS status;
	do {
		buffer = std::make_unique<BYTE[]>(size);
		// 시스템 정보 검색
		status = ::NtQuerySystemInformation(SystemProcessInformation, buffer.get(), size, nullptr);
		// 설정된 size보다 정보가 더 많으면 size 증가
		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			size *= 2;
			continue;
		}
		break;
	} while (true);
	// 시스템 프로세스 정보를 가져오지 못했으면 return;
	if (status != STATUS_SUCCESS)
		return;

	bool first = _processes.empty();
	auto existingProcesses(_processesByKey);

	_processes.clear();
	_processes.reserve(first ? 256 : _processesByKey.size() + 10);

	if (first) {
		_processesByKey.reserve(256);
	}

	auto p = (SYSTEM_PROCESS_INFORMATION*)buffer.get();
	for (;;) {
		// (생성 시간, pid)쌍 key 생성
		std::shared_ptr<ProcessInfo> pi;
		auto pid = HandleToULong(p->UniqueProcessId);
		ProcessKey key(p->CreateTime.QuadPart, pid);
		auto it = _processesByKey.find(key);

		// (생성 시간, pid)key가 없으면...
		if (it == _processesByKey.end()) {
			pi = std::make_unique<ProcessInfo>(key.CreateTime, pid);				// 생성 시간, pid 입력
			pi->Ppid = HandleToULong(p->InheritedFromUniqueProcessId);				// ppid 입력
			pi->Name = pid == 0 ? L"[Idle]" : CString(p->ImageName.Buffer, p->ImageName.Length / sizeof(WCHAR));	// 이름 입력
			pi->SessionId = p->SessionId;											// Session ID 입력
			pi->UserName = GetUserNameFromPid(pid);									// UserName 입력

			// Full Path 입력
			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
			TCHAR exeName[MAX_PATH] = { 0, };
			DWORD dwSize = sizeof(exeName) / sizeof(TCHAR);
			bool res = QueryFullProcessImageName(hProcess, 0, exeName, &dwSize);	
			pi->FullPath = exeName;

			_processesByKey.insert({ key, pi });
		}
		// (생성 시간, pid)key가 있으면 위의 정보 입력 X
		else {
			pi = it->second;
			existingProcesses.erase(key);
		}
		_processes.push_back(pi);

		// 추가 정보 갱신
		pi->HandleCount = p->HandleCount;
		pi->ThreadCount = p->NumberOfThreads;
		pi->UserTime = p->UserTime.QuadPart;
		pi->KernelTime = p->KernelTime.QuadPart;
		pi->WorkingSet = p->WorkingSetSize;
		if (p->NextEntryOffset == 0)
			break;
		p = (SYSTEM_PROCESS_INFORMATION*)((BYTE*)p + p->NextEntryOffset);
	}

	// remove dead processes
	for (auto& [key, _] : existingProcesses)
		_processesByKey.erase(key);
}

const std::vector<std::shared_ptr<ProcessInfo>>& ProcessManager::GetProcesses() const {
	return _processes;
}

CString ProcessManager::GetUserNameFromPid(uint32_t pid) {
	wil::unique_handle hProcess(::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid));
	if(!hProcess)
		return L"";

	wil::unique_handle hToken;
	if (!::OpenProcessToken(hProcess.get(), TOKEN_QUERY, hToken.addressof()))
		return L"";

	BYTE buffer[MAX_SID_SIZE + sizeof(TOKEN_USER)];
	DWORD len;
	if(!::GetTokenInformation(hToken.get(), TokenUser, buffer, sizeof(buffer), &len))
		return L"";

	auto user = (TOKEN_USER*)buffer;
	return GetUserNameFromSid(user->User.Sid);
}


CString ProcessManager::GetUserNameFromSid(PSID sid) {
	if (sid == nullptr)
		return L"";

	WCHAR name[64], domain[64];
	DWORD len = _countof(name);
	DWORD domainLen = _countof(domain);
	SID_NAME_USE use;
	if (!::LookupAccountSid(nullptr, sid, name, &len, domain, &domainLen, &use))
		return L"";

	return CString(domain) + L"\\" + name;
}
