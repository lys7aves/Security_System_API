#include "stdafx.h"
#include "pch.h"
#include "InformationBar.h"

void CInformationBar::Init() {
	int count;
	PWSTR* args = ::CommandLineToArgvW(::GetCommandLine(), &count);
	if (count == 1) {
		// �ܵ� ���� �� ���� �޸� ����
		m_hSharedMem.reset(::CreateFileMapping(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, 1 << 16, nullptr));
	}
	else {
		// launcher�� ���� ���� ��, launcher���� �Ѱ��� �ڵ� ������ ���� �޸� ����
		m_hSharedMem.reset((HANDLE)(ULONG_PTR)::_wtoi(args[1]));
	}
	::LocalFree(args);

	ATLASSERT(m_hSharedMem);

	WCHAR buffer[1000] = { 0, };
	int start = 0;

	start = readSharedMemory(buffer);
	start += useGetProductInfoAPI(buffer + start);
	start += useiKUSER_SHARED_DATAstruct(buffer + start);
	start += useGetComputerNameAPI(buffer + start);
	SetDlgItemText(IDC_INFORMATION, buffer);
}

BOOL CInformationBar::PreTranslateMessage(MSG * pMsg) {
	return CWindow::IsDialogMessage(pMsg);
}

LRESULT CInformationBar::OnEraseBackground(UINT, WPARAM wParam, LPARAM, BOOL &) {
	CDCHandle dc((HDC)wParam);
	RECT rc;
	GetClientRect(&rc);
	dc.FillSolidRect(&rc, ::GetSysColor(COLOR_WINDOW));

	return 1;
}

LRESULT CInformationBar::OnControlColor(UINT, WPARAM, LPARAM, BOOL &) {
	return COLOR_WINDOW + 1;
}

int CInformationBar::readSharedMemory(PWSTR text) {
	// ���� �޸� �б� �������� ����
	void* buffer = ::MapViewOfFile(m_hSharedMem.get(), FILE_MAP_READ, 0, 0, 0);
	if (!buffer) return 0;	// ���� ���� ��, return

	int start, len1, len2;
	// ���� �޸� : "[Name]\0[Student ID]\0"

	// "Examiner Name:\t[Name]\n" ���ڿ� ���ۿ� ����
	::wcscpy_s((PWSTR)text, 17, L"Examiner Name: \t\0");
	start = 16;
	for (len1 = 0; *((PCWSTR)buffer + len1) != L'\0'; len1++);
	::wcscpy_s((PWSTR)text + start, len1 + 1, (PCWSTR)buffer);
	start += len1;
	::wcscpy_s((PWSTR)text + start, 2, L"\n\0");
	start += 1;

	// "Examiner ID:\t\t[Student ID]\n" ���ڿ� ���ۿ� ����
	::wcscpy_s((PWSTR)text + start, 16, L"Examiner ID: \t\t\0");
	start += 15;
	for (len2 = len1 + 1; *((PCWSTR)buffer + len2) != L'\0'; len2++);
	::wcscpy_s((PWSTR)text + start, len2 - len1, (PCWSTR)buffer + len1 + 1);
	start += len2-len1-1;
	::wcscpy_s((PWSTR)text + start, 2, L"\n\0");
	start += 1;

	::UnmapViewOfFile(buffer);

	return start;
}

int CInformationBar::useGetProductInfoAPI(PWSTR text) {
	int start;

	::wcscpy_s((PWSTR)text, 20, L"Operating System: \t\0");
	start = 19;

	// GetProductInfo API Ȱ��
	// ���� ��ǻ���� �ü���� ���� ��ǰ ������ �˻��ϰ�, ������ �ü������ �����ϴ� ��ǰ ������ ������ ������ �� �ִ�.
	// ���� : DWORD dwOSMajorVersion, DWORD dwOSMinorVersion, DWORD dwSpMajorVersion, DWORD dwSpMinorVersion, PDWORD pdwReturnedProductType
	// ��ȯ : BOOL
	DWORD dwPInfo, dwVersion, dwMajorVersion, dwMinorVersion;
	bool res;

	dwVersion = GetVersion();
	dwMajorVersion = (DWORD)(LOBYTE(LOWORD(dwVersion)));
	dwMinorVersion = (DWORD)(HIBYTE(LOWORD(dwVersion)));

	res = ::GetProductInfo(dwMajorVersion, dwMinorVersion, 0, 0, &dwPInfo);	// ���������� ����Ǹ� ture, �׷��� ������ false�� return �Ѵ�.
	if (res) {
		switch (dwPInfo) {	// ��ȣ�� ���� �ǹ̰� �޶� �Ϻθ� ������ �� �ǹ̸� ����ߴ�.
		case PRODUCT_BUSINESS: ::wcscpy_s((PWSTR)text + start, 10, L"Business \0"); start += 9; break;
		case PRODUCT_BUSINESS_N: ::wcscpy_s((PWSTR)text + start, 12, L"Business N \0"); start += 11; break;
		case PRODUCT_CLUSTER_SERVER: ::wcscpy_s((PWSTR)text + start, 12, L"HPC Edition \0"); start += 11; break;
		case PRODUCT_CLUSTER_SERVER_V: ::wcscpy_s((PWSTR)text + start, 21, L"Server Hyper Core V \0"); start += 20; break;
		case PRODUCT_CORE: ::wcscpy_s((PWSTR)text + start, 17, L"Windows 10 Home \0"); start += 16; break;
		case PRODUCT_CORE_COUNTRYSPECIFIC: ::wcscpy_s((PWSTR)text + start, 23, L"Windows 10 Home China \0"); start += 22; break;
		case PRODUCT_CORE_N: ::wcscpy_s((PWSTR)text + start, 19, L"Windows 10 Home N \0"); start += 18; break;
		default: ::wcscpy_s((PWSTR)text + start, 8, L"others \0"); start += 7;
		}
	}
	else {
		::wcscpy_s((PWSTR)text + start, 7, L"Error \0");
		start += 6;
	}

	return start;
}

int CInformationBar::useiKUSER_SHARED_DATAstruct(PWSTR text) {
	// KUSER_SHARED_DATA struct ���

	auto sharedUserData = (BYTE*)0x7FFE0000;

	WCHAR version[100] = { 0, };
	int start;

	wsprintf(version, L"(%d.%d.%d)\n\0",
		*(ULONG*)(sharedUserData + 0x26c), // major version offset
		*(ULONG*)(sharedUserData + 0x270), // minor version offset
		*(ULONG*)(sharedUserData + 0x260)); // build number offset (Windows 10)

	for (start = 0; version[start] != L'\0'; start++);
	::wcscpy_s((PWSTR)text, start + 1, version);

	return start;
}

int CInformationBar::useGetComputerNameAPI(PWSTR text) {
	int start;
	::wcscpy_s((PWSTR)text, 17, L"Computer Name: \t\0");
	start = 16;

	// GetComputerName API Ȱ��
	// ���� ��ǻ���� NetBIOS �̸��� �˻��� �� �ִ�.
	// ���� : LPSTR lpBuffer, LPDWORD nSize
	wchar_t buffer[256] = L"";	// GetComputerName �Լ��� ù��° ���ڰ� LPSTR�̾ char�� �ƴ� wchar_t�� ����Ͽ�����, �ʱ�ȭ�� "" �� �ƴ� L""���� �Ͽ���.
	DWORD size = sizeof(buffer);
	if (::GetComputerName(buffer, &size)) {	// buffer�� ũ�Ⱑ ������ 0�� return �ϸ�, GetLastError�� � �������� �� �� �ִ�.
		int len;

		for (len = 0; buffer[len] != '\0'; len++);

		::wcscpy_s((PWSTR)text + start, len+1, buffer);
		start += len;
	}
	else {
		::wcscpy_s((PWSTR)text + start, 6, L"Error\0");
		start += 5;
	}

	return start;
}
