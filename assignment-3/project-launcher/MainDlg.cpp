// MainDlg.cpp : implementation of the CMainDlg class
//
/////////////////////////////////////////////////////////////////////////////

#include "stdafx.h"

#include "MainDlg.h"

LRESULT CMainDlg::OnInitDialog(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/) {
	// dialog ����
	CenterWindow();

	// ������ ����
	HICON hIcon = AtlLoadIconImage(IDR_MAINFRAME, LR_DEFAULTCOLOR, ::GetSystemMetrics(SM_CXICON), ::GetSystemMetrics(SM_CYICON));
	SetIcon(hIcon, TRUE);
	HICON hIconSmall = AtlLoadIconImage(IDR_MAINFRAME, LR_DEFAULTCOLOR, ::GetSystemMetrics(SM_CXSMICON), ::GetSystemMetrics(SM_CYSMICON));
	SetIcon(hIconSmall, FALSE);

	// �����޸� ����
	m_hSharedMem.reset(::CreateFileMapping(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, 1 << 16, nullptr));
	ATLASSERT(m_hSharedMem);

	return TRUE;
}

LRESULT CMainDlg::OnDestroy(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/) {
	return 0;
}

LRESULT CMainDlg::OnCancel(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/) {
	EndDialog(wID);
	return 0;
}

LRESULT CMainDlg::OnRun(WORD, WORD, HWND, BOOL &) {
	// ����ڰ� �Է��� ���� ���� �޸𸮿� �Է�
	WriteInfo();

	// thread�� ����� tracer ���� �� ���
	HANDLE hThread = ::CreateThread(nullptr, 0, ThreadProc, (void*)this, 0, nullptr);
	CloseHandle(hThread);

	return 0;
}

void CMainDlg::WriteInfo() {
	// ���� �޸𸮸� ���� ������� ����
	void* buffer = ::MapViewOfFile(m_hSharedMem.get(), FILE_MAP_WRITE, 0, 0, 0);
	if (!buffer) return;	// ���� �޸� ���� ���� ��, return

	// Name ��������
	CString name;
	GetDlgItemText(IDC_NAME, name);
	::wcscpy_s((PWSTR)buffer, name.GetLength() + 1, name);

	// '\0'�� Name�� Student ID �����ϱ�
	::wcscpy_s((PWSTR)buffer + name.GetLength(), 1, L"\0");

	// Student ID ��������
	CString student_id;
	GetDlgItemText(IDC_STUDENT_ID, student_id);
	::wcscpy_s((PWSTR)buffer + name.GetLength() + 1, student_id.GetLength() + 1, student_id);

	// ���� �޸� ���� ����
	::UnmapViewOfFile(buffer);
}

DWORD CMainDlg::CreateProc() {
	// ��� �����ϵ��� ���� �޸� ����
	::SetHandleInformation(m_hSharedMem.get(), HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);

	STARTUPINFO si = {sizeof(si)};
	PROCESS_INFORMATION pi;

	// command line ����
	WCHAR path[MAX_PATH] = _T("project-tracer.exe");
	// command line �������� ���� �޸� �ڵ� ���� �ٿ���.
	WCHAR handle[16];
	::_itow_s((int)(ULONG_PTR)m_hSharedMem.get(), handle, 10);
	::wcscat_s(path, L" ");
	::wcscat_s(path, handle);

	// ���ο� process ���� (tracer ����)
	if (::CreateProcess(nullptr, path, nullptr, nullptr, TRUE,
		0, nullptr, nullptr, &si, &pi)) {
		// tracer ���� �� ���
		::WaitForSingleObject(pi.hProcess, INFINITE);
		// tracer ���� ��, timestamp ���
		WriteTimeStamp();
		::CloseHandle(pi.hProcess);
		::CloseHandle(pi.hThread);
	}
	else;	// error
	
	return 0;
}

void CMainDlg::WriteTimeStamp() {
	// ���� �޸𸮸� �б� ������� ����
	void* buffer = ::MapViewOfFile(m_hSharedMem.get(), FILE_MAP_READ, 0, 0, 0);
	if (!buffer) return;	// ���� �޸� ���� ���� ��, return

	// "terminated timestamp: [���� �޸� ��]" ���� text �迭 ����
	WCHAR text[100] = L"Running time: ";
	::wcscat_s(text, (PCWSTR)buffer);

	SetDlgItemText(IDC_TIMESTAMP, (PCWSTR)text);

	::UnmapViewOfFile(buffer);
}

// thread���� class ���� �Լ��� ������ �� ���� �ܺ� �Լ� ThreadProc�� ���Ͽ� class ���� �Լ� ���� 
DWORD WINAPI ThreadProc(LPVOID IParam) {
	return ((CMainDlg*)IParam)->CreateProc();
}