// MainDlg.cpp : implementation of the CMainDlg class
//
/////////////////////////////////////////////////////////////////////////////

#include "stdafx.h"

#include "MainDlg.h"

LRESULT CMainDlg::OnInitDialog(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/) {
	// dialog 설정
	CenterWindow();

	// 아이콘 설정
	HICON hIcon = AtlLoadIconImage(IDR_MAINFRAME, LR_DEFAULTCOLOR, ::GetSystemMetrics(SM_CXICON), ::GetSystemMetrics(SM_CYICON));
	SetIcon(hIcon, TRUE);
	HICON hIconSmall = AtlLoadIconImage(IDR_MAINFRAME, LR_DEFAULTCOLOR, ::GetSystemMetrics(SM_CXSMICON), ::GetSystemMetrics(SM_CYSMICON));
	SetIcon(hIconSmall, FALSE);

	// 공유메모리 생성
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
	// 사용자가 입력한 값을 공유 메모리에 입력
	WriteInfo();

	// thread를 만들어 tracer 실행 및 대기
	HANDLE hThread = ::CreateThread(nullptr, 0, ThreadProc, (void*)this, 0, nullptr);
	CloseHandle(hThread);

	return 0;
}

void CMainDlg::WriteInfo() {
	// 공유 메모리를 쓰기 기능으로 매핑
	void* buffer = ::MapViewOfFile(m_hSharedMem.get(), FILE_MAP_WRITE, 0, 0, 0);
	if (!buffer) return;	// 공유 메모리 매핑 실패 시, return

	// Name 가져오기
	CString name;
	GetDlgItemText(IDC_NAME, name);
	::wcscpy_s((PWSTR)buffer, name.GetLength() + 1, name);

	// '\0'로 Name과 Student ID 구분하기
	::wcscpy_s((PWSTR)buffer + name.GetLength(), 1, L"\0");

	// Student ID 가져오기
	CString student_id;
	GetDlgItemText(IDC_STUDENT_ID, student_id);
	::wcscpy_s((PWSTR)buffer + name.GetLength() + 1, student_id.GetLength() + 1, student_id);

	// 공유 메모리 매핑 해제
	::UnmapViewOfFile(buffer);
}

DWORD CMainDlg::CreateProc() {
	// 상속 가능하도록 공유 메모리 설정
	::SetHandleInformation(m_hSharedMem.get(), HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);

	STARTUPINFO si = {sizeof(si)};
	PROCESS_INFORMATION pi;

	// command line 생성
	WCHAR path[MAX_PATH] = _T("project-tracer.exe");
	// command line 마지막에 공유 메모리 핸들 값을 붙여줌.
	WCHAR handle[16];
	::_itow_s((int)(ULONG_PTR)m_hSharedMem.get(), handle, 10);
	::wcscat_s(path, L" ");
	::wcscat_s(path, handle);

	// 새로운 process 실행 (tracer 실행)
	if (::CreateProcess(nullptr, path, nullptr, nullptr, TRUE,
		0, nullptr, nullptr, &si, &pi)) {
		// tracer 실행 후 대기
		::WaitForSingleObject(pi.hProcess, INFINITE);
		// tracer 종료 시, timestamp 출력
		WriteTimeStamp();
		::CloseHandle(pi.hProcess);
		::CloseHandle(pi.hThread);
	}
	else;	// error
	
	return 0;
}

void CMainDlg::WriteTimeStamp() {
	// 공유 메모리를 읽기 기능으로 매핑
	void* buffer = ::MapViewOfFile(m_hSharedMem.get(), FILE_MAP_READ, 0, 0, 0);
	if (!buffer) return;	// 공유 메모리 매핑 실패 시, return

	// "terminated timestamp: [공유 메모리 값]" 으로 text 배열 설정
	WCHAR text[100] = L"Running time: ";
	::wcscat_s(text, (PCWSTR)buffer);

	SetDlgItemText(IDC_TIMESTAMP, (PCWSTR)text);

	::UnmapViewOfFile(buffer);
}

// thread에서 class 내부 함수를 실행할 수 없어 외부 함수 ThreadProc를 통하여 class 내부 함수 실행 
DWORD WINAPI ThreadProc(LPVOID IParam) {
	return ((CMainDlg*)IParam)->CreateProc();
}