

#include "stdafx.h"

#include "resource.h"

#include "View.h"
#include "aboutdlg.h"
#include "MainFrm.h"

#include <atltime.h>

CAppModule _Module;

int Run(LPTSTR /*lpstrCmdLine*/ = nullptr, int nCmdShow = SW_SHOWDEFAULT) {
	CMessageLoop theLoop;
	_Module.AddMessageLoop(&theLoop);

	CMainFrame wndMain;

	if (wndMain.CreateEx() == nullptr) {
		ATLTRACE(_T("Main window creation failed!\n"));
		return 0;
	}

	wndMain.ShowWindow(nCmdShow);

	int nRet = theLoop.Run();

	_Module.RemoveMessageLoop();

	wil::unique_handle m_hSharedMem;

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

	void* buffer = ::MapViewOfFile(m_hSharedMem.get(), FILE_MAP_WRITE, 0, 0, 0);
	if (!buffer) return nRet;	// ���� �޸� ���� ���� ��, return

	// ���� �ð��� �����ͼ� ���� �޸𸮿� �Է�
	CTime dt = CTime::GetCurrentTime();
	::wcscpy_s((PWSTR)buffer, 100, dt.Format(L"%T"));

	// ���� �޸� ���� ����
	::UnmapViewOfFile(buffer);

	return nRet;
}

int WINAPI _tWinMain(HINSTANCE hInstance, HINSTANCE /*hPrevInstance*/, LPTSTR lpstrCmdLine, int nCmdShow) {
	HRESULT hRes = ::CoInitialize(nullptr);
	ATLASSERT(SUCCEEDED(hRes));

	AtlInitCommonControls(ICC_COOL_CLASSES | ICC_BAR_CLASSES | ICC_LISTVIEW_CLASSES);	// add flags to support other controls

	hRes = _Module.Init(nullptr, hInstance);
	ATLASSERT(SUCCEEDED(hRes));

	int nRet = Run(lpstrCmdLine, nCmdShow);

	_Module.Term();
	::CoUninitialize();

	return nRet;
}
