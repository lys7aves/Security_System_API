// View.cpp : implementation of the CView class
//
/////////////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "resource.h"

#include "View.h"
#include <atltime.h>

BOOL CView::PreTranslateMessage(MSG* pMsg) {
	if (m_InformationBar.PreTranslateMessage(pMsg))
		return TRUE;

	return FALSE;
}

void CView::Refresh() {
	// 프로세스 갱신
	m_ProcMgr.Refresh();
	m_List.SetItemCountEx(static_cast<int>(m_ProcMgr.GetProcesses().size()), LVSICF_NOINVALIDATEALL| LVSICF_NOSCROLL);
	m_List.RedrawItems(m_List.GetTopIndex(), m_List.GetCountPerPage() + m_List.GetTopIndex());
}

LRESULT CView::OnTimer(UINT, WPARAM id, LPARAM, BOOL&) {
	if (id == 1)
		Refresh();

	return 0;
}

LRESULT CView::OnCreate(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/) {
	// 정보 바 생성
	m_InformationBar.Create(m_hWnd);
	m_InformationBar.ShowWindow(SW_SHOW);

	// 프로세스 리스트 생성
	m_List.Create(m_hWnd, rcDefault, nullptr,
		WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPCHILDREN | LVS_REPORT | LVS_OWNERDATA | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
		0, 123);
	m_List.SetExtendedListViewStyle(LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER, 0);

	struct {
		PCWSTR Header;
		int Width;
		int Format = LVCFMT_LEFT;
	} columns[] = {
		{ L"Name", 200 },
		{ L"PID", 100, LVCFMT_RIGHT },
		{ L"PPID", 100, LVCFMT_RIGHT },
		{ L"Session", 80, LVCFMT_RIGHT },
		{ L"User Name", 150 },
		{ L"Threads", 80, LVCFMT_RIGHT },
		{ L"Handles", 80, LVCFMT_RIGHT },
		{ L"Working Set", 100, LVCFMT_RIGHT },
		{ L"CPU Time", 120, LVCFMT_RIGHT },
		{ L"Full Path", 250, LVCFMT_RIGHT },
	};

	int i = 0;
	for (auto& col : columns)
		m_List.InsertColumn(i++, col.Header, col.Format, col.Width);
	
	// 프로세스 정보 업데이트
	Refresh();
	// 기본정보 업데이트
	m_InformationBar.Init();
	SetTimer(1, 1000, nullptr);

	return 0;
}

LRESULT CView::OnSize(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM lParam, BOOL& /*bHandled*/) {
	if (m_InformationBar.IsWindow()) {
		int cx = GET_X_LPARAM(lParam), cy = GET_Y_LPARAM(lParam);
		RECT rc;
		m_InformationBar.GetClientRect(&rc);
		m_InformationBar.MoveWindow(0, 0, rc.right, rc.bottom);
		m_List.MoveWindow(0, rc.bottom, cx, cy - rc.bottom);
	}

//	int cx = GET_X_LPARAM(lParam), cy = GET_Y_LPARAM(lParam);
//	if (m_List)
//		m_List.MoveWindow(0, 0, cx, cy);
	return 0;
}

LRESULT CView::OnGetDispInfo(int, LPNMHDR pnmh, BOOL&) {
	auto lv = (NMLVDISPINFO*)pnmh;
	auto& item = lv->item;

	if (lv->item.mask & LVIF_TEXT) {
		const auto& data = m_ProcMgr.GetProcesses()[item.iItem];

		switch (item.iSubItem) {
			case 0:	// name
				item.pszText = (PWSTR)(PCWSTR)data->Name;
				break;

			case 1:	// pid
				StringCchPrintf(item.pszText, item.cchTextMax, L"%d", data->Id);
				break;

			case 2: // ppid
				StringCchPrintf(item.pszText, item.cchTextMax, L"%d", data->Ppid);
				break;

			case 3:	// session
				StringCchPrintf(item.pszText, item.cchTextMax, L"%d", data->SessionId);
				break;

			case 4:	// user name
				item.pszText = (PWSTR)(PCWSTR)data->UserName;
				break;

			case 5:	// threads
				StringCchPrintf(item.pszText, item.cchTextMax, L"%d", data->ThreadCount);
				break;

			case 6:	// handles
				StringCchPrintf(item.pszText, item.cchTextMax, L"%d", data->HandleCount);
				break;

			case 7:	// working set
				StringCchPrintf(item.pszText, item.cchTextMax, L"%d KB", data->WorkingSet >> 10);
				break;

			case 8:	// CPU Time
				StringCchPrintf(item.pszText, item.cchTextMax, L"%ws", 
					(PCWSTR)CTimeSpan((data->KernelTime + data->UserTime) / 10000000).Format(L"%D:%H:%M:%S"));
				break;

			case 9: // Full Path
				item.pszText = (PWSTR)(PCWSTR)data->FullPath;
				break;
		}
	}

	return 0;
}
