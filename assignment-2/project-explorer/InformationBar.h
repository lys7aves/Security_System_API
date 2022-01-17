#pragma once

#include "resource.h"

class CInformationBar : 
	public CDialogImpl<CInformationBar> {
public:
	void Init();

	enum { IDD = IDD_INFORMATIONBAR };

	BOOL PreTranslateMessage(MSG* pMsg);

	BEGIN_MSG_MAP(CInformationBar)
		MESSAGE_HANDLER(WM_ERASEBKGND, OnEraseBackground)
		MESSAGE_HANDLER(WM_CTLCOLORSTATIC, OnControlColor)
	END_MSG_MAP()

private:
	LRESULT OnEraseBackground(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/);
	LRESULT OnControlColor(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/);

	int readSharedMemory(PWSTR text);
	int useGetProductInfoAPI(PWSTR text);
	int useiKUSER_SHARED_DATAstruct(PWSTR text);
	int useGetComputerNameAPI(PWSTR text);

public:
	wil::unique_handle m_hSharedMem;
};

