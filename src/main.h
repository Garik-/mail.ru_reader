#include <windows.h>
#include <Commctrl.h>
#pragma comment(lib,"Comctl32.lib")
#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#include <tchar.h>
#include <richedit.h>

#include "resource.h"

#define WINTITLE _TEXT("Mail.ru History Reader")

#define TYPE_SMS 0x11

HMENU hMenu;
HWND hwndDlg;
HINSTANCE hInst;
HANDLE hDBSFile=INVALID_HANDLE_VALUE;
HANDLE hDBSMap=NULL;

unsigned char * mra_base = NULL;
unsigned int * offset_table;
int cur_sel_item_index;


#pragma pack(push,1) 
typedef struct _ids{
	unsigned int id1;
	unsigned int id2;
}_ids;

struct _message{
	unsigned int size;
	unsigned int prev_id;
	unsigned int next_id;
	unsigned int xz1;
	FILETIME time;
	unsigned int type_message;
	char flag_incoming;
	char lol[3]; 
	unsigned int count_nick;
	unsigned int magic_num; // 0x38
	unsigned int count_message; // именно количество, не размер в байтах
	unsigned int xz2; // 
	unsigned int size_lps_rtf; // байт 
	unsigned int xz3; // 
};



typedef struct _email{
	wchar_t *history;
	HANDLE hTmpFile;
	_ids *id;
}_email;

typedef struct _emails{
	struct _email *emails;
	unsigned int count_messages;
}_emails;

struct _emails emails = {NULL,0};

/* Сигнатура строки "mrahistory_" в unicode */
unsigned char mrahistory[22] = {
	0x6D, 0x00, 0x72, 0x00, 0x61, 0x00, 0x68, 0x00, 0x69, 0x00, 0x73, 0x00, 0x74, 0x00, 0x6F, 0x00, 
	0x72, 0x00, 0x79, 0x00, 0x5F, 0x00
};

#pragma pack(pop)

void * memmem(const void *buf, const void *pattern, size_t buflen, size_t len);
void * (*__memset)(void *dest,int c,size_t count);
void get_history();
BOOL CALLBACK MainDialogProc(HWND s_hwndDlg,UINT Message, UINT wParam, LONG lParam);
DWORD CALLBACK EditStreamCallback(DWORD_PTR dwCookie, LPBYTE lpBuff,LONG cb, PLONG pcb);
BOOL SetListEmails();
BOOL PrintMessage(HWND hwndDlg,struct _emails * emails,int email_index);
LRESULT SetDefaultText(HWND hRich);
BOOL save_text(UINT type);
BOOL CALLBACK MainDialogProc(HWND s_hwndDlg,UINT Message, UINT wParam, LONG lParam);
