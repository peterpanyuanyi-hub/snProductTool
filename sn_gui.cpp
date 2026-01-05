#include <windows.h>
#include <wincrypt.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <cstdio>
#pragma comment(lib, "Comctl32.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Bcrypt.lib")

static std::string Sha256(const std::string &s){
    HCRYPTPROV hProv=0; HCRYPTHASH hHash=0; BYTE hash[32]; DWORD len=32;
    CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    CryptHashData(hHash, (BYTE*)s.data(), (DWORD)s.size(), 0);
    CryptGetHashParam(hHash, HP_HASHVAL, hash, &len, 0);
    CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0);
    return std::string((char*)hash, (char*)hash+32);
}
static std::string Pkcs7(const std::string &in){
    size_t bs=16; size_t pad=bs-(in.size()%bs); if(!pad) pad=bs; std::string o=in; o.resize(in.size()+pad,(char)pad); return o; }
static std::string Base64(const std::string &bin){ DWORD outLen=0; CryptBinaryToStringA((BYTE*)bin.data(),(DWORD)bin.size(),CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF,NULL,&outLen); std::string out; out.resize(outLen); CryptBinaryToStringA((BYTE*)bin.data(),(DWORD)bin.size(),CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF,&out[0],&outLen); if(!out.empty()&&out.back()=='\0') out.pop_back(); return out; }
static std::string AesCbc(const std::string &plain, const std::string &keyRaw32, const std::string &iv){
    HCRYPTPROV hProv=0; HCRYPTKEY hKey=0;
    if(!CryptAcquireContext(&hProv,NULL,NULL,PROV_RSA_AES,CRYPT_VERIFYCONTEXT)) return std::string();
    struct { BLOBHEADER hdr; DWORD len; BYTE key[32]; } blob; blob.hdr.bType=PLAINTEXTKEYBLOB; blob.hdr.bVersion=CUR_BLOB_VERSION; blob.hdr.reserved=0; blob.hdr.aiKeyAlg=CALG_AES_256; blob.len=32; memcpy(blob.key,(const BYTE*)keyRaw32.data(),32);
    if(!CryptImportKey(hProv,(BYTE*)&blob,sizeof(blob),0,0,&hKey)){ CryptReleaseContext(hProv,0); return std::string(); }
    DWORD mode=CRYPT_MODE_CBC; CryptSetKeyParam(hKey,KP_MODE,(BYTE*)&mode,0); BYTE ivBuf[16]; memcpy(ivBuf,iv.data(),16); CryptSetKeyParam(hKey,KP_IV,ivBuf,0);
    std::string data=Pkcs7(plain); std::string ct=data; DWORD ctLen=(DWORD)ct.size(); if(!CryptEncrypt(hKey,0,FALSE,0,(BYTE*)&ct[0],&ctLen,(DWORD)ct.size())){ CryptDestroyKey(hKey); CryptReleaseContext(hProv,0); return std::string(); } CryptDestroyKey(hKey); CryptReleaseContext(hProv,0); return ct; }

static char PickAN(const std::string&s,int start){int n=(int)s.size();for(int k=0;k<n;++k){char c=s[(start+k)%n]; if((c>='0'&&c<='9')||(c>='A'&&c<='Z')||(c>='a'&&c<='z')) return c;}return '0';}
static std::string BuildF10(const std::string&t,const std::string&m,int sn,std::string&err){int r=10-((int)t.size()+(int)m.size()); if(r<1){err="前10位长度不合法：产品类型+型号总长度需小于10"; return "";} char buf[64]; sprintf(buf,"%0*d",r,sn); return t+m+std::string(buf);} 

struct Row{int idx; std::string type, model, f10, tail6, did; int sn;};
static std::vector<Row> Gen(const std::string&type,const std::string&model,int snStart,int count,std::string&err){std::vector<Row> rows; rows.reserve(count); for(int i=0;i<count;++i){int sn=snStart+i; auto f10=BuildF10(type,model,sn,err); if(!err.empty()) return rows; std::string keyStr(Sha256("123456")); auto iv=Sha256(f10).substr(0,16); auto ct=AesCbc(f10,keyStr,iv); auto b64=Base64(ct); int pos[6]={1,3,6,10,15,21}; std::string tail(6,'0'); for(int j=0;j<6;++j){tail[j]=PickAN(b64,pos[j]-1); if(tail[j]>='a'&&tail[j]<='z') tail[j]=tail[j]-'a'+'A';} rows.push_back({i+1,type,model,f10,tail,f10+tail,sn}); } return rows; }

static bool WriteXls(const std::vector<Row>&rows,const std::string&name){std::string fname=name.empty()?"did_list.xls":name; FILE*fp=fopen(fname.c_str(),"wb"); if(!fp) return false; fputs("<!DOCTYPE html><html><head><meta charset=\"utf-8\"></head><body><table border=\"1\"><thead><tr>",fp); const char*head[7]={"#","产品类型","型号","SN","First10","尾6","DID"}; for(int i=0;i<7;++i) fprintf(fp,"<th>%s</th>",head[i]); fputs("</tr></thead><tbody>",fp); for(auto&r:rows) fprintf(fp,"<tr><td>%d</td><td>%s</td><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td>%s</td></tr>",r.idx,r.type.c_str(),r.model.c_str(),r.sn,r.f10.c_str(),r.tail6.c_str(),r.did.c_str()); fputs("</tbody></table></body></html>",fp); fclose(fp); return true; }
static bool WriteXlsW(const std::vector<Row>&rows,const std::wstring&wname){std::wstring wf=wname.empty()?L"did_list.xls":wname; FILE*fp=_wfopen(wf.c_str(),L"wb"); if(!fp) return false; fputs("<!DOCTYPE html><html><head><meta charset=\"utf-8\"></head><body><table border=\"1\"><thead><tr>",fp); const char*head[7]={"#","产品类型","型号","SN","First10","尾6","DID"}; for(int i=0;i<7;++i) fprintf(fp,"<th>%s</th>",head[i]); fputs("</tr></thead><tbody>",fp); for(auto&r:rows) fprintf(fp,"<tr><td>%d</td><td>%s</td><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td>%s</td></tr>",r.idx,r.type.c_str(),r.model.c_str(),r.sn,r.f10.c_str(),r.tail6.c_str(),r.did.c_str()); fputs("</tbody></table></body></html>",fp); fclose(fp); return true; }

// UI IDs
#define IDC_TYPE   1001
#define IDC_MODEL  1002
#define IDC_SNSTART 1003
#define IDC_COUNT  1004
#define IDC_OUT    1005
#define IDC_PREVIEW 1006
#define IDC_GEN    1101
#define IDC_EXPORT 1102
#define IDC_MSG    1201

LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l){
    static HWND hType,hModel,hSnStart,hCount,hOut,hPreview,hGen,hExport,hMsg,hList,hLoadCfg,hStatus;
    static std::vector<Row> gRows;
    switch(m){
    case WM_CREATE:{
        CreateWindowEx(0, WC_STATIC, L"生产SN&DID工具 v1.1", WS_CHILD|WS_VISIBLE, 10,10,300,24, h, 0, 0, 0);
        CreateWindowEx(0, WC_STATIC, L"产品类型", WS_CHILD|WS_VISIBLE, 10,40,80,24, h, 0, 0, 0);
        hType=CreateWindowEx(WS_EX_CLIENTEDGE, WC_EDIT, L"", WS_CHILD|WS_VISIBLE|ES_LEFT, 100,40,200,24, h, (HMENU)IDC_TYPE, 0,0);
        CreateWindowEx(0, WC_STATIC, L"型号", WS_CHILD|WS_VISIBLE, 10,70,80,24, h, 0, 0, 0);
        hModel=CreateWindowEx(WS_EX_CLIENTEDGE, WC_EDIT, L"", WS_CHILD|WS_VISIBLE|ES_LEFT, 100,70,200,24, h, (HMENU)IDC_MODEL, 0,0);
        CreateWindowEx(0, WC_STATIC, L"起始SN", WS_CHILD|WS_VISIBLE, 10,100,80,24, h, 0, 0, 0);
        hSnStart=CreateWindowEx(WS_EX_CLIENTEDGE, WC_EDIT, L"1", WS_CHILD|WS_VISIBLE|ES_LEFT, 100,100,200,24, h, (HMENU)IDC_SNSTART, 0,0);
        CreateWindowEx(0, WC_STATIC, L"生成数量", WS_CHILD|WS_VISIBLE, 10,130,80,24, h, 0, 0, 0);
        hCount=CreateWindowEx(WS_EX_CLIENTEDGE, WC_EDIT, L"100", WS_CHILD|WS_VISIBLE|ES_LEFT, 100,130,200,24, h, (HMENU)IDC_COUNT, 0,0);
        CreateWindowEx(0, WC_STATIC, L"导出文件名", WS_CHILD|WS_VISIBLE, 10,160,80,24, h, 0, 0, 0);
        hOut=CreateWindowEx(WS_EX_CLIENTEDGE, WC_EDIT, L"did_list.xls", WS_CHILD|WS_VISIBLE|ES_LEFT, 100,160,200,24, h, (HMENU)IDC_OUT, 0,0);
        CreateWindowEx(0, WC_STATIC, L"预览条数", WS_CHILD|WS_VISIBLE, 10,190,80,24, h, 0, 0, 0);
        hPreview=CreateWindowEx(WS_EX_CLIENTEDGE, WC_EDIT, L"10", WS_CHILD|WS_VISIBLE|ES_LEFT, 100,190,200,24, h, (HMENU)IDC_PREVIEW, 0,0);
        hGen=CreateWindowEx(0, WC_BUTTON, L"生成预览", WS_CHILD|WS_VISIBLE, 320,40,120,28, h, (HMENU)IDC_GEN, 0,0);
        hExport=CreateWindowEx(0, WC_BUTTON, L"导出.xls", WS_CHILD|WS_VISIBLE, 320,75,120,28, h, (HMENU)IDC_EXPORT, 0,0);
        hLoadCfg=CreateWindowEx(0, WC_BUTTON, L"导入配置", WS_CHILD|WS_VISIBLE, 320,110,120,28, h, (HMENU)1301, 0,0);
        hMsg=CreateWindowEx(0, WC_STATIC, L"", WS_CHILD|WS_VISIBLE, 10,220,760,24, h, (HMENU)IDC_MSG, 0,0);
        // 预览表格
        INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_LISTVIEW_CLASSES }; InitCommonControlsEx(&icc);
        hList=CreateWindowEx(WS_EX_CLIENTEDGE, WC_LISTVIEW, L"", WS_CHILD|WS_VISIBLE|LVS_REPORT, 10,260,760,300, h, 0, 0, 0);
        ListView_SetExtendedListViewStyle(hList, LVS_EX_FULLROWSELECT|LVS_EX_GRIDLINES);
        LVCOLUMNW col{}; col.mask=LVCF_TEXT|LVCF_WIDTH; 
        const wchar_t* heads[7]={L"#",L"产品类型",L"型号",L"SN",L"First10",L"尾6",L"DID"}; int widths[7]={60,100,120,100,140,100,220};
        for(int i=0;i<7;++i){ col.pszText=(LPWSTR)heads[i]; col.cx=widths[i]; ListView_InsertColumn(hList,i,&col);}        
        HMENU mb=CreateMenu(); HMENU mf=CreateMenu(); HMENU mh=CreateMenu();
        AppendMenuW(mf, MF_STRING, 2001, L"导入配置");
        AppendMenuW(mf, MF_STRING, 2002, L"导出.xls");
        AppendMenuW(mf, MF_STRING, 2003, L"退出");
        AppendMenuW(mh, MF_STRING, 2101, L"关于");
        AppendMenuW(mb, MF_POPUP, (UINT_PTR)mf, L"文件");
        AppendMenuW(mb, MF_POPUP, (UINT_PTR)mh, L"帮助");
        SetMenu(h, mb);
        hStatus=CreateWindowEx(0, STATUSCLASSNAMEW, L"", WS_CHILD|WS_VISIBLE|SBARS_SIZEGRIP, 0,0,0,0, h, 0, 0, 0);
        SendMessageW(hStatus, SB_SETTEXT, 0, (LPARAM)L"就绪");
        break;}
    case WM_COMMAND:{
        if (LOWORD(w)==IDC_GEN || LOWORD(w)==IDC_EXPORT || LOWORD(w)==2002){
            wchar_t wt[64], wm[64], wsn[64], wc[64], wo[128], wp[64];
            GetWindowTextW(hType, wt, 64); GetWindowTextW(hModel, wm, 64);
            GetWindowTextW(hSnStart, wsn, 64); GetWindowTextW(hCount, wc, 64);
            GetWindowTextW(hOut, wo, 128); GetWindowTextW(hPreview, wp, 64);
            char t[64], m[64], o[128]; WideCharToMultiByte(CP_UTF8,0,wt,-1,t,64,0,0); WideCharToMultiByte(CP_UTF8,0,wm,-1,m,64,0,0); WideCharToMultiByte(CP_UTF8,0,wo,-1,o,128,0,0);
            int snStart = _wtoi(wsn); int count = _wtoi(wc); int preview = _wtoi(wp);
            std::string err; auto rows = Gen(t,m,snStart,count,err);
            if (!err.empty()){
                std::wstring msg(err.begin(), err.end()); SetWindowTextW(hMsg, msg.c_str());
            } else {
                std::wstring msg=L"生成成功"; SetWindowTextW(hMsg, msg.c_str());
                ListView_DeleteAllItems(hList);
                int n = preview; if (n>(int)rows.size()) n=(int)rows.size();
                for(int i=0;i<n;++i){ auto&r=rows[i]; LVITEMW it{}; it.mask=LVIF_TEXT; it.iItem=i; wchar_t buf[256];
                    swprintf(buf,256,L"%d",r.idx); it.pszText=buf; ListView_InsertItem(hList,&it);
                    wchar_t c1[64],c2[64],c3[64],c4[64],c5[64];
                    MultiByteToWideChar(CP_UTF8,0,r.type.c_str(),-1,c1,64);
                    MultiByteToWideChar(CP_UTF8,0,r.model.c_str(),-1,c2,64);
                    swprintf(c3,64,L"%d",r.sn);
                    MultiByteToWideChar(CP_UTF8,0,r.f10.c_str(),-1,c4,64);
                    MultiByteToWideChar(CP_UTF8,0,r.tail6.c_str(),-1,c5,64);
                    ListView_SetItemText(hList,i,1,c1);
                    ListView_SetItemText(hList,i,2,c2);
                    ListView_SetItemText(hList,i,3,c3);
                    ListView_SetItemText(hList,i,4,c4);
                    ListView_SetItemText(hList,i,5,c5);
                    wchar_t c6[256]; MultiByteToWideChar(CP_UTF8,0,r.did.c_str(),-1,c6,256);
                    ListView_SetItemText(hList,i,6,c6);
                }
                gRows=rows;
                wchar_t sb[128]; swprintf(sb,128,L"生成 %d 条", (int)rows.size()); SendMessageW(hStatus, SB_SETTEXT, 0, (LPARAM)sb);
                if (LOWORD(w)==IDC_EXPORT || LOWORD(w)==2002){
                    wchar_t save[260]; wcscpy(save, L"did_list.xls");
                    OPENFILENAMEW ofn{}; ofn.lStructSize=sizeof(ofn); ofn.hwndOwner=h; ofn.lpstrFilter=L"Excel (*.xls)\0*.xls\0所有文件\0*.*\0"; ofn.lpstrFile=save; ofn.nMaxFile=260; ofn.Flags=OFN_OVERWRITEPROMPT|OFN_PATHMUSTEXIST;
                    if (GetSaveFileNameW(&ofn)){
                        if(WriteXlsW(gRows, save)) MessageBoxW(h, L"导出完成", L"提示", MB_OK); else MessageBoxW(h, L"导出失败", L"错误", MB_OK|MB_ICONERROR);
                    }
            }
        }
        }
        else if (LOWORD(w)==1301){
            OPENFILENAMEW ofn{}; wchar_t path[260]=L""; ofn.lStructSize=sizeof(ofn); ofn.hwndOwner=h; ofn.lpstrFilter=L"配置文件 (*.cfg;*.txt)\0*.cfg;*.txt\0所有文件\0*.*\0"; ofn.lpstrFile=path; ofn.nMaxFile=260; ofn.Flags=OFN_FILEMUSTEXIST|OFN_PATHMUSTEXIST;
            if (GetOpenFileNameW(&ofn)){
                FILE*fp=_wfopen(path,L"rb"); if(fp){ char buf[512]={0}; fread(buf,1,sizeof(buf)-1,fp); fclose(fp);
                    auto getv=[&](const char*key){ const char*p=strstr(buf,key); if(!p) return std::string(); p+=strlen(key); while(*p==' '||*p=='\t'||*p=='=') ++p; std::string v; while(*p && *p!='\r' && *p!='\n') v.push_back(*p++); return v; };
                    auto vt=getv("type"); auto vm=getv("model"); auto vs=getv("snStart"); auto vc=getv("count"); auto vo=getv("out"); auto vp=getv("preview");
                    if(!vt.empty()){ wchar_t w[64]; MultiByteToWideChar(CP_UTF8,0,vt.c_str(),-1,w,64); SetWindowTextW(hType,w);} 
                    if(!vm.empty()){ wchar_t w[64]; MultiByteToWideChar(CP_UTF8,0,vm.c_str(),-1,w,64); SetWindowTextW(hModel,w);} 
                    if(!vs.empty()){ wchar_t w[64]; MultiByteToWideChar(CP_UTF8,0,vs.c_str(),-1,w,64); SetWindowTextW(hSnStart,w);} 
                    if(!vc.empty()){ wchar_t w[64]; MultiByteToWideChar(CP_UTF8,0,vc.c_str(),-1,w,64); SetWindowTextW(hCount,w);} 
                    if(!vo.empty()){ wchar_t w[128]; MultiByteToWideChar(CP_UTF8,0,vo.c_str(),-1,w,128); SetWindowTextW(hOut,w);} 
                    if(!vp.empty()){ wchar_t w[64]; MultiByteToWideChar(CP_UTF8,0,vp.c_str(),-1,w,64); SetWindowTextW(hPreview,w);} 
                    MessageBoxW(h,L"配置已导入",L"提示",MB_OK);
                }
            }
        } else if (LOWORD(w)==2001){ SendMessage(h, WM_COMMAND, (WPARAM)1301, 0); }
        else if (LOWORD(w)==2003){ DestroyWindow(h); }
        else if (LOWORD(w)==2101){ MessageBoxW(h,L"生产SN&DID工具",L"关于",MB_OK); }
        break;
    }
    case WM_DESTROY: PostQuitMessage(0); break;
    default: return DefWindowProc(h,m,w,l);
    }
    return 0;
}

static HICON CreateAppIcon()
{
    HICON hIco = (HICON)LoadIconW(GetModuleHandleW(NULL), MAKEINTRESOURCEW(1));
    if (hIco) return hIco;
    hIco = (HICON)LoadImageW(NULL, L"app.ico", IMAGE_ICON, 32, 32, LR_LOADFROMFILE);
    if (hIco) return hIco;

    const int W = 32, H = 32;
    BITMAPINFO bmi{}; bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = W; bmi.bmiHeader.biHeight = -H; // top-down
    bmi.bmiHeader.biPlanes = 1; bmi.bmiHeader.biBitCount = 32; bmi.bmiHeader.biCompression = BI_RGB;
    void* bits = nullptr;
    HDC hdc = GetDC(NULL);
    HBITMAP color = CreateDIBSection(hdc, &bmi, DIB_RGB_COLORS, &bits, NULL, 0);
    ReleaseDC(NULL, hdc);
    if (!color || !bits) return NULL;

    auto px = (unsigned int*)bits;
    auto put = [&](int x, int y, unsigned int argb){ if(x>=0&&x<W&&y>=0&&y<H) px[y*W + x] = argb; };
    unsigned int blue = 0xFF4D64F8; // ARGB
    // clear
    for (int i=0;i<W*H;i++) px[i]=0x00000000;
    // draw three bars resembling provided logo
    auto drawBar = [&](int x, int w, int h){ for(int yy=H-h; yy<H; ++yy){ for(int xx=x; xx<x+w; ++xx){ put(xx, yy, blue); } } };
    drawBar(4, 8, 14);   // left short
    drawBar(16, 8, 20);  // middle medium
    drawBar(26-2, 8, 28); // right tall (adjusted to fit 32)

    HBITMAP mask = CreateBitmap(W, H, 1, 1, NULL);
    ICONINFO ii{}; ii.fIcon = TRUE; ii.hbmColor = color; ii.hbmMask = mask;
    HICON hicon = CreateIconIndirect(&ii);
    DeleteObject(color); DeleteObject(mask);
    return hicon;
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int){
    int argc = 0; LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv && argc > 1){
        std::string type="", model="", out="did_list.xls"; int snStart=1, count=1, preview=0;
        for (int i=1; i<argc; ++i){
            std::wstring a = argv[i];
            auto w2u = [&](const std::wstring& w){ int len = WideCharToMultiByte(CP_UTF8,0,w.c_str(),-1,NULL,0,NULL,NULL); std::string s; s.resize(len); WideCharToMultiByte(CP_UTF8,0,w.c_str(),-1,&s[0],len,NULL,NULL); if(!s.empty() && s.back()=="\0"[0]) s.pop_back(); return s; };
            if (a == L"-type" && i+1<argc) type = w2u(argv[++i]);
            else if (a == L"-model" && i+1<argc) model = w2u(argv[++i]);
            else if (a == L"-snStart" && i+1<argc) snStart = _wtoi(argv[++i]);
            else if (a == L"-count" && i+1<argc) count = _wtoi(argv[++i]);
            else if (a == L"-out" && i+1<argc) out = w2u(argv[++i]);
            else if (a == L"-preview" && i+1<argc) preview = _wtoi(argv[++i]);
        }
        LocalFree(argv);
        std::string err; auto rows = Gen(type, model, snStart, count, err);
        if (!err.empty()){
            MessageBoxW(0, L"参数错误", L"SN&DID", MB_OK|MB_ICONERROR);
            return 1;
        }
        WriteXls(rows, out);
        return 0;
    }
    INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_WIN95_CLASSES }; InitCommonControlsEx(&icc);
    WNDCLASSW wc{}; wc.lpszClassName=L"SN_GUI"; wc.hInstance=hInst; wc.lpfnWndProc=WndProc; wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);
    wc.hIcon = CreateAppIcon(); wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassW(&wc);
    HWND h = CreateWindowExW(0, L"SN_GUI", L"生产SN&DID工具 v1.1", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 800, 600, 0, 0, hInst, 0);
    HICON small = CreateAppIcon(); SendMessageW(h, WM_SETICON, ICON_SMALL, (LPARAM)small);
    ShowWindow(h, SW_SHOW);
    MSG msg; while (GetMessage(&msg, 0, 0, 0)){ TranslateMessage(&msg); DispatchMessage(&msg);} return 0;
}
