#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>
#include <iostream>

static std::string Sha256(const std::string &s)
{
    HCRYPTPROV hProv = 0; HCRYPTHASH hHash = 0; BYTE rgbHash[32]; DWORD cbHash = 32;
    CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    CryptHashData(hHash, (BYTE*)s.data(), (DWORD)s.size(), 0);
    CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0);
    CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0);
    return std::string((char*)rgbHash, (char*)rgbHash + 32);
}

static std::string Pkcs7(const std::string &in, size_t bs)
{
    size_t pad = bs - (in.size() % bs);
    if (pad == 0) pad = bs;
    std::string out = in; out.resize(in.size() + pad, (char)pad);
    return out;
}

static std::string Base64Encode(const std::string &bin)
{
    DWORD outLen = 0; CryptBinaryToStringA((BYTE*)bin.data(), (DWORD)bin.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &outLen);
    std::string out; out.resize(outLen);
    CryptBinaryToStringA((BYTE*)bin.data(), (DWORD)bin.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &out[0], &outLen);
    if (!out.empty() && out.back() == '\0') out.pop_back();
    return out;
}

static std::string AesCbcEncrypt(const std::string &plain, const std::string &key, const std::string &iv)
{
    HCRYPTPROV hProv = 0; HCRYPTKEY hKey = 0; HCRYPTHASH hHash = 0;
    CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    CryptHashData(hHash, (BYTE*)key.data(), (DWORD)key.size(), 0);
    BYTE raw[32]; DWORD rawLen = 32; CryptGetHashParam(hHash, HP_HASHVAL, raw, &rawLen, 0);
    CryptDestroyHash(hHash);

    struct { BLOBHEADER hdr; DWORD len; BYTE key[32]; } blob;
    blob.hdr.bType = PLAINTEXTKEYBLOB; blob.hdr.bVersion = CUR_BLOB_VERSION; blob.hdr.reserved = 0; blob.hdr.aiKeyAlg = CALG_AES_256;
    blob.len = 32; memcpy(blob.key, raw, 32);
    CryptImportKey(hProv, (BYTE*)&blob, sizeof(blob), 0, 0, &hKey);

    DWORD mode = CRYPT_MODE_CBC; CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0);
    BYTE ivBuf[16]; memcpy(ivBuf, iv.data(), 16); CryptSetKeyParam(hKey, KP_IV, ivBuf, 0);

    std::string data = Pkcs7(plain, 16);
    std::string ct = data; DWORD ctLen = (DWORD)ct.size();
    CryptEncrypt(hKey, 0, TRUE, 0, (BYTE*)&ct[0], &ctLen, (DWORD)ct.size());
    CryptDestroyKey(hKey); CryptReleaseContext(hProv, 0);
    return ct;
}

static char PickAlphaNum(const std::string &s, int startIdx)
{
    int n = (int)s.size();
    for (int k = 0; k < n; ++k) {
        char ch = s[(startIdx + k) % n];
        if ((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')) return ch;
    }
    return '0';
}

static std::string BuildFirst10(const std::string &t, const std::string &m, int sn, std::string &err)
{
    int remain = 10 - ((int)t.size() + (int)m.size());
    if (remain < 1) { err = "前10位长度不合法：产品类型+型号总长度需小于10"; return ""; }
    char buf[64]; sprintf(buf, "%0*d", remain, sn);
    return t + m + std::string(buf);
}

struct Row { int idx; std::string type, model, f10, tail6, did; int sn; };

static std::vector<Row> GenerateRows(const std::string &type, const std::string &model, int snStart, int count, std::string &err)
{
    std::vector<Row> rows; rows.reserve(count);
    for (int i = 0; i < count; ++i) {
        int sn = snStart + i;
        std::string f10 = BuildFirst10(type, model, sn, err);
        if (!err.empty()) return rows;
        std::string key = "123456";
        std::string iv = Sha256(f10).substr(0, 16);
        std::string ct = AesCbcEncrypt(f10, key, iv);
        std::string b64 = Base64Encode(ct);
        int pos[6] = {1,3,6,10,15,21};
        std::string tail(6, '0');
        for (int j = 0; j < 6; ++j) tail[j] = PickAlphaNum(b64, pos[j]-1);
        for (auto &c : tail) c = (char)toupper((unsigned char)c);
        std::string did = f10 + tail;
        rows.push_back({ i+1, type, model, f10, tail, did, sn });
    }
    return rows;
}

static bool WriteXls(const std::vector<Row> &rows, const std::string &name)
{
    std::string fname = name.empty() ? "did_list.xls" : name;
    FILE *fp = fopen(fname.c_str(), "wb"); if (!fp) return false;
    fputs("<!DOCTYPE html><html><head><meta charset=\"utf-8\"></head><body><table border=\"1\"><thead><tr>", fp);
    const char *head[7] = {"#","产品类型","型号","SN","First10","尾6","DID"};
    for (int i = 0; i < 7; ++i) { fprintf(fp, "<th>%s</th>", head[i]); }
    fputs("</tr></thead><tbody>", fp);
    for (auto &r : rows) {
        fprintf(fp, "<tr><td>%d</td><td>%s</td><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td>%s</td></tr>", r.idx, r.type.c_str(), r.model.c_str(), r.sn, r.f10.c_str(), r.tail6.c_str(), r.did.c_str());
    }
    fputs("</tbody></table></body></html>", fp);
    fclose(fp); return true;
}

int main(int argc, char **argv)
{
    std::string type="", model="", out="did_list.xls"; int snStart=1, count=100, preview=10;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "-type" && i+1<argc) { type = argv[++i]; }
        else if (a == "-model" && i+1<argc) { model = argv[++i]; }
        else if (a == "-snStart" && i+1<argc) { snStart = atoi(argv[++i]); }
        else if (a == "-count" && i+1<argc) { count = atoi(argv[++i]); }
        else if (a == "-out" && i+1<argc) { out = argv[++i]; }
        else if (a == "-preview" && i+1<argc) { preview = atoi(argv[++i]); }
    }
    std::string err;
    auto rows = GenerateRows(type, model, snStart, count, err);
    if (!err.empty()) { fprintf(stderr, "%s\n", err.c_str()); return 1; }
    if (preview > (int)rows.size()) preview = (int)rows.size();
    printf("#\t类型\t型号\tSN\tFirst10\t尾6\tDID\n");
    for (int i = 0; i < preview; ++i) {
        auto &r = rows[i];
        printf("%d\t%s\t%s\t%d\t%s\t%s\t%s\n", r.idx, r.type.c_str(), r.model.c_str(), r.sn, r.f10.c_str(), r.tail6.c_str(), r.did.c_str());
    }
    if (!WriteXls(rows, out)) { fprintf(stderr, "导出失败: %s\n", out.c_str()); return 2; }
    printf("导出完成: %s\n", out.c_str());
    return 0;
}
