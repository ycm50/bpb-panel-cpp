#pragma once
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace bpb::net::httpc {

struct Response {
    int status = 0;
    std::string body;
    std::map<std::string, std::string> headers;
    std::string header(const std::string& name) const;
};

using Headers = std::vector<std::pair<std::string, std::string>>;

bool request(const std::string& method,
             const std::string& url,
             const std::string& body,
             const Headers& headers,
             Response& out,
             std::string& error,
             int timeout_ms = 10000);

bool get(const std::string& url, Response& out, std::string& error, int timeout_ms = 10000,
         const Headers& headers = {});

bool post(const std::string& url, const std::string& body, Response& out, std::string& error,
          int timeout_ms = 15000, const Headers& headers = {});

struct Url {
    std::string scheme;
    std::string host;
    int port = 80;
    std::string path;
};

bool parse_url(const std::string& url, Url& out, std::string& error);

} // namespace bpb::net::httpc
