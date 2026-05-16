# Secure SOCKS5 Tunneling Proxy & Firewall

A high-performance, multi-threaded secure tunneling application implemented in **C** and **C++**. This project establishes an encrypted tunnel between a custom client and a backend server, routing browser traffic safely using a local SOCKS5 proxy and utilizing a built-in rate-limiting firewall for enhanced security.

## 🚀 Key Features

* **Secure TLS Tunneling:** Full encryption of data packets between the client and server using the **OpenSSL API**.
* **Multi-Threaded Architecture:** Backend server handles multiple concurrent client connections efficiently using the **Win32 Threads API** and critical sections to prevent race conditions.
* **Local SOCKS5 Proxy:** Client-side background thread acts as a local proxy, catching and packaging browser network traffic.
* **Embedded Browser UI:** A Native Win32 desktop application featuring an embedded **Microsoft WebView2** engine for a seamless, secure browsing experience.
* **Active Firewall & Rate Limiting:** Server-side connection and authentication tracking to actively drop DoS/Brute-Force attacks and filter system telemetry.

---

## 🛠️ Tech Stack & Prerequisites

* **Language:** C (Core Logic & Server), C++ (WebView2 Handler)
* **OS Environment:** Windows 10 / 11 (64-bit)
* **IDE/Compiler:** Visual Studio 2022 (MSVC)
* **Dependencies:**
    * `Winsock2` (Windows Sockets API)
    * `OpenSSL SDK` (v3.x or v1.1.x)
    * `Microsoft.Web.WebView2` (Installed via NuGet Package Manager)

---

## 📁 Repository Structure

```text
├── Server/
│   ├── server.c             # Multi-threaded backend server & firewall logic
│   └── users.db             # Dynamic user database (Generated at runtime)
│
├── Client/
│   ├── client.c             # Win32 Native UI & Main Window Loop
│   ├── proxy_client.c       # Background SOCKS5 proxy thread logic
│   └── webview_handler.cc   # Embedded Microsoft WebView2 browser initialization
│
└── .gitignore               # Excludes keys, certificates, binaries, and build files

to generate key and certificate to run the server run the following command in powershell/terminal:
openssl req -x509 -nodes -newkey rsa:4096 -keyout private.key -out certificate.crt -sha256 -days 365
