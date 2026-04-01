#include <arpa/inet.h>
#include <atomic>
#include <ctime>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <mutex>
#include <netinet/in.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>
using namespace std;

// ==================== STRUCT ====================
struct ScanResult {
  string ip;
  int port;
  bool isOpen;
  string service;
  string banner; // NEW: hasil banner grabbing
};

// ==================== UTILITY ====================

// Ambil waktu sekarang
string getCurrentTime() {
  time_t now = time(0);
  char buf[20];
  strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
  return string(buf);
}

// ==================== VALIDASI IP (FIXED) ====================
// Bug fix: sekarang handle leading zeros, broadcast, empty string

bool isValidIP(const string &ip) {
  // Cek kosong
  if (ip.empty())
    return false;

  int dots = 0;
  int num = 0;
  int digitCount = 0;
  bool allZero = true; // Cek apakah semua oktet 0 (0.0.0.0)
  bool allMax = true;  // Cek apakah semua oktet 255 (broadcast)

  for (size_t i = 0; i <= ip.length(); i++) {
    char c = (i < ip.length()) ? ip[i] : '.';
    if (c == '.') {
      if (digitCount == 0)
        return false;
      if (num > 255)
        return false;
      // Cek leading zero (contoh: 01, 001)
      if (digitCount > 1 && ip[i - digitCount] == '0')
        return false;

      if (num != 0)
        allZero = false;
      if (num != 255)
        allMax = false;

      dots++;
      num = 0;
      digitCount = 0;
    } else if (c >= '0' && c <= '9') {
      num = num * 10 + (c - '0');
      digitCount++;
      if (digitCount > 3)
        return false;
    } else {
      return false;
    }
  }

  if (dots != 4)
    return false;

  // Tolak 0.0.0.0 dan 255.255.255.255
  if (allZero || allMax)
    return false;

  return true;
}

// Validasi port
bool isValidPort(int port) { return port >= 1 && port <= 65535; }

// ==================== INPUT HELPER ====================
// Baca integer dengan validasi — gak crash kalau user ketik huruf

int readInt(const string &prompt) {
  int value;
  while (true) {
    cout << prompt;
    if (cin >> value) {
      return value;
    }
    // User ketik bukan angka — bersihkan cin
    cin.clear();
    cin.ignore(10000, '\n');
    cout << "  ERROR: Masukkan angka yang valid!" << endl;
  }
}

string readString(const string &prompt) {
  string value;
  cout << prompt;
  cin >> value;
  return value;
}

string readIPWithValidation(const string &prompt) {
  while (true) {
    string ip = readString(prompt);
    if (isValidIP(ip)) {
      return ip;
    }
    cout << "  ERROR: Format IP tidak valid! Contoh: 192.168.1.1" << endl;
    cout << "  (Tidak boleh: 0.0.0.0, 255.255.255.255, atau leading zero)"
         << endl;
  }
}

int readPortWithValidation(const string &prompt) {
  while (true) {
    int port = readInt(prompt);
    if (isValidPort(port)) {
      return port;
    }
    cout << "  ERROR: Port harus antara 1-65535!" << endl;
  }
}

// ==================== PROGRESS BAR ====================

void showProgressBar(int current, int total, int openCount) {
  int barWidth = 30;
  float progress = (float)current / (float)total;
  int filled = (int)(progress * barWidth);

  cout << "\r  [";
  for (int i = 0; i < barWidth; i++) {
    if (i < filled)
      cout << "█";
    else
      cout << "░";
  }
  cout << "] " << (int)(progress * 100) << "% "
       << "(" << current << "/" << total << ") "
       << "Open: " << openCount << "  " << flush;
}

// ==================== SERVICE NAME ====================

string getServiceName(int port) {
  switch (port) {
  case 21:
    return "FTP";
  case 22:
    return "SSH";
  case 23:
    return "Telnet";
  case 25:
    return "SMTP";
  case 53:
    return "DNS";
  case 80:
    return "HTTP";
  case 110:
    return "POP3";
  case 135:
    return "RPC";
  case 139:
    return "NetBIOS";
  case 143:
    return "IMAP";
  case 443:
    return "HTTPS";
  case 445:
    return "SMB";
  case 3306:
    return "MySQL";
  case 3389:
    return "RDP";
  case 5432:
    return "PostgreSQL";
  case 6379:
    return "Redis";
  case 8080:
    return "HTTP-Alt";
  case 8443:
    return "HTTPS-Alt";
  default:
    return "Unknown";
  }
}

// ==================== PORT CHECKER ====================
// Versi cepat — non-blocking connect + select timeout

bool isPortOpen(const string &ip, int port, int timeoutMs = 1000) {
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    return false;

  // Set non-blocking
  int flags = fcntl(sock, F_GETFL, 0);
  fcntl(sock, F_SETFL, flags | O_NONBLOCK);

  struct sockaddr_in server;
  server.sin_family = AF_INET;
  server.sin_port = htons(port);
  inet_pton(AF_INET, ip.c_str(), &server.sin_addr);

  int result = connect(sock, (struct sockaddr *)&server, sizeof(server));

  if (result == 0) {
    close(sock);
    return true;
  }

  // Tunggu pake select() dengan timeout
  fd_set fdset;
  FD_ZERO(&fdset);
  FD_SET(sock, &fdset);

  struct timeval tv;
  tv.tv_sec = timeoutMs / 1000;
  tv.tv_usec = (timeoutMs % 1000) * 1000;

  result = select(sock + 1, NULL, &fdset, NULL, &tv);

  if (result > 0) {
    int so_error;
    socklen_t len = sizeof(so_error);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
    close(sock);
    return so_error == 0;
  }

  close(sock);
  return false;
}

// ==================== BANNER GRABBING (NEW!) ====================
// Konek ke port yang open, kirim request, baca response
// Ini yang dipake security engineer buat deteksi versi software

string grabBanner(const string &ip, int port, int timeoutMs = 2000) {
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    return "";

  // Set timeout untuk recv
  struct timeval timeout;
  timeout.tv_sec = timeoutMs / 1000;
  timeout.tv_usec = (timeoutMs % 1000) * 1000;
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

  struct sockaddr_in server;
  server.sin_family = AF_INET;
  server.sin_port = htons(port);
  inet_pton(AF_INET, ip.c_str(), &server.sin_addr);

  if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
    close(sock);
    return "";
  }

  // Beberapa service langsung kirim banner (SSH, FTP, SMTP)
  // Untuk HTTP, kita harus kirim request dulu
  if (port == 80 || port == 8080 || port == 443 || port == 8443) {
    string httpReq = "HEAD / HTTP/1.0\r\nHost: " + ip + "\r\n\r\n";
    send(sock, httpReq.c_str(), httpReq.length(), 0);
  } else if (port == 3306) {
    // MySQL langsung kirim greeting, gak perlu kirim apa-apa
  } else {
    // Service lain (SSH, FTP, SMTP) biasanya langsung kirim banner
    // Tunggu aja response-nya
  }

  // Baca response
  char buffer[1024];
  memset(buffer, 0, sizeof(buffer));
  int bytesRead = (int)recv(sock, buffer, sizeof(buffer) - 1, 0);
  close(sock);

  if (bytesRead <= 0)
    return "";

  // Bersihkan banner — ambil baris pertama aja, hapus karakter aneh
  string banner(buffer, bytesRead);

  // Ambil baris pertama
  size_t newline = banner.find('\n');
  if (newline != string::npos) {
    banner = banner.substr(0, newline);
  }

  // Hapus \r di akhir
  if (!banner.empty() && banner.back() == '\r') {
    banner.pop_back();
  }

  // Hapus karakter non-printable
  string clean;
  for (char c : banner) {
    if (c >= 32 && c < 127) {
      clean += c;
    }
  }

  // Limit panjang banner
  if (clean.length() > 80) {
    clean = clean.substr(0, 80) + "...";
  }

  return clean;
}

// Cek host aktif
bool isHostAlive(const string &ip) {
  return isPortOpen(ip, 80, 500) || isPortOpen(ip, 22, 500) ||
         isPortOpen(ip, 443, 500);
}

// ==================== SAVE RESULTS ====================

void saveToFile(const vector<ScanResult> &results, const string &ip,
                const string &scanType) {
  string filename = "scan_" + ip + "_" + scanType + ".txt";
  ofstream f(filename);

  f << "================================================" << endl;
  f << "         NETWORK MONITOR v2.1 - SCAN RESULTS    " << endl;
  f << "================================================" << endl;
  f << "Scan Type : " << scanType << endl;
  f << "Target    : " << ip << endl;
  f << "Time      : " << getCurrentTime() << endl;
  f << "------------------------------------------------" << endl;

  int openCount = 0;
  for (const auto &r : results) {
    if (r.isOpen) {
      f << "[OPEN]   Port " << r.port << "\t- " << r.service;
      if (!r.banner.empty()) {
        f << "\t| Banner: " << r.banner;
      }
      f << endl;
      openCount++;
    } else {
      f << "[CLOSED] Port " << r.port << "\t- " << r.service << endl;
    }
  }

  f << "------------------------------------------------" << endl;
  f << "Total open  : " << openCount << endl;
  f << "Total scan  : " << results.size() << endl;
  f.close();
  cout << "\nHasil disimpan ke: " << filename << endl;
}

// ==================== FITUR 1: PORT SCANNER ====================

void runPortScanner() {
  cout << "\n=== PORT SCANNER ===" << endl;

  string targetIP = readIPWithValidation("Masukkan IP target  : ");
  int startPort = readPortWithValidation("Port mulai dari     : ");
  int endPort = readPortWithValidation("Port sampai         : ");

  if (startPort > endPort) {
    cout << "ERROR: Port mulai tidak boleh lebih besar dari port akhir!"
         << endl;
    return;
  }

  int totalPorts = endPort - startPort + 1;
  cout << "\nScanning " << targetIP << " port " << startPort << "-" << endPort
       << " (" << totalPorts << " ports)..." << endl;
  cout << "------------------------------------" << endl;

  vector<ScanResult> results(totalPorts);
  atomic<int> scannedCount(0);
  atomic<int> openCount(0);
  mutex printMtx;

  // Fungsi scan per thread
  auto scanWorker = [&](int threadStart, int threadEnd) {
    for (int port = threadStart; port <= threadEnd; port++) {
      bool open = isPortOpen(targetIP, port);
      string svc = getServiceName(port);
      string banner = "";

      // Banner grab kalau port open
      if (open) {
        banner = grabBanner(targetIP, port);
      }

      int idx = port - startPort;
      results[idx] = {targetIP, port, open, svc, banner};

      if (open) {
        openCount++;
        lock_guard<mutex> lock(printMtx);
        cout << "\r  [OPEN]   Port " << port << " - " << svc;
        if (!banner.empty()) {
          cout << " | " << banner;
        }
        cout << "                    " << endl;
      }
      scannedCount++;
    }
  };

  // Bagi kerja ke beberapa thread (max 10 thread)
  int numThreads = min(10, totalPorts);
  vector<thread> threads;
  int portsPerThread = totalPorts / numThreads;

  for (int t = 0; t < numThreads; t++) {
    int tStart = startPort + t * portsPerThread;
    int tEnd = (t == numThreads - 1) ? endPort : tStart + portsPerThread - 1;
    threads.emplace_back(scanWorker, tStart, tEnd);
  }

  // Progress bar di main thread
  while (scannedCount < totalPorts) {
    showProgressBar(scannedCount, totalPorts, openCount);
    this_thread::sleep_for(chrono::milliseconds(100));
  }
  showProgressBar(totalPorts, totalPorts, openCount);

  // Tunggu semua thread selesai
  for (auto &t : threads) {
    t.join();
  }

  cout << "\n------------------------------------" << endl;
  cout << "Selesai! Open: " << openCount << "/" << totalPorts << " port"
       << endl;
  saveToFile(results, targetIP, "portscan");
}

// ==================== FITUR 2: QUICK SCAN ====================

void runQuickScan() {
  cout << "\n=== QUICK SCAN (Top 20 Ports) ===" << endl;

  string ip = readIPWithValidation("IP Target : ");

  vector<int> topPorts = {21,   22,   23,   25,   53,   80,   110,
                          135,  139,  143,  443,  445,  3306, 3389,
                          5432, 6379, 8080, 8443, 8888, 9090};

  int total = (int)topPorts.size();
  cout << "\nScanning " << ip << "..." << endl;
  cout << "------------------------------------" << endl;

  vector<ScanResult> results(total);
  atomic<int> scannedCount(0);
  atomic<int> openCount(0);
  mutex printMtx;

  // Multi-thread — tiap port 1 thread (cuma 20, aman)
  vector<thread> threads;
  for (int i = 0; i < total; i++) {
    threads.emplace_back([&, i]() {
      int port = topPorts[i];
      bool open = isPortOpen(ip, port, 800);
      string svc = getServiceName(port);
      string banner = "";

      if (open) {
        banner = grabBanner(ip, port);
      }

      results[i] = {ip, port, open, svc, banner};

      if (open) {
        openCount++;
        lock_guard<mutex> lock(printMtx);
        cout << "\r  [OPEN]   Port " << port << " - " << svc;
        if (!banner.empty()) {
          cout << " | " << banner;
        }
        cout << "                    " << endl;
      }
      scannedCount++;
    });
  }

  // Progress bar
  while (scannedCount < total) {
    showProgressBar(scannedCount, total, openCount);
    this_thread::sleep_for(chrono::milliseconds(100));
  }
  showProgressBar(total, total, openCount);

  for (auto &t : threads) {
    t.join();
  }

  cout << "\n------------------------------------" << endl;
  cout << "Selesai! Open: " << openCount << "/" << total << " port" << endl;
  saveToFile(results, ip, "quickscan");
}

// ==================== FITUR 3: HOST DISCOVERY ====================

void runHostDiscovery() {
  cout << "\n=== HOST DISCOVERY ===" << endl;
  string baseIP = readString("Masukkan base IP (contoh: 192.168.1): ");

  int hostCount = 20;
  cout << "\nScanning " << baseIP << ".1 - " << baseIP << "." << hostCount
       << "..." << endl;
  cout << "------------------------------------" << endl;

  vector<string> aliveHosts;
  mutex mtx;
  atomic<int> scannedCount(0);
  atomic<int> aliveCount(0);

  // Multi-thread host discovery
  vector<thread> threads;
  for (int i = 1; i <= hostCount; i++) {
    threads.emplace_back([&, i]() {
      string ip = baseIP + "." + to_string(i);
      if (isHostAlive(ip)) {
        aliveCount++;
        lock_guard<mutex> lock(mtx);
        cout << "\r  [ALIVE]  " << ip << "                    " << endl;
        aliveHosts.push_back(ip);
      }
      scannedCount++;
    });
  }

  // Progress bar
  while (scannedCount < hostCount) {
    showProgressBar(scannedCount, hostCount, aliveCount);
    this_thread::sleep_for(chrono::milliseconds(100));
  }
  showProgressBar(hostCount, hostCount, aliveCount);

  for (auto &t : threads) {
    t.join();
  }

  cout << "\n------------------------------------" << endl;
  cout << "Selesai! " << aliveHosts.size() << " host aktif ditemukan." << endl;

  string filename = "hosts_" + baseIP + ".txt";
  ofstream f(filename);
  f << "HOST DISCOVERY RESULTS" << endl;
  f << "Base IP : " << baseIP << ".x" << endl;
  f << "Time    : " << getCurrentTime() << endl;
  f << "------------------------" << endl;
  for (const auto &h : aliveHosts) {
    f << "[ALIVE] " << h << endl;
  }
  f << "------------------------" << endl;
  f << "Total alive: " << aliveHosts.size() << endl;
  f.close();
  cout << "Hasil disimpan ke: " << filename << endl;
}

// ==================== FITUR 4: BANNER GRAB ONLY (NEW!) ====================
// Scan port yang open, terus grab banner dari tiap port

void runBannerGrab() {
  cout << "\n=== BANNER GRABBING ===" << endl;
  cout << "(Deteksi versi software di balik port yang open)" << endl;

  string ip = readIPWithValidation("IP Target : ");

  vector<int> topPorts = {21,  22,   23,   25,   53,   80,   110,  143,  443,
                          445, 3306, 3389, 5432, 6379, 8080, 8443, 8888, 9090};

  int total = (int)topPorts.size();
  cout << "\nScanning & grabbing banners dari " << ip << "..." << endl;
  cout << "------------------------------------" << endl;

  atomic<int> scannedCount(0);
  atomic<int> openCount(0);
  mutex printMtx;

  struct BannerResult {
    int port;
    string service;
    string banner;
  };
  vector<BannerResult> found;
  mutex foundMtx;

  vector<thread> threads;
  for (int i = 0; i < total; i++) {
    threads.emplace_back([&, i]() {
      int port = topPorts[i];
      if (isPortOpen(ip, port, 800)) {
        openCount++;
        string svc = getServiceName(port);
        string banner = grabBanner(ip, port);

        lock_guard<mutex> lock(printMtx);
        cout << "\r  Port " << port << " (" << svc << ") OPEN";
        if (!banner.empty()) {
          cout << " => " << banner;
        } else {
          cout << " => (no banner)";
        }
        cout << "                    " << endl;

        lock_guard<mutex> lock2(foundMtx);
        found.push_back({port, svc, banner});
      }
      scannedCount++;
    });
  }

  // Progress bar
  while (scannedCount < total) {
    showProgressBar(scannedCount, total, openCount);
    this_thread::sleep_for(chrono::milliseconds(100));
  }
  showProgressBar(total, total, openCount);

  for (auto &t : threads) {
    t.join();
  }

  cout << "\n------------------------------------" << endl;
  cout << "Selesai! " << openCount << " port open ditemukan." << endl;

  // Simpan ke file
  if (!found.empty()) {
    string filename = "banner_" + ip + ".txt";
    ofstream f(filename);
    f << "================================================" << endl;
    f << "       BANNER GRABBING RESULTS                  " << endl;
    f << "================================================" << endl;
    f << "Target : " << ip << endl;
    f << "Time   : " << getCurrentTime() << endl;
    f << "------------------------------------------------" << endl;
    for (const auto &b : found) {
      f << "Port " << b.port << " (" << b.service << ")";
      if (!b.banner.empty()) {
        f << " => " << b.banner;
      } else {
        f << " => (no banner)";
      }
      f << endl;
    }
    f << "------------------------------------------------" << endl;
    f << "Total open: " << found.size() << endl;
    f.close();
    cout << "Hasil disimpan ke: " << filename << endl;
  }
}

// ==================== MAIN MENU ====================

int main() {
  while (true) {
    cout << "\n================================================" << endl;
    cout << "         NETWORK MONITOR v2.1                   " << endl;
    cout << "         by Muhammad Fikri Taufikillah           " << endl;
    cout << "================================================" << endl;
    cout << "  1. Port Scanner (custom range)  [MULTI-THREAD]" << endl;
    cout << "  2. Quick Scan (top 20 ports)    [MULTI-THREAD]" << endl;
    cout << "  3. Host Discovery               [MULTI-THREAD]" << endl;
    cout << "  4. Banner Grabbing              [NEW!]        " << endl;
    cout << "  0. Exit" << endl;
    cout << "------------------------------------------------" << endl;

    int pilihan = readInt("Pilihan : ");

    switch (pilihan) {
    case 1:
      runPortScanner();
      break;
    case 2:
      runQuickScan();
      break;
    case 3:
      runHostDiscovery();
      break;
    case 4:
      runBannerGrab();
      break;
    case 0:
      cout << "\nTerima kasih! Sampai jumpa." << endl;
      return 0;
    default:
      cout << "Pilihan tidak valid! Masukkan 0-4." << endl;
    }
  }

  return 0;
}