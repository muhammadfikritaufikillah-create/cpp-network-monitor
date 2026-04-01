#include <arpa/inet.h>
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>
using namespace std;

// Struct untuk simpan hasil scan
struct ScanResult {
  string ip;
  int port;
  bool isOpen;
  string service;
};

// Fungsi: deteksi nama service dari nomor port
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
  case 443:
    return "HTTPS";
  case 3306:
    return "MySQL";
  case 8080:
    return "HTTP-Alt";
  default:
    return "Unknown";
  }
}

// Fungsi: cek apakah satu port open atau closed
bool isPortOpen(const string &ip, int port) {
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    return false;

  // Timeout 2 detik supaya tidak nunggu lama
  struct timeval timeout;
  timeout.tv_sec = 2;
  timeout.tv_usec = 0;
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

  struct sockaddr_in server;
  server.sin_family = AF_INET;
  server.sin_port = htons(port);
  inet_pton(AF_INET, ip.c_str(), &server.sin_addr);

  int result = connect(sock, (struct sockaddr *)&server, sizeof(server));
  close(sock);

  return result == 0;
}

// Fungsi: simpan hasil ke file
void saveResults(const vector<ScanResult> &results, const string &ip) {
  string filename = "scan_" + ip + ".txt";
  ofstream f(filename);

  f << "================================" << endl;
  f << "     NETWORK SCAN RESULTS" << endl;
  f << "================================" << endl;
  f << "Target IP: " << ip << endl;
  f << "--------------------------------" << endl;

  int openCount = 0;
  for (const auto &r : results) {
    if (r.isOpen) {
      f << "[OPEN]   Port " << r.port << " - " << r.service << endl;
      openCount++;
    } else {
      f << "[CLOSED] Port " << r.port << " - " << r.service << endl;
    }
  }

  f << "--------------------------------" << endl;
  f << "Total open: " << openCount << "/" << results.size() << endl;
  f.close();

  cout << "\nHasil disimpan ke: " << filename << endl;
}

int main() {
  string targetIP;
  int startPort, endPort;

  cout << "================================" << endl;
  cout << "     SIMPLE PORT SCANNER v1" << endl;
  cout << "================================" << endl;
  cout << "Masukkan IP target  : ";
  cin >> targetIP;
  cout << "Port mulai dari     : ";
  cin >> startPort;
  cout << "Port sampai         : ";
  cin >> endPort;

  cout << "\nScanning " << targetIP;
  cout << " port " << startPort << "-" << endPort << endl;
  cout << "--------------------------------" << endl;

  vector<ScanResult> results;
  int openCount = 0;

  for (int port = startPort; port <= endPort; port++) {
    cout << "Checking port " << port << "...\r" << flush;

    bool open = isPortOpen(targetIP, port);
    string service = getServiceName(port);

    results.push_back({targetIP, port, open, service});

    if (open) {
      cout << "[OPEN]   Port " << port << " - " << service << "          "
           << endl;
      openCount++;
    }
  }

  cout << "--------------------------------" << endl;
  cout << "Scan selesai!" << endl;
  cout << "Total open: " << openCount << " port" << endl;

  saveResults(results, targetIP);

  return 0;
}