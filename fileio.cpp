#include <fstream>
#include <iostream>
#include <string>
#include <vector>
using namespace std;

struct ScanResult {
  string ip;
  int port;
  bool isOpen;
  string service;
};

void saveToFile(const vector<ScanResult> &results, const string &filename) {
  ofstream logFile(filename);

  if (!logFile.is_open()) {
    cout << "ERROR: Tidak bisa buat file " << filename << endl;
    return;
  }

  logFile << "================================" << endl;
  logFile << "      NETWORK SCAN RESULTS      " << endl;
  logFile << "================================" << endl;
  logFile << "Target: " << results[0].ip << endl;
  logFile << "Total port diperiksa: " << results.size() << endl;
  logFile << "--------------------------------" << endl;

  int openCount = 0;
  for (const auto &r : results) {
    if (r.isOpen) {
      logFile << "[OPEN]   Port " << r.port << " - " << r.service << endl;
      openCount++;
    } else {
      logFile << "[CLOSED] Port " << r.port << " - " << r.service << endl;
    }
  }

  logFile << "--------------------------------" << endl;
  logFile << "Total open: " << openCount << endl;
  logFile.close();

  cout << "Hasil scan disimpan ke file: " << filename << endl;
}

void readFromFile(const string &filename) {
  ifstream logFile(filename);

  if (!logFile.is_open()) {
    cout << "ERROR: File tidak ditemukan!" << endl;
    return;
  }

  cout << "\n=== ISI FILE " << filename << " ===" << endl;
  string line;
  while (getline(logFile, line)) {
    cout << line << endl;
  }
  logFile.close();
}

int main() {
  vector<ScanResult> results = {
      {"192.168.1.1", 80, true, "HTTP"},    {"192.168.1.1", 443, true, "HTTPS"},
      {"192.168.1.1", 22, false, "SSH"},    {"192.168.1.1", 21, false, "FTP"},
      {"192.168.1.1", 3306, true, "MySQL"},
  };

  saveToFile(results, "hasil_scan.txt");
  readFromFile("hasil_scan.txt");

  return 0;
}