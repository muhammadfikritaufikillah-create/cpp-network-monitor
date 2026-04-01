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

int main() {
  vector<ScanResult> results;

  ScanResult r1;
  r1.ip = "192.168.1.1";
  r1.port = 80;
  r1.isOpen = true;
  r1.service = "HTTP";
  results.push_back(r1);

  ScanResult r2;
  r2.ip = "192.168.1.1";
  r2.port = 443;
  r2.isOpen = true;
  r2.service = "HTTPS";
  results.push_back(r2);

  ScanResult r3;
  r3.ip = "192.168.1.1";
  r3.port = 22;
  r3.isOpen = false;
  r3.service = "SSH";
  results.push_back(r3);

  cout << "=== HASIL SCAN ===" << endl;
  cout << "IP\t\tPort\tService\tStatus" << endl;
  cout << "------------------------------------" << endl;

  for (auto &r : results) {
    cout << r.ip << "\t" << r.port << "\t" << r.service << "\t"
         << (r.isOpen ? "OPEN" : "CLOSED") << endl;
  }

  return 0;
}