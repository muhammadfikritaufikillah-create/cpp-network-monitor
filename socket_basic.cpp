#include <arpa/inet.h>
#include <iostream>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
using namespace std;

int main() {
  string targetIP = "8.8.8.8"; // Google DNS
  int targetPort = 53;         // Port DNS

  cout << "=== SOCKET BASIC TEST ===" << endl;
  cout << "Target: " << targetIP << ":" << targetPort << endl;
  cout << "Mencoba connect..." << endl;

  // Step 1: Buat socket
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    cout << "ERROR: Gagal buat socket!" << endl;
    return 1;
  }
  cout << "Socket berhasil dibuat. ID: " << sock << endl;

  // Step 2: Setup alamat tujuan
  struct sockaddr_in server;
  server.sin_family = AF_INET;
  server.sin_port = htons(targetPort);
  inet_pton(AF_INET, targetIP.c_str(), &server.sin_addr);

  // Step 3: Set timeout 3 detik
  struct timeval timeout;
  timeout.tv_sec = 3;
  timeout.tv_usec = 0;
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

  // Step 4: Coba connect
  int result = connect(sock, (struct sockaddr *)&server, sizeof(server));

  if (result == 0) {
    cout << "STATUS: Port " << targetPort << " di " << targetIP << " = OPEN!"
         << endl;
  } else {
    cout << "STATUS: Port " << targetPort << " di " << targetIP << " = CLOSED"
         << endl;
  }

  // Step 5: Tutup socket
  close(sock);
  cout << "Socket ditutup." << endl;

  return 0;
}