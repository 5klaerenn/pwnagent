#include <stdio.h>
#include <unistd.h>

void win() { printf("flag{test}\n"); }

void vuln() {
  char buf[64];
  read(0, buf, 256);
}

int main() {
  vuln();
  return 0;
}
