#pragma once

#include <stdio.h>
#include <string.h>

// CLI and parsing helpers shared by the firewall tables (FirewallTable, RoutePolicy, HopPolicy), which inherit
// them privately.

#define TABLE_REPLY_MAX    140   // longest table CLI reply before it ends with " +N more"

class TableCli {
protected:
  // Adds a page line at reply[n], or counts it in 'more' if the reply would get too long. Returns the length.
  static int addLine(char* reply, int n, const char* item, int len, int& more) {
    if (n + 1 + len > TABLE_REPLY_MAX) {
      more++;
      return n;
    }
    if (n > 0) reply[n++] = '\n';
    strcpy(&reply[n], item);
    return n + len;
  }

  // Reads a number at 'p' (then a space or the end) and moves past it and any spaces. -1 if there's none.
  static int parseSlotNumber(const char*& p) {
    if (*p < '0' || *p > '9') return -1;
    int n = 0;
    while (*p >= '0' && *p <= '9') {
      n = n * 10 + (*p - '0');
      if (n > 999) return -1;
      p++;
    }
    if (*p != 0 && *p != ' ') return -1;
    while (*p == ' ') p++;
    return n;
  }

  // Adds slot 'i' to a slot list being written at reply[n] (eg. "0,1,2"). Returns the new length.
  static int addSlotToList(char* reply, int n, int i) {
    if (n == 0) return sprintf(reply, "%d", i);
    return n + sprintf(&reply[n], ",%d", i);
  }

  // true if the field starts with the 2-letter 'key'
  static bool isKey(const char* field, const char* key) {
    return field[0] == key[0] && field[1] == key[1];
  }

  // "unknown field xx" error, naming the field's key (the message is only valid until the next call)
  static const char* unknownField(const char* field) {
    static char msg[] = "unknown field xx";
    msg[sizeof(msg) - 3] = field[0];
    msg[sizeof(msg) - 2] = field[1];
    return msg;
  }

  // true if s (len characters) is exactly 'word'
  static bool isWord(const char* s, int len, const char* word) {
    int i = 0;
    while (i < len && word[i] != 0 && s[i] == word[i]) i++;
    return i == len && word[i] == 0;
  }
};
