#pragma once

// Text file helpers for saving the firewall tables. Expects the filesystem (FILESYSTEM, File) to be included
// first, as MyMesh.h does.

// Opens 'filename' for writing, replacing any existing file (the same as RegionMap's openWrite()).
inline File tableFileOpenWrite(FILESYSTEM* fs, const char* filename) {
  #if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
    fs->remove(filename);
    return fs->open(filename, FILE_O_WRITE);
  #elif defined(RP2040_PLATFORM)
    return fs->open(filename, "w");
  #else
    return fs->open(filename, "w", true);
  #endif
}

// Opens 'filename' for reading. Check the result before using it.
inline File tableFileOpenRead(FILESYSTEM* fs, const char* filename) {
  #if defined(RP2040_PLATFORM)
    return fs->open(filename, "r");
  #else
    return fs->open(filename);
  #endif
}

// Writes 'text' and a newline. Returns false if not everything was written.
inline bool tableFileWriteLine(File& file, const char* text) {
  size_t len = strlen(text);
  if (file.write((const uint8_t*)text, len) != len) return false;
  return file.write((const uint8_t*)"\n", 1) == 1;
}

// Reads one line (without '\r' / '\n') into 'line', at most 'max' characters ('too_long' if more). Returns false
// at the end of the file.
inline bool tableFileReadLine(File& file, char* line, int max, bool& too_long) {
  int len = 0;
  bool any = false;
  too_long = false;
  while (file.available()) {
    int c = file.read();
    if (c < 0) break;
    any = true;
    if (c == '\n') break;
    if (c == '\r') continue;
    if (len < max) {
      line[len++] = (char)c;
    } else {
      too_long = true;
    }
  }
  line[len] = 0;
  return any;
}
