# Radare2 MCP - Tool Call Spezifikation

> Vollstaendige Definition aller MCP Tool Calls fuer den radare2 MCP Server.
> Jeder Tool Call ist mit Name, Beschreibung, Parametern (JSON Schema), Output-Format,
> internem r2-Befehl und Beispiel dokumentiert.

---

## Inhaltsverzeichnis

1. [Session Management](#1-session-management)
2. [Binary Analysis](#2-binary-analysis)
3. [ESIL Emulation](#3-esil-emulation)
4. [Shellcode Analysis](#4-shellcode-analysis)
5. [Memory und Navigation](#5-memory-und-navigation)
6. [Advanced](#6-advanced)

---

## 1. Session Management

### 1.1 `open_binary`

**Beschreibung:** Oeffnet ein Binary in radare2 und erstellt eine neue Analyse-Session. Optional kann eine automatische Analyse (aaa) direkt ausgefuehrt werden. Dies ist typischerweise der erste Aufruf in jedem Reverse-Engineering-Workflow.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "file_path": {
      "type": "string",
      "description": "Absoluter oder relativer Pfad zum Binary"
    },
    "analyze": {
      "type": "boolean",
      "default": true,
      "description": "Automatische Analyse (aaa) nach dem Oeffnen ausfuehren"
    },
    "load_address": {
      "type": "string",
      "default": null,
      "description": "Basisadresse zum Laden (hex, z.B. '0x400000'). Null fuer Auto-Detect."
    },
    "architecture": {
      "type": "string",
      "default": null,
      "description": "Architektur erzwingen (z.B. 'x86', 'arm', 'mips'). Null fuer Auto-Detect."
    },
    "bits": {
      "type": "integer",
      "enum": [8, 16, 32, 64],
      "default": null,
      "description": "Bitbreite erzwingen. Null fuer Auto-Detect."
    },
    "raw": {
      "type": "boolean",
      "default": false,
      "description": "Als Raw-Binary oeffnen (kein Format-Parsing, noetig fuer Shellcode)"
    }
  },
  "required": ["file_path"]
}
```

**Output-Format:**
```json
{
  "session_id": "string (UUID)",
  "file": "string (Dateipfad)",
  "format": "string (z.B. 'elf64', 'pe32', 'raw')",
  "architecture": "string (z.B. 'x86')",
  "bits": 64,
  "size": 12345,
  "analyzed": true
}
```

**r2-Befehl:** `r2 [-b bits] [-a arch] [-B baddr] [-n] <file>` gefolgt von `aaa` wenn `analyze=true`

**Beispiel:**
```
Input:  { "file_path": "/tmp/malware.elf", "analyze": true }
Output: {
  "session_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "file": "/tmp/malware.elf",
  "format": "elf64",
  "architecture": "x86",
  "bits": 64,
  "size": 54321,
  "analyzed": true
}
```

---

### 1.2 `close_session`

**Beschreibung:** Schliesst eine radare2-Session und gibt alle Ressourcen frei. Sollte aufgerufen werden, wenn die Analyse abgeschlossen ist.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "description": "UUID der zu schliessenden Session"
    }
  },
  "required": ["session_id"]
}
```

**Output-Format:**
```json
{
  "closed": true,
  "session_id": "string"
}
```

**r2-Befehl:** `r2pipe.quit()` / internes Session-Management

**Beispiel:**
```
Input:  { "session_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890" }
Output: { "closed": true, "session_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890" }
```

---

### 1.3 `list_sessions`

**Beschreibung:** Listet alle aktuell offenen radare2-Sessions auf. Nuetzlich um den Ueberblick ueber mehrere parallele Analysen zu behalten.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {},
  "required": []
}
```

**Output-Format:**
```json
{
  "sessions": [
    {
      "session_id": "string",
      "file": "string",
      "format": "string",
      "architecture": "string",
      "bits": 64,
      "opened_at": "string (ISO 8601)"
    }
  ],
  "count": 1
}
```

**r2-Befehl:** Internes Session-Management (kein direkter r2-Befehl)

**Beispiel:**
```
Input:  {}
Output: {
  "sessions": [
    {
      "session_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "file": "/tmp/malware.elf",
      "format": "elf64",
      "architecture": "x86",
      "bits": 64,
      "opened_at": "2026-02-28T14:30:00Z"
    }
  ],
  "count": 1
}
```

---

## 2. Binary Analysis

### 2.1 `analyze_binary`

**Beschreibung:** Fuehrt eine automatische Analyse des geladenen Binaries durch. Verschiedene Analyse-Tiefen sind verfuegbar. Dies identifiziert Funktionen, Strings, Cross-References und weitere Strukturen.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "description": "Session-ID des geoeffneten Binaries"
    },
    "level": {
      "type": "string",
      "enum": ["basic", "calls", "full", "experimental"],
      "default": "full",
      "description": "Analyse-Tiefe: basic=aa, calls=aac, full=aaa, experimental=aaaa"
    }
  },
  "required": ["session_id"]
}
```

**Output-Format:**
```json
{
  "functions_found": 142,
  "strings_found": 87,
  "xrefs_found": 523,
  "duration_ms": 1250,
  "level": "full"
}
```

**r2-Befehl:**
- `basic` -> `aa` (Analyse aller Symbole und Funktionen)
- `calls` -> `aac` (Analysiere Calls)
- `full` -> `aaa` (Vollstaendige Auto-Analyse)
- `experimental` -> `aaaa` (Experimentelle, tiefere Analyse)

**Beispiel:**
```
Input:  { "session_id": "a1b2c3d4...", "level": "full" }
Output: { "functions_found": 142, "strings_found": 87, "xrefs_found": 523, "duration_ms": 1250, "level": "full" }
```

---

### 2.2 `get_binary_info`

**Beschreibung:** Gibt allgemeine Informationen ueber das Binary zurueck: Format, Architektur, Compiler, Checksummen, Sicherheitsfeatures (NX, PIE, Canary, etc.).

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "description": "Session-ID"
    }
  },
  "required": ["session_id"]
}
```

**Output-Format:**
```json
{
  "file": "string",
  "format": "string (elf, pe, mach0, raw)",
  "architecture": "string",
  "bits": 64,
  "endian": "little",
  "os": "linux",
  "compiler": "gcc",
  "language": "c",
  "stripped": false,
  "static": false,
  "has_crypto": false,
  "has_nx": true,
  "has_pie": true,
  "has_canary": true,
  "has_relro": "full",
  "class": "ELF64",
  "machine": "AMD x86-64",
  "md5": "string",
  "sha256": "string",
  "size": 12345
}
```

**r2-Befehl:** `ij` (info als JSON), `iIj` (detaillierte Binary-Info als JSON)

**Beispiel:**
```
Input:  { "session_id": "a1b2c3d4..." }
Output: {
  "file": "/tmp/crackme",
  "format": "elf64",
  "architecture": "x86",
  "bits": 64,
  "endian": "little",
  "os": "linux",
  "stripped": false,
  "has_nx": true,
  "has_pie": true,
  "has_canary": true,
  "size": 16384
}
```

---

### 2.3 `list_functions`

**Beschreibung:** Listet alle erkannten Funktionen im Binary auf. Kann gefiltert werden nach Name oder Adressbereich. Gibt Adresse, Name, Groesse und Anzahl der Basic Blocks zurueck.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "description": "Session-ID"
    },
    "filter": {
      "type": "string",
      "default": null,
      "description": "Optionaler Namensfilter (Substring-Match, z.B. 'main')"
    },
    "offset": {
      "type": "integer",
      "default": 0,
      "description": "Pagination: Startindex"
    },
    "limit": {
      "type": "integer",
      "default": 100,
      "description": "Pagination: Max. Anzahl zurueckgegebener Funktionen"
    }
  },
  "required": ["session_id"]
}
```

**Output-Format:**
```json
{
  "functions": [
    {
      "address": "0x00401000",
      "name": "main",
      "size": 245,
      "num_bbs": 8,
      "num_args": 2,
      "num_locals": 5,
      "calltype": "cdecl",
      "type": "fcn"
    }
  ],
  "total": 142,
  "offset": 0,
  "limit": 100
}
```

**r2-Befehl:** `aflj` (function list als JSON), mit Filter: `aflj~name`

**Beispiel:**
```
Input:  { "session_id": "a1b2c3d4...", "filter": "main", "limit": 10 }
Output: {
  "functions": [
    { "address": "0x00401000", "name": "main", "size": 245, "num_bbs": 8 },
    { "address": "0x00401200", "name": "main_loop", "size": 120, "num_bbs": 4 }
  ],
  "total": 2,
  "offset": 0,
  "limit": 10
}
```

---

### 2.4 `disassemble_function`

**Beschreibung:** Disassembliert eine Funktion und gibt die Assembly-Instruktionen zurueck. Die Funktion kann ueber Name oder Adresse identifiziert werden.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "description": "Session-ID"
    },
    "function_name": {
      "type": "string",
      "default": null,
      "description": "Name der Funktion (z.B. 'main', 'sym.encrypt')"
    },
    "address": {
      "type": "string",
      "default": null,
      "description": "Adresse der Funktion (hex, z.B. '0x00401000')"
    }
  },
  "required": ["session_id"],
  "oneOf_note": "Mindestens function_name oder address muss angegeben werden"
}
```

**Output-Format:**
```json
{
  "function": "main",
  "address": "0x00401000",
  "size": 245,
  "instructions": [
    {
      "offset": "0x00401000",
      "esil": "rbp,8,rsp,-=,rsp,=[8]",
      "bytes": "55",
      "opcode": "push rbp",
      "type": "push",
      "size": 1,
      "comment": null
    }
  ],
  "num_instructions": 58
}
```

**r2-Befehl:** `s <addr_or_name>; pdfj` (seek + print disassembly function JSON)

**Beispiel:**
```
Input:  { "session_id": "a1b2c3d4...", "function_name": "main" }
Output: {
  "function": "main",
  "address": "0x00401000",
  "size": 245,
  "instructions": [
    { "offset": "0x00401000", "bytes": "55", "opcode": "push rbp", "type": "push", "size": 1 },
    { "offset": "0x00401001", "bytes": "4889e5", "opcode": "mov rbp, rsp", "type": "mov", "size": 3 }
  ],
  "num_instructions": 58
}
```

---

### 2.5 `decompile_function`

**Beschreibung:** Decompiliert eine Funktion in Pseudo-C-Code. Verwendet den in r2 verfuegbaren Decompiler (r2ghidra/r2dec/pdc). Gibt lesbaren C-aehnlichen Code zurueck.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "description": "Session-ID"
    },
    "function_name": {
      "type": "string",
      "default": null,
      "description": "Name der Funktion"
    },
    "address": {
      "type": "string",
      "default": null,
      "description": "Adresse der Funktion (hex)"
    },
    "decompiler": {
      "type": "string",
      "enum": ["pdc", "pdg", "pdd"],
      "default": "pdc",
      "description": "Decompiler: pdc (r2 built-in), pdg (r2ghidra), pdd (r2dec)"
    }
  },
  "required": ["session_id"],
  "oneOf_note": "Mindestens function_name oder address muss angegeben werden"
}
```

**Output-Format:**
```json
{
  "function": "main",
  "address": "0x00401000",
  "decompiler": "pdc",
  "code": "int main(int argc, char **argv) {\n    int var_4h;\n    char *s;\n    ...\n}"
}
```

**r2-Befehl:**
- `pdc` (r2 built-in Pseudo-C)
- `pdg` (r2ghidra Decompiler, Plugin noetig)
- `pdd` (r2dec Decompiler, Plugin noetig)

**Beispiel:**
```
Input:  { "session_id": "a1b2c3d4...", "function_name": "main", "decompiler": "pdc" }
Output: {
  "function": "main",
  "address": "0x00401000",
  "decompiler": "pdc",
  "code": "int main(int argc, char **argv) {\n    if (argc <= 1) {\n        puts(\"Usage: crackme <password>\");\n        return 1;\n    }\n    return check_password(argv[1]);\n}"
}
```

---

### 2.6 `get_strings`

**Beschreibung:** Extrahiert Strings aus dem Binary. Kann auf die Data-Section beschraenkt werden oder das gesamte Binary durchsuchen. Nuetzlich zur schnellen Erkennung von Funktionalitaet, URLs, Fehlermeldungen, Verschluesselungshinweisen.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "description": "Session-ID"
    },
    "source": {
      "type": "string",
      "enum": ["data_section", "whole_binary"],
      "default": "data_section",
      "description": "data_section=iz (nur Daten-Sektionen), whole_binary=izz (gesamtes Binary)"
    },
    "filter": {
      "type": "string",
      "default": null,
      "description": "Optionaler Filter (Substring-Match)"
    },
    "min_length": {
      "type": "integer",
      "default": 4,
      "description": "Minimale String-Laenge"
    },
    "offset": {
      "type": "integer",
      "default": 0,
      "description": "Pagination: Startindex"
    },
    "limit": {
      "type": "integer",
      "default": 200,
      "description": "Pagination: Max. Anzahl"
    }
  },
  "required": ["session_id"]
}
```

**Output-Format:**
```json
{
  "strings": [
    {
      "address": "0x00402000",
      "type": "ascii",
      "length": 13,
      "section": ".rodata",
      "string": "Hello, World!"
    }
  ],
  "total": 87,
  "offset": 0,
  "limit": 200
}
```

**r2-Befehl:** `izj` (Strings in Data-Sections, JSON) / `izzj` (alle Strings, JSON)

**Beispiel:**
```
Input:  { "session_id": "a1b2c3d4...", "source": "data_section", "filter": "password" }
Output: {
  "strings": [
    { "address": "0x00402050", "type": "ascii", "length": 18, "section": ".rodata", "string": "Enter password: " },
    { "address": "0x00402070", "type": "ascii", "length": 16, "section": ".rodata", "string": "Wrong password!" }
  ],
  "total": 2,
  "offset": 0,
  "limit": 200
}
```

---

### 2.7 `get_imports`

**Beschreibung:** Listet alle importierten Symbole (Funktionen/Variablen aus externen Libraries) auf. Wichtig um die Abhaengigkeiten und potentiell gefaehrliche API-Aufrufe zu erkennen (z.B. system, exec, connect).

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "description": "Session-ID"
    },
    "filter": {
      "type": "string",
      "default": null,
      "description": "Optionaler Namensfilter (Substring-Match)"
    },
    "offset": {
      "type": "integer",
      "default": 0,
      "description": "Pagination: Startindex"
    },
    "limit": {
      "type": "integer",
      "default": 100,
      "description": "Pagination: Max. Anzahl"
    }
  },
  "required": ["session_id"]
}
```

**Output-Format:**
```json
{
  "imports": [
    {
      "ordinal": 1,
      "bind": "GLOBAL",
      "type": "FUNC",
      "name": "puts",
      "plt": "0x00401030",
      "library": "libc.so.6"
    }
  ],
  "total": 23,
  "offset": 0,
  "limit": 100
}
```

**r2-Befehl:** `iij` (Imports als JSON)

**Beispiel:**
```
Input:  { "session_id": "a1b2c3d4...", "filter": "exec" }
Output: {
  "imports": [
    { "ordinal": 5, "bind": "GLOBAL", "type": "FUNC", "name": "execve", "plt": "0x00401060", "library": "libc.so.6" }
  ],
  "total": 1,
  "offset": 0,
  "limit": 100
}
```

---

### 2.8 `get_exports`

**Beschreibung:** Listet alle exportierten Symbole des Binaries auf. Bei Shared Libraries zeigt dies die oeffentliche API.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "description": "Session-ID"
    },
    "filter": {
      "type": "string",
      "default": null,
      "description": "Optionaler Namensfilter"
    },
    "offset": {
      "type": "integer",
      "default": 0,
      "description": "Pagination: Startindex"
    },
    "limit": {
      "type": "integer",
      "default": 100,
      "description": "Pagination: Max. Anzahl"
    }
  },
  "required": ["session_id"]
}
```

**Output-Format:**
```json
{
  "exports": [
    {
      "address": "0x00401000",
      "type": "FUNC",
      "name": "main",
      "size": 245
    }
  ],
  "total": 5,
  "offset": 0,
  "limit": 100
}
```

**r2-Befehl:** `iEj` (Exports als JSON)

**Beispiel:**
```
Input:  { "session_id": "a1b2c3d4..." }
Output: {
  "exports": [
    { "address": "0x00401000", "type": "FUNC", "name": "main", "size": 245 },
    { "address": "0x00401100", "type": "FUNC", "name": "_start", "size": 42 }
  ],
  "total": 2,
  "offset": 0,
  "limit": 100
}
```

---

### 2.9 `get_sections`

**Beschreibung:** Listet alle Sektionen des Binaries auf mit Adressen, Groessen und Berechtigungen. Wichtig um zu verstehen, welche Speicherbereiche ausfuehrbar, beschreibbar oder nur lesbar sind.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "description": "Session-ID"
    }
  },
  "required": ["session_id"]
}
```

**Output-Format:**
```json
{
  "sections": [
    {
      "name": ".text",
      "size": 4096,
      "vsize": 4096,
      "paddr": "0x00001000",
      "vaddr": "0x00401000",
      "perm": "r-x",
      "type": "PROGBITS",
      "entropy": 6.12
    }
  ],
  "total": 8
}
```

**r2-Befehl:** `iSj` (Sections als JSON), `iS,entropy` fuer Entropie

**Beispiel:**
```
Input:  { "session_id": "a1b2c3d4..." }
Output: {
  "sections": [
    { "name": ".text", "size": 4096, "vaddr": "0x00401000", "perm": "r-x", "entropy": 6.12 },
    { "name": ".data", "size": 512, "vaddr": "0x00402000", "perm": "rw-", "entropy": 3.45 },
    { "name": ".rodata", "size": 256, "vaddr": "0x00403000", "perm": "r--", "entropy": 4.88 }
  ],
  "total": 3
}
```

---

### 2.10 `get_entry_points`

**Beschreibung:** Gibt die Entry Points des Binaries zurueck. Bei ELF ist dies typischerweise `_start`, bei PE der `AddressOfEntryPoint`.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "description": "Session-ID"
    }
  },
  "required": ["session_id"]
}
```

**Output-Format:**
```json
{
  "entry_points": [
    {
      "vaddr": "0x00401100",
      "paddr": "0x00001100",
      "baddr": "0x00400000",
      "haddr": "0x00000018",
      "type": "program"
    }
  ],
  "total": 1
}
```

**r2-Befehl:** `iej` (Entry Points als JSON)

**Beispiel:**
```
Input:  { "session_id": "a1b2c3d4..." }
Output: {
  "entry_points": [
    { "vaddr": "0x00401100", "paddr": "0x00001100", "type": "program" }
  ],
  "total": 1
}
```

---

### 2.11 `get_xrefs_to`

**Beschreibung:** Findet alle Cross-References ZU einer bestimmten Adresse oder Funktion. Zeigt, von wo aus eine Funktion/Adresse aufgerufen oder referenziert wird. Essentiell fuer das Verstaendnis von Code-Zusammenhaengen.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "description": "Session-ID"
    },
    "address": {
      "type": "string",
      "default": null,
      "description": "Ziel-Adresse (hex, z.B. '0x00401000')"
    },
    "function_name": {
      "type": "string",
      "default": null,
      "description": "Ziel-Funktionsname (z.B. 'main')"
    },
    "offset": {
      "type": "integer",
      "default": 0,
      "description": "Pagination: Startindex"
    },
    "limit": {
      "type": "integer",
      "default": 100,
      "description": "Pagination: Max. Anzahl"
    }
  },
  "required": ["session_id"],
  "oneOf_note": "Mindestens address oder function_name muss angegeben werden"
}
```

**Output-Format:**
```json
{
  "target": "0x00401000",
  "xrefs": [
    {
      "from": "0x004012a0",
      "from_function": "entry0",
      "type": "CALL",
      "opcode": "call main"
    }
  ],
  "total": 3
}
```

**r2-Befehl:** `s <addr>; axtj` (Seek + Cross-References TO als JSON)

**Beispiel:**
```
Input:  { "session_id": "a1b2c3d4...", "function_name": "sym.check_password" }
Output: {
  "target": "0x00401200",
  "xrefs": [
    { "from": "0x00401050", "from_function": "main", "type": "CALL", "opcode": "call sym.check_password" },
    { "from": "0x00401300", "from_function": "sym.retry", "type": "CALL", "opcode": "call sym.check_password" }
  ],
  "total": 2
}
```

---

### 2.12 `get_xrefs_from`

**Beschreibung:** Findet alle Cross-References VON einer bestimmten Adresse ausgehend. Zeigt, welche Funktionen/Adressen von einer bestimmten Stelle aus aufgerufen oder referenziert werden.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "description": "Session-ID"
    },
    "address": {
      "type": "string",
      "default": null,
      "description": "Quell-Adresse (hex)"
    },
    "function_name": {
      "type": "string",
      "default": null,
      "description": "Quell-Funktionsname"
    },
    "offset": {
      "type": "integer",
      "default": 0,
      "description": "Pagination: Startindex"
    },
    "limit": {
      "type": "integer",
      "default": 100,
      "description": "Pagination: Max. Anzahl"
    }
  },
  "required": ["session_id"],
  "oneOf_note": "Mindestens address oder function_name muss angegeben werden"
}
```

**Output-Format:**
```json
{
  "source": "0x00401000",
  "xrefs": [
    {
      "to": "0x00401200",
      "to_function": "sym.check_password",
      "type": "CALL",
      "opcode": "call sym.check_password"
    }
  ],
  "total": 5
}
```

**r2-Befehl:** `s <addr>; axfj` (Seek + Cross-References FROM als JSON)

**Beispiel:**
```
Input:  { "session_id": "a1b2c3d4...", "function_name": "main" }
Output: {
  "source": "0x00401000",
  "xrefs": [
    { "to": "0x00401030", "to_function": "sym.imp.puts", "type": "CALL" },
    { "to": "0x00401200", "to_function": "sym.check_password", "type": "CALL" },
    { "to": "0x00402050", "to_function": null, "type": "DATA" }
  ],
  "total": 3
}
```

---

## 3. ESIL Emulation

### 3.1 `esil_init`

**Beschreibung:** Initialisiert die ESIL (Evaluable Strings Intermediate Language) Virtual Machine fuer Emulation. Setzt den Stack, Register und Speicher auf. ESIL erlaubt die Emulation von Code ohne nativen Prozessor - essentiell fuer Malware-Analyse und Shellcode-Untersuchung.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "description": "Session-ID"
    },
    "address": {
      "type": "string",
      "default": null,
      "description": "Startadresse fuer die Emulation (hex). Default: Entry Point."
    },
    "stack_address": {
      "type": "string",
      "default": "0x00100000",
      "description": "Basisadresse des emulierten Stacks (hex)"
    },
    "stack_size": {
      "type": "integer",
      "default": 262144,
      "description": "Stack-Groesse in Bytes (default: 256KB)"
    }
  },
  "required": ["session_id"]
}
```

**Output-Format:**
```json
{
  "initialized": true,
  "start_address": "0x00401000",
  "stack_address": "0x00100000",
  "stack_size": 262144,
  "architecture": "x86",
  "bits": 64,
  "registers": {
    "rip": "0x00401000",
    "rsp": "0x00130000",
    "rbp": "0x00000000"
  }
}
```

**r2-Befehl:** `aei` (ESIL VM init), `aeim` (ESIL Stack/Memory init), `aeip` (Instruction Pointer auf Entry setzen), `s <addr>` (Optional: Seek)

**Beispiel:**
```
Input:  { "session_id": "a1b2c3d4...", "address": "0x00401000" }
Output: {
  "initialized": true,
  "start_address": "0x00401000",
  "stack_address": "0x00100000",
  "stack_size": 262144,
  "registers": { "rip": "0x00401000", "rsp": "0x00130000", "rbp": "0x00000000" }
}
```

---

### 3.2 `esil_step`

**Beschreibung:** Fuehrt einen einzelnen ESIL-Schritt (eine Instruktion) aus. Gibt den Zustand nach der Ausfuehrung zurueck (aktuelle Instruktion, veraenderte Register). Ideal fuer schrittweises Debugging und Verstaendnis des Kontrollflusses.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "description": "Session-ID"
    },
    "count": {
      "type": "integer",
      "default": 1,
      "minimum": 1,
      "maximum": 1000,
      "description": "Anzahl der auszufuehrenden Schritte"
    },
    "show_registers": {
      "type": "boolean",
      "default": true,
      "description": "Register nach jedem Schritt ausgeben"
    }
  },
  "required": ["session_id"]
}
```

**Output-Format:**
```json
{
  "steps": [
    {
      "address": "0x00401000",
      "opcode": "push rbp",
      "esil": "rbp,8,rsp,-=,rsp,=[8]",
      "registers_changed": {
        "rsp": { "before": "0x00130000", "after": "0x0012fff8" }
      }
    }
  ],
  "current_address": "0x00401001",
  "total_steps": 1,
  "registers": {
    "rip": "0x00401001",
    "rsp": "0x0012fff8",
    "rbp": "0x00000000"
  }
}
```

**r2-Befehl:** `aes` (ESIL step), `aesj` (step mit JSON-Output), `N*aes` fuer N Schritte

**Beispiel:**
```
Input:  { "session_id": "a1b2c3d4...", "count": 3, "show_registers": true }
Output: {
  "steps": [
    { "address": "0x00401000", "opcode": "push rbp", "esil": "rbp,8,rsp,-=,rsp,=[8]" },
    { "address": "0x00401001", "opcode": "mov rbp, rsp", "esil": "rsp,rbp,=" },
    { "address": "0x00401004", "opcode": "sub rsp, 0x20", "esil": "32,rsp,-=,rsp,=" }
  ],
  "current_address": "0x00401008",
  "total_steps": 3,
  "registers": { "rip": "0x00401008", "rsp": "0x0012ffd8", "rbp": "0x0012fff8" }
}
```

---

### 3.3 `esil_run`

**Beschreibung:** Fuehrt die ESIL-Emulation kontinuierlich aus bis ein Breakpoint erreicht wird, eine bestimmte Adresse erreicht wird, oder eine maximale Schrittzahl ueberschritten wird. Nuetzlich um groessere Codebloecke zu emulieren.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "description": "Session-ID"
    },
    "until_address": {
      "type": "string",
      "default": null,
      "description": "Ausfuehrung stoppen bei dieser Adresse (hex)"
    },
    "max_steps": {
      "type": "integer",
      "default": 10000,
      "minimum": 1,
      "maximum": 1000000,
      "description": "Maximale Anzahl Schritte (Sicherheitslimit)"
    },
    "timeout_ms": {
      "type": "integer",
      "default": 30000,
      "description": "Timeout in Millisekunden"
    }
  },
  "required": ["session_id"]
}
```

**Output-Format:**
```json
{
  "stopped_at": "0x00401050",
  "stop_reason": "breakpoint | address_reached | max_steps | timeout | end_of_function",
  "steps_executed": 142,
  "duration_ms": 85,
  "registers": {
    "rip": "0x00401050",
    "rsp": "0x0012ffd0",
    "rax": "0x00000001"
  }
}
```

**r2-Befehl:** `aecu <addr>` (Continue until address), `aec` (Continue), `e esil.timeout=<ms>`

**Beispiel:**
```
Input:  { "session_id": "a1b2c3d4...", "until_address": "0x00401050", "max_steps": 5000 }
Output: {
  "stopped_at": "0x00401050",
  "stop_reason": "address_reached",
  "steps_executed": 142,
  "duration_ms": 85,
  "registers": { "rip": "0x00401050", "rsp": "0x0012ffd0", "rax": "0x00000001" }
}
```

---

### 3.4 `esil_get_registers`

**Beschreibung:** Liest die aktuellen Werte aller Register oder bestimmter Register der ESIL VM aus. Zentral fuer die Ueberwachung des Emulationszustands.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "description": "Session-ID"
    },
    "registers": {
      "type": "array",
      "items": { "type": "string" },
      "default": null,
      "description": "Liste bestimmter Register (z.B. ['rax', 'rbx']). Null fuer alle Register."
    }
  },
  "required": ["session_id"]
}
```

**Output-Format:**
```json
{
  "registers": {
    "rax": "0x0000000000000001",
    "rbx": "0x0000000000000000",
    "rcx": "0x00000000004010a0",
    "rdx": "0x00007fffffffea48",
    "rsi": "0x00007fffffffea38",
    "rdi": "0x0000000000000001",
    "rsp": "0x0012fff8",
    "rbp": "0x0012fff8",
    "rip": "0x00401000",
    "rflags": "0x0000000000000246"
  }
}
```

**r2-Befehl:** `aerj` (ESIL Registers als JSON), `aer <register>` fuer einzelne Register

**Beispiel:**
```
Input:  { "session_id": "a1b2c3d4...", "registers": ["rax", "rsp", "rip"] }
Output: {
  "registers": {
    "rax": "0x0000000000000001",
    "rsp": "0x0012fff8",
    "rip": "0x00401000"
  }
}
```

---

### 3.5 `esil_set_register`

**Beschreibung:** Setzt den Wert eines Registers in der ESIL VM. Nuetzlich um Funktionsargumente vor der Emulation zu setzen oder den Zustand zu manipulieren.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "description": "Session-ID"
    },
    "register": {
      "type": "string",
      "description": "Register-Name (z.B. 'rax', 'eax', 'r0', 'pc')"
    },
    "value": {
      "type": "string",
      "description": "Wert als Hex-String (z.B. '0x41414141') oder Dezimalzahl"
    }
  },
  "required": ["session_id", "register", "value"]
}
```

**Output-Format:**
```json
{
  "register": "rax",
  "old_value": "0x0000000000000000",
  "new_value": "0x0000000041414141",
  "success": true
}
```

**r2-Befehl:** `aer <register>=<value>` (Set ESIL Register)

**Beispiel:**
```
Input:  { "session_id": "a1b2c3d4...", "register": "rdi", "value": "0x00402050" }
Output: { "register": "rdi", "old_value": "0x0000000000000000", "new_value": "0x0000000000402050", "success": true }
```

---

### 3.6 `esil_get_memory`

**Beschreibung:** Liest Speicher aus der ESIL VM an einer bestimmten Adresse. Gibt die Bytes in verschiedenen Formaten zurueck (Hex, ASCII, Integer). Essentiell um den Zustand von Variablen, Stack-Frames und Heap-Daten zu inspizieren.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "description": "Session-ID"
    },
    "address": {
      "type": "string",
      "description": "Leseadresse (hex, z.B. '0x00402000')"
    },
    "size": {
      "type": "integer",
      "default": 64,
      "minimum": 1,
      "maximum": 65536,
      "description": "Anzahl zu lesender Bytes"
    },
    "format": {
      "type": "string",
      "enum": ["hex", "ascii", "hexdump", "bytes"],
      "default": "hexdump",
      "description": "Ausgabeformat: hex (reiner Hex-String), ascii (String-Darstellung), hexdump (klassische Hex+ASCII Ansicht), bytes (Array von Byte-Werten)"
    }
  },
  "required": ["session_id", "address"]
}
```

**Output-Format:**
```json
{
  "address": "0x00402000",
  "size": 64,
  "format": "hexdump",
  "data": "0x00402000  4865 6c6c 6f2c 2057 6f72 6c64 2100 0000  Hello, World!...\n0x00402010  0000 0000 0000 0000 0000 0000 0000 0000  ................",
  "hex": "48656c6c6f2c20576f726c64210000000000000000000000000000000000000000",
  "ascii": "Hello, World!..."
}
```

**r2-Befehl:** `px <size> @ <addr>` (Hexdump), `p8 <size> @ <addr>` (Hex-String), `ps @ <addr>` (String)

**Beispiel:**
```
Input:  { "session_id": "a1b2c3d4...", "address": "0x0012ffd0", "size": 32, "format": "hexdump" }
Output: {
  "address": "0x0012ffd0",
  "size": 32,
  "format": "hexdump",
  "data": "0x0012ffd0  0100 0000 0000 0000 a0ea ffff ff7f 0000  ................\n0x0012ffe0  0000 0000 0000 0000 0010 4000 0000 0000  ..........@....."
}
```

---

### 3.7 `esil_set_memory`

**Beschreibung:** Schreibt Daten in den Speicher der ESIL VM. Ermoeglicht das Setzen von Eingabedaten, das Manipulieren von Variablen oder das Vorbereiten von Testszenarien.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "description": "Session-ID"
    },
    "address": {
      "type": "string",
      "description": "Zieladresse (hex)"
    },
    "data": {
      "type": "string",
      "description": "Zu schreibende Daten als Hex-String (z.B. '48656c6c6f') oder als String mit Praefix 's:' (z.B. 's:Hello')"
    }
  },
  "required": ["session_id", "address", "data"]
}
```

**Output-Format:**
```json
{
  "address": "0x00402000",
  "bytes_written": 5,
  "success": true
}
```

**r2-Befehl:** `wx <hex> @ <addr>` (Hex-Bytes schreiben), `w <string> @ <addr>` (String schreiben)

**Beispiel:**
```
Input:  { "session_id": "a1b2c3d4...", "address": "0x00500000", "data": "s:AAAA" }
Output: { "address": "0x00500000", "bytes_written": 4, "success": true }
```

---

### 3.8 `esil_expression`

**Beschreibung:** Wertet einen ESIL-Ausdruck direkt aus, ohne ihn einer Instruktion zuzuordnen. ESIL ist eine Stack-basierte Zwischensprache (aehnlich Forth/RPN). Nuetzlich fuer schnelle Berechnungen und zum Verstaendnis von ESIL-Ausdruecken.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "description": "Session-ID"
    },
    "expression": {
      "type": "string",
      "description": "ESIL-Ausdruck (z.B. '1,2,+', 'rax,rbx,+,rcx,=', '0x41,0x00402000,=[1]')"
    }
  },
  "required": ["session_id", "expression"]
}
```

**Output-Format:**
```json
{
  "expression": "1,2,+",
  "stack": ["3"],
  "registers_changed": {},
  "success": true
}
```

**r2-Befehl:** `ae <expression>` (ESIL Expression auswerten), `"ae 1,2,+"`

**ESIL-Syntax Kurzreferenz:**
- Stack-basiert, Komma-separiert: `1,2,+` ergibt 3
- Register lesen: `rax` pusht RAX-Wert
- Register schreiben: `42,rax,=` setzt RAX auf 42
- Speicher lesen: `[8]` liest 8 Bytes von Stack-Top-Adresse
- Speicher schreiben: `value,addr,=[size]`
- Vergleiche: `==,!,<,>,<=,>=`
- Sprung: `addr,rip,=` aendert den PC

**Beispiel:**
```
Input:  { "session_id": "a1b2c3d4...", "expression": "0x41414141,rax,=" }
Output: {
  "expression": "0x41414141,rax,=",
  "stack": [],
  "registers_changed": { "rax": { "before": "0x0000000000000000", "after": "0x0000000041414141" } },
  "success": true
}
```

---

## 4. Shellcode Analysis

### 4.1 `analyze_shellcode`

**Beschreibung:** Laedt rohen Shellcode (als Hex-Bytes), disassembliert ihn und fuehrt eine automatische Analyse durch. Erkennt Architektur (falls nicht angegeben), identifiziert Syscalls, Strings und typische Shellcode-Muster. Dies ist ein High-Level-Wrapper, der mehrere r2-Befehle kombiniert.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "shellcode": {
      "type": "string",
      "description": "Shellcode als Hex-String (z.B. '\\x31\\xc0\\x50\\x68' oder '31c05068' oder '31 c0 50 68')"
    },
    "architecture": {
      "type": "string",
      "default": "x86",
      "description": "Architektur: x86, arm, arm64, mips, ppc, etc."
    },
    "bits": {
      "type": "integer",
      "enum": [16, 32, 64],
      "default": 32,
      "description": "Bitbreite (16, 32, 64)"
    },
    "base_address": {
      "type": "string",
      "default": "0x00000000",
      "description": "Basisadresse fuer Disassembly (hex)"
    }
  },
  "required": ["shellcode"]
}
```

**Output-Format:**
```json
{
  "session_id": "string (automatisch erstellt)",
  "size": 28,
  "architecture": "x86",
  "bits": 32,
  "disassembly": [
    { "offset": "0x00000000", "bytes": "31c0", "opcode": "xor eax, eax", "type": "xor" },
    { "offset": "0x00000002", "bytes": "50", "opcode": "push eax", "type": "push" }
  ],
  "syscalls_detected": [
    { "offset": "0x00000018", "number": 11, "name": "execve", "args_hint": "(\"/bin/sh\", NULL, NULL)" }
  ],
  "strings_found": ["/bin/sh"],
  "patterns_detected": ["stack_pivot", "null_free", "execve_shellcode"],
  "is_null_free": true,
  "summary": "Linux x86 execve('/bin/sh') Shellcode, 28 Bytes, null-free"
}
```

**r2-Befehl:** Kombination aus:
- `r2 -a x86 -b 32 -c 'wx <hex>; aaa; pdf; /ad syscall; iz' malloc://<size>`
- Oder: `rasm2 -a x86 -b 32 -d <hex>` fuer schnelles Disassembly

**Beispiel:**
```
Input:  { "shellcode": "31c050682f2f7368682f62696e89e350535389e1b00bcd80", "architecture": "x86", "bits": 32 }
Output: {
  "session_id": "sc-12345",
  "size": 23,
  "architecture": "x86",
  "bits": 32,
  "disassembly": [
    { "offset": "0x00000000", "bytes": "31c0", "opcode": "xor eax, eax" },
    { "offset": "0x00000002", "bytes": "50", "opcode": "push eax" },
    { "offset": "0x00000003", "bytes": "682f2f7368", "opcode": "push 0x68732f2f" },
    { "offset": "0x00000008", "bytes": "682f62696e", "opcode": "push 0x6e69622f" },
    { "offset": "0x0000000d", "bytes": "89e3", "opcode": "mov ebx, esp" },
    { "offset": "0x0000000f", "bytes": "50", "opcode": "push eax" },
    { "offset": "0x00000010", "bytes": "53", "opcode": "push ebx" },
    { "offset": "0x00000011", "bytes": "53", "opcode": "push ebx" },
    { "offset": "0x00000012", "bytes": "89e1", "opcode": "mov ecx, esp" },
    { "offset": "0x00000014", "bytes": "b00b", "opcode": "mov al, 0xb" },
    { "offset": "0x00000016", "bytes": "cd80", "opcode": "int 0x80" }
  ],
  "syscalls_detected": [
    { "offset": "0x00000016", "number": 11, "name": "execve" }
  ],
  "strings_found": ["/bin//sh"],
  "patterns_detected": ["execve_binsh", "null_free", "stack_based_string"],
  "is_null_free": true,
  "summary": "Linux x86 execve('/bin//sh') Shellcode, 23 Bytes, null-free"
}
```

---

### 4.2 `detect_shellcode_patterns`

**Beschreibung:** Scannt Bytes oder ein bereits geladenes Binary nach bekannten Shellcode-Patterns und -Techniken. Erkennt gaengige Encoder (XOR, Shikata-ga-nai), NOP-Sleds, Egg-Hunter, Syscall-Chains und Anti-Debugging-Tricks.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "default": null,
      "description": "Session-ID eines bereits geoeffneten Binaries"
    },
    "shellcode": {
      "type": "string",
      "default": null,
      "description": "Alternativ: Shellcode als Hex-String"
    },
    "address": {
      "type": "string",
      "default": null,
      "description": "Startadresse fuer Scan (nur bei session_id)"
    },
    "size": {
      "type": "integer",
      "default": null,
      "description": "Scan-Groesse in Bytes (nur bei session_id)"
    }
  },
  "required": [],
  "oneOf_note": "Entweder session_id oder shellcode muss angegeben werden"
}
```

**Output-Format:**
```json
{
  "patterns": [
    {
      "name": "nop_sled",
      "offset": "0x00000000",
      "size": 16,
      "confidence": "high",
      "description": "NOP-Sled (16 bytes of 0x90)"
    },
    {
      "name": "xor_decoder",
      "offset": "0x00000010",
      "size": 12,
      "confidence": "medium",
      "description": "XOR-basierter Decoder-Stub (Key: 0x41)"
    },
    {
      "name": "syscall_execve",
      "offset": "0x00000030",
      "size": 2,
      "confidence": "high",
      "description": "Linux x86 execve syscall (int 0x80 mit eax=0xb)"
    }
  ],
  "techniques": ["encoding_xor", "nop_sled", "stack_string_construction"],
  "risk_assessment": "high",
  "summary": "Encoded shellcode with NOP sled, XOR decoder (key=0x41), execve syscall"
}
```

**r2-Befehl:** Kombination aus:
- `/x 9090909090` (NOP-Sled suchen)
- `/ad int 0x80` / `/ad syscall` / `/ad svc` (Syscall-Patterns)
- `/x 80f?00` (XOR-Encoder-Patterns)
- Heuristische Analyse ueber `pd` und Pattern-Matching

**Beispiel:**
```
Input:  { "shellcode": "909090909090909090909090909090903109c031d2eb0e5e8d7e0131c9b10c8034310141e2f9eb055e8d7e01506a0b5889e331c931d2cd80e8edffffff2f2e2f72682f68" }
Output: {
  "patterns": [
    { "name": "nop_sled", "offset": "0x00000000", "size": 16, "confidence": "high", "description": "NOP-Sled (16 bytes)" },
    { "name": "xor_decoder", "offset": "0x00000010", "size": 20, "confidence": "high", "description": "XOR decoder loop (key: 0x41)" },
    { "name": "jmp_call_pop", "offset": "0x00000010", "size": 6, "confidence": "high", "description": "JMP-CALL-POP technique for position-independent addressing" }
  ],
  "techniques": ["nop_sled", "encoding_xor", "jmp_call_pop"],
  "risk_assessment": "high",
  "summary": "Encoded shellcode: NOP sled + XOR decoder (key=0x41) + JMP-CALL-POP addressing"
}
```

---

### 4.3 `emulate_shellcode`

**Beschreibung:** Emuliert Shellcode in der ESIL VM und protokolliert alle Syscalls, Speicherzugriffe und Register-Aenderungen. Gibt eine Ausfuehrungs-Trace zurueck. Automatisiert die Schritte: Shellcode laden, ESIL init, emulieren, Trace aufzeichnen.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "shellcode": {
      "type": "string",
      "description": "Shellcode als Hex-String"
    },
    "architecture": {
      "type": "string",
      "default": "x86",
      "description": "Architektur"
    },
    "bits": {
      "type": "integer",
      "enum": [16, 32, 64],
      "default": 32,
      "description": "Bitbreite"
    },
    "max_steps": {
      "type": "integer",
      "default": 10000,
      "minimum": 1,
      "maximum": 1000000,
      "description": "Maximale Emulationsschritte"
    },
    "timeout_ms": {
      "type": "integer",
      "default": 30000,
      "description": "Timeout in Millisekunden"
    },
    "trace_memory": {
      "type": "boolean",
      "default": true,
      "description": "Speicherzugriffe mitprotokollieren"
    },
    "trace_syscalls": {
      "type": "boolean",
      "default": true,
      "description": "Syscalls mitprotokollieren"
    },
    "input_data": {
      "type": "object",
      "default": null,
      "description": "Optionale Eingabedaten fuer die Emulation",
      "properties": {
        "stdin": { "type": "string", "description": "Simulierter stdin (Hex-String)" },
        "argv": { "type": "array", "items": { "type": "string" }, "description": "Simulierte Kommandozeilen-Argumente" },
        "env": { "type": "object", "description": "Simulierte Umgebungsvariablen" }
      }
    }
  },
  "required": ["shellcode"]
}
```

**Output-Format:**
```json
{
  "session_id": "string",
  "steps_executed": 42,
  "stop_reason": "syscall_exit | max_steps | timeout | error",
  "duration_ms": 150,
  "syscall_trace": [
    {
      "step": 38,
      "address": "0x00000016",
      "syscall_number": 11,
      "syscall_name": "execve",
      "args": {
        "arg0": "0x0012fff0 -> \"/bin/sh\"",
        "arg1": "0x0012ffe0 -> [ptr array]",
        "arg2": "0x00000000 -> NULL"
      }
    }
  ],
  "memory_trace": [
    {
      "step": 3,
      "type": "write",
      "address": "0x0012fff0",
      "size": 4,
      "value": "0x68732f2f"
    }
  ],
  "final_registers": {
    "eax": "0x0000000b",
    "ebx": "0x0012fff0",
    "ecx": "0x0012ffe0",
    "edx": "0x00000000",
    "esp": "0x0012ffe0",
    "eip": "0x00000018"
  },
  "decoded_strings": ["/bin/sh"],
  "summary": "Shellcode executes execve('/bin/sh', ['/bin/sh', NULL], NULL)"
}
```

**r2-Befehl:** Kombination aus:
- `r2 -a x86 -b 32 malloc://<size>`
- `wx <shellcode>`
- `aei; aeim; aeip`
- `e dbg.trace=true`
- `aets+` (ESIL trace start)
- `aecu <end>` oder `N*aes`
- `aets` (ESIL trace dump)
- `ar` (Registers)

**Beispiel:**
```
Input:  { "shellcode": "31c050682f2f7368682f62696e89e350535389e1b00bcd80", "architecture": "x86", "bits": 32 }
Output: {
  "session_id": "sc-emul-67890",
  "steps_executed": 11,
  "stop_reason": "syscall_exit",
  "syscall_trace": [
    { "step": 11, "address": "0x00000016", "syscall_number": 11, "syscall_name": "execve",
      "args": { "arg0": "0x0012fff0 -> \"/bin//sh\"" } }
  ],
  "decoded_strings": ["/bin//sh"],
  "summary": "Shellcode executes execve('/bin//sh', ...)"
}
```

---

### 4.4 `disassemble_bytes`

**Beschreibung:** Disassembliert rohe Bytes ohne sie in einer vollstaendigen Session zu laden. Schnelle Einzeloperation fuer kurze Byte-Sequenzen. Nuetzlich fuer schnelle Checks von Instruktions-Opcodes.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "bytes": {
      "type": "string",
      "description": "Zu disassemblierende Bytes als Hex-String (z.B. '90cc31c0')"
    },
    "architecture": {
      "type": "string",
      "default": "x86",
      "description": "Architektur"
    },
    "bits": {
      "type": "integer",
      "enum": [16, 32, 64],
      "default": 64,
      "description": "Bitbreite"
    },
    "base_address": {
      "type": "string",
      "default": "0x00000000",
      "description": "Basisadresse fuer Offset-Berechnung"
    },
    "count": {
      "type": "integer",
      "default": null,
      "description": "Maximale Anzahl zu disassemblierender Instruktionen. Null = alle."
    }
  },
  "required": ["bytes"]
}
```

**Output-Format:**
```json
{
  "instructions": [
    {
      "offset": "0x00000000",
      "bytes": "90",
      "opcode": "nop",
      "size": 1,
      "type": "nop",
      "esil": ""
    },
    {
      "offset": "0x00000001",
      "bytes": "cc",
      "opcode": "int3",
      "size": 1,
      "type": "swi",
      "esil": ""
    }
  ],
  "total_bytes": 4,
  "total_instructions": 2
}
```

**r2-Befehl:** `rasm2 -a <arch> -b <bits> -d <hex>` oder inline: `pad <hex>`

**Beispiel:**
```
Input:  { "bytes": "554889e54883ec20", "architecture": "x86", "bits": 64 }
Output: {
  "instructions": [
    { "offset": "0x00000000", "bytes": "55", "opcode": "push rbp", "size": 1 },
    { "offset": "0x00000001", "bytes": "4889e5", "opcode": "mov rbp, rsp", "size": 3 },
    { "offset": "0x00000004", "bytes": "4883ec20", "opcode": "sub rsp, 0x20", "size": 4 }
  ],
  "total_bytes": 8,
  "total_instructions": 3
}
```

---

## 5. Memory und Navigation

### 5.1 `seek`

**Beschreibung:** Navigiert zu einer bestimmten Adresse, einem Symbol oder einem Flag im Binary. Aendert die aktuelle Position fuer nachfolgende Befehle. Unterstuetzt symbolische Namen, Flags, Ausdruecke und relative Navigation.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "description": "Session-ID"
    },
    "target": {
      "type": "string",
      "description": "Ziel: Adresse (hex), Funktionsname, Flag, oder Ausdruck (z.B. '0x401000', 'main', 'entry0', 'rsp', '$$+0x10')"
    }
  },
  "required": ["session_id", "target"]
}
```

**Output-Format:**
```json
{
  "address": "0x00401000",
  "function": "main",
  "section": ".text",
  "previous_address": "0x00401100"
}
```

**r2-Befehl:** `s <target>` (seek), `s` (aktuelle Position), `sj` (seek info JSON)

**Beispiel:**
```
Input:  { "session_id": "a1b2c3d4...", "target": "main" }
Output: { "address": "0x00401000", "function": "main", "section": ".text", "previous_address": "0x00401100" }
```

---

### 5.2 `read_bytes`

**Beschreibung:** Liest Bytes an einer bestimmten Adresse und gibt sie in verschiedenen Formaten zurueck. Standardmaessig als Hexdump mit ASCII-Darstellung.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "description": "Session-ID"
    },
    "address": {
      "type": "string",
      "default": null,
      "description": "Adresse (hex). Default: aktuelle Seek-Position."
    },
    "size": {
      "type": "integer",
      "default": 64,
      "minimum": 1,
      "maximum": 65536,
      "description": "Anzahl Bytes"
    },
    "format": {
      "type": "string",
      "enum": ["hexdump", "hex", "binary", "octal", "disasm", "c_array", "python_array", "base64"],
      "default": "hexdump",
      "description": "Ausgabeformat"
    }
  },
  "required": ["session_id"]
}
```

**Output-Format:**
```json
{
  "address": "0x00401000",
  "size": 64,
  "format": "hexdump",
  "data": "0x00401000  5548 89e5 4883 ec20 897d ec48 8975 e0...",
  "hex": "554889e54883ec20897dec488975e0..."
}
```

**r2-Befehl:**
- `hexdump` -> `px <size> @ <addr>`
- `hex` -> `p8 <size> @ <addr>`
- `disasm` -> `pd <n> @ <addr>`
- `c_array` -> `pc <size> @ <addr>`
- `python_array` -> `pcp <size> @ <addr>`
- `base64` -> `p6e <size> @ <addr>`

**Beispiel:**
```
Input:  { "session_id": "a1b2c3d4...", "address": "0x00401000", "size": 16, "format": "hex" }
Output: { "address": "0x00401000", "size": 16, "format": "hex", "data": "554889e54883ec20897dec488975e0" }
```

---

### 5.3 `write_bytes`

**Beschreibung:** Schreibt Bytes an eine bestimmte Adresse. Unterstuetzt Hex-Bytes, Strings und Assembler-Instruktionen als Input.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "description": "Session-ID"
    },
    "address": {
      "type": "string",
      "description": "Zieladresse (hex)"
    },
    "data": {
      "type": "string",
      "description": "Daten zum Schreiben"
    },
    "data_type": {
      "type": "string",
      "enum": ["hex", "string", "assembly"],
      "default": "hex",
      "description": "Typ der Eingabedaten: hex='90cc', string='Hello', assembly='nop; ret'"
    }
  },
  "required": ["session_id", "address", "data"]
}
```

**Output-Format:**
```json
{
  "address": "0x00401000",
  "bytes_written": 2,
  "data_hex": "90cc",
  "success": true
}
```

**r2-Befehl:**
- `hex` -> `wx <hex> @ <addr>`
- `string` -> `w <string> @ <addr>`
- `assembly` -> `wa <asm> @ <addr>` (Assemble + Write)

**Beispiel:**
```
Input:  { "session_id": "a1b2c3d4...", "address": "0x00401000", "data": "nop; nop; ret", "data_type": "assembly" }
Output: { "address": "0x00401000", "bytes_written": 3, "data_hex": "9090c3", "success": true }
```

---

### 5.4 `search_bytes`

**Beschreibung:** Durchsucht das Binary nach einem Byte-Pattern, Hex-Sequenz oder regulaerem Ausdruck. Gibt alle Fundstellen zurueck.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "description": "Session-ID"
    },
    "pattern": {
      "type": "string",
      "description": "Suchmuster (abhaengig von search_type)"
    },
    "search_type": {
      "type": "string",
      "enum": ["hex", "string", "regex", "rop", "assembly"],
      "default": "hex",
      "description": "Suchtyp: hex='41424344', string='ABCD', regex='pass.{0,10}word', rop='pop rdi; ret', assembly='push rbp'"
    },
    "from_address": {
      "type": "string",
      "default": null,
      "description": "Startadresse fuer die Suche (hex). Null = Anfang des Binaries."
    },
    "to_address": {
      "type": "string",
      "default": null,
      "description": "Endadresse fuer die Suche (hex). Null = Ende des Binaries."
    },
    "max_results": {
      "type": "integer",
      "default": 100,
      "description": "Maximale Anzahl Ergebnisse"
    }
  },
  "required": ["session_id", "pattern"]
}
```

**Output-Format:**
```json
{
  "pattern": "41424344",
  "search_type": "hex",
  "results": [
    {
      "offset": "0x00402010",
      "section": ".rodata",
      "context": "...data before...ABCD...data after..."
    }
  ],
  "total": 3
}
```

**r2-Befehl:**
- `hex` -> `/xj <hex>`
- `string` -> `/j <string>`
- `regex` -> `/ej <regex>`
- `rop` -> `/Rj <gadget>`
- `assembly` -> `/adj <asm>`

**Beispiel:**
```
Input:  { "session_id": "a1b2c3d4...", "pattern": "/bin/sh", "search_type": "string" }
Output: {
  "pattern": "/bin/sh",
  "search_type": "string",
  "results": [
    { "offset": "0x00402050", "section": ".rodata" }
  ],
  "total": 1
}
```

---

### 5.5 `search_string`

**Beschreibung:** Spezial-Suche nach Strings im Binary. Wrapper um die allgemeine Suche, optimiert fuer String-Muster. Unterstuetzt auch Regex.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "description": "Session-ID"
    },
    "query": {
      "type": "string",
      "description": "Suchstring oder Regex-Pattern"
    },
    "is_regex": {
      "type": "boolean",
      "default": false,
      "description": "Als Regex interpretieren"
    },
    "case_sensitive": {
      "type": "boolean",
      "default": true,
      "description": "Gross-/Kleinschreibung beachten"
    },
    "max_results": {
      "type": "integer",
      "default": 100,
      "description": "Maximale Anzahl Ergebnisse"
    }
  },
  "required": ["session_id", "query"]
}
```

**Output-Format:**
```json
{
  "query": "password",
  "results": [
    {
      "offset": "0x00402050",
      "string": "Enter password: ",
      "section": ".rodata",
      "type": "ascii",
      "length": 16
    }
  ],
  "total": 2
}
```

**r2-Befehl:** `/j <string>` oder `/ej <regex>`, `e search.case` fuer Case-Sensitivity

**Beispiel:**
```
Input:  { "session_id": "a1b2c3d4...", "query": "pass.*word", "is_regex": true }
Output: {
  "query": "pass.*word",
  "results": [
    { "offset": "0x00402050", "string": "Enter password: ", "section": ".rodata", "length": 16 },
    { "offset": "0x00402070", "string": "Wrong password!", "section": ".rodata", "length": 15 }
  ],
  "total": 2
}
```

---

## 6. Advanced

### 6.1 `run_r2_command`

**Beschreibung:** Fuehrt einen beliebigen radare2-Befehl direkt aus und gibt das Ergebnis zurueck. Dies ist der maechtigste Tool Call - er erlaubt den Zugriff auf ALLE r2-Befehle, die nicht durch spezialisierte Tool Calls abgedeckt sind. Sollte als Fallback verwendet werden, wenn kein passender spezialisierter Tool Call existiert.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "description": "Session-ID"
    },
    "command": {
      "type": "string",
      "description": "r2-Befehl (z.B. 'afl', 'pdf @ main', 'px 64 @ rsp')"
    },
    "json_output": {
      "type": "boolean",
      "default": false,
      "description": "Automatisch 'j' an den Befehl anhaengen fuer JSON-Output (z.B. 'afl' -> 'aflj')"
    },
    "timeout_ms": {
      "type": "integer",
      "default": 30000,
      "description": "Timeout in Millisekunden"
    }
  },
  "required": ["session_id", "command"]
}
```

**Output-Format:**
```json
{
  "command": "afl",
  "output": "0x00401000    8 245          main\n0x00401100    1  42          entry0\n...",
  "success": true,
  "execution_time_ms": 5
}
```

Falls `json_output=true` und der Befehl JSON zurueckgibt:
```json
{
  "command": "aflj",
  "output": [ { "offset": 4198400, "name": "main", "size": 245 } ],
  "success": true,
  "execution_time_ms": 5
}
```

**r2-Befehl:** Direkte r2pipe-Weiterleitung: `r2.cmd(<command>)` bzw. `r2.cmdj(<command>j)`

**Beispiel:**
```
Input:  { "session_id": "a1b2c3d4...", "command": "afl", "json_output": true }
Output: {
  "command": "aflj",
  "output": [
    { "offset": 4198400, "name": "main", "size": 245, "nbbs": 8 },
    { "offset": 4198656, "name": "entry0", "size": 42, "nbbs": 1 }
  ],
  "success": true,
  "execution_time_ms": 5
}
```

---

### 6.2 `get_callgraph`

**Beschreibung:** Gibt den Callgraph einer Funktion oder des gesamten Programms zurueck. Zeigt, welche Funktionen welche anderen Funktionen aufrufen. Kann als DOT-Graph oder als strukturierte Daten ausgegeben werden.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "description": "Session-ID"
    },
    "function_name": {
      "type": "string",
      "default": null,
      "description": "Funktion fuer lokalen Callgraph. Null fuer globalen Callgraph."
    },
    "depth": {
      "type": "integer",
      "default": 3,
      "minimum": 1,
      "maximum": 20,
      "description": "Maximale Tiefe des Callgraphs"
    },
    "format": {
      "type": "string",
      "enum": ["json", "dot", "mermaid"],
      "default": "json",
      "description": "Ausgabeformat: json (strukturiert), dot (Graphviz), mermaid (Markdown-kompatibel)"
    }
  },
  "required": ["session_id"]
}
```

**Output-Format (JSON):**
```json
{
  "root": "main",
  "nodes": [
    { "name": "main", "address": "0x00401000", "size": 245 },
    { "name": "sym.check_password", "address": "0x00401200", "size": 80 },
    { "name": "sym.imp.puts", "address": "0x00401030", "size": 6 },
    { "name": "sym.imp.strcmp", "address": "0x00401040", "size": 6 }
  ],
  "edges": [
    { "from": "main", "to": "sym.check_password", "type": "call" },
    { "from": "main", "to": "sym.imp.puts", "type": "call" },
    { "from": "sym.check_password", "to": "sym.imp.strcmp", "type": "call" }
  ],
  "depth": 3
}
```

**r2-Befehl:**
- `agcj @ <func>` (Callgraph als JSON)
- `agcd @ <func>` (Callgraph als DOT)
- `agCj` (Globaler Callgraph JSON)

**Beispiel:**
```
Input:  { "session_id": "a1b2c3d4...", "function_name": "main", "depth": 2, "format": "json" }
Output: {
  "root": "main",
  "nodes": [
    { "name": "main", "address": "0x00401000" },
    { "name": "sym.check_password", "address": "0x00401200" },
    { "name": "sym.imp.puts", "address": "0x00401030" }
  ],
  "edges": [
    { "from": "main", "to": "sym.check_password" },
    { "from": "main", "to": "sym.imp.puts" }
  ]
}
```

---

### 6.3 `get_cfg`

**Beschreibung:** Gibt den Control Flow Graph (CFG) einer Funktion zurueck. Zeigt Basic Blocks und deren Verbindungen (true/false branches, unconditional jumps). Essentiell fuer das Verstaendnis der Programmlogik.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "description": "Session-ID"
    },
    "function_name": {
      "type": "string",
      "default": null,
      "description": "Funktionsname"
    },
    "address": {
      "type": "string",
      "default": null,
      "description": "Funktionsadresse (hex)"
    },
    "format": {
      "type": "string",
      "enum": ["json", "dot", "mermaid"],
      "default": "json",
      "description": "Ausgabeformat"
    }
  },
  "required": ["session_id"],
  "oneOf_note": "Mindestens function_name oder address muss angegeben werden"
}
```

**Output-Format (JSON):**
```json
{
  "function": "main",
  "address": "0x00401000",
  "basic_blocks": [
    {
      "address": "0x00401000",
      "size": 24,
      "num_instructions": 6,
      "instructions": [
        { "offset": "0x00401000", "opcode": "push rbp" },
        { "offset": "0x00401001", "opcode": "mov rbp, rsp" },
        { "offset": "0x00401004", "opcode": "sub rsp, 0x20" },
        { "offset": "0x00401008", "opcode": "mov [rbp-0x14], edi" },
        { "offset": "0x0040100b", "opcode": "cmp dword [rbp-0x14], 1" },
        { "offset": "0x0040100f", "opcode": "jg 0x00401020" }
      ],
      "jump_target": "0x00401020",
      "fail_target": "0x00401011",
      "type": "conditional"
    }
  ],
  "edges": [
    { "from": "0x00401000", "to": "0x00401020", "type": "true" },
    { "from": "0x00401000", "to": "0x00401011", "type": "false" }
  ],
  "num_blocks": 8,
  "cyclomatic_complexity": 4
}
```

**r2-Befehl:** `agfj @ <func>` (Function graph als JSON), `agfd @ <func>` (als DOT)

**Beispiel:**
```
Input:  { "session_id": "a1b2c3d4...", "function_name": "main", "format": "json" }
Output: {
  "function": "main",
  "basic_blocks": [
    { "address": "0x00401000", "size": 24, "num_instructions": 6, "type": "conditional",
      "jump_target": "0x00401020", "fail_target": "0x00401011" }
  ],
  "num_blocks": 8,
  "cyclomatic_complexity": 4
}
```

---

### 6.4 `rename_function`

**Beschreibung:** Benennt eine Funktion um. Wichtig um die Analyse-Ergebnisse fuer den Menschen lesbarer zu machen, indem auto-generierte Namen (wie `fcn.00401200`) durch beschreibende Namen ersetzt werden.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "description": "Session-ID"
    },
    "old_name": {
      "type": "string",
      "default": null,
      "description": "Aktueller Funktionsname"
    },
    "address": {
      "type": "string",
      "default": null,
      "description": "Funktionsadresse (hex)"
    },
    "new_name": {
      "type": "string",
      "description": "Neuer Funktionsname"
    }
  },
  "required": ["session_id", "new_name"],
  "oneOf_note": "Mindestens old_name oder address muss angegeben werden"
}
```

**Output-Format:**
```json
{
  "address": "0x00401200",
  "old_name": "fcn.00401200",
  "new_name": "check_password",
  "success": true
}
```

**r2-Befehl:** `afn <new_name> @ <addr>` oder `afn <new_name> <old_name>`

**Beispiel:**
```
Input:  { "session_id": "a1b2c3d4...", "old_name": "fcn.00401200", "new_name": "check_password" }
Output: { "address": "0x00401200", "old_name": "fcn.00401200", "new_name": "check_password", "success": true }
```

---

### 6.5 `add_comment`

**Beschreibung:** Fuegt einen Kommentar an einer bestimmten Adresse hinzu. Kommentare werden in der Disassembly- und Decompiler-Ausgabe angezeigt und helfen bei der Dokumentation der Analyse.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "description": "Session-ID"
    },
    "address": {
      "type": "string",
      "description": "Adresse (hex)"
    },
    "comment": {
      "type": "string",
      "description": "Kommentartext"
    },
    "type": {
      "type": "string",
      "enum": ["inline", "function", "block"],
      "default": "inline",
      "description": "Kommentartyp: inline (neben Instruktion), function (Funktionskommentar), block (ueber Basic Block)"
    }
  },
  "required": ["session_id", "address", "comment"]
}
```

**Output-Format:**
```json
{
  "address": "0x00401050",
  "comment": "Checks if argument count > 1",
  "type": "inline",
  "success": true
}
```

**r2-Befehl:**
- `inline` -> `CC <comment> @ <addr>` (Inline-Kommentar)
- `function` -> `CCf <comment> @ <addr>` (Funktionskommentar)
- `block` -> Ueber `CC` mit Prefix

**Beispiel:**
```
Input:  { "session_id": "a1b2c3d4...", "address": "0x00401050", "comment": "Validate argument count", "type": "inline" }
Output: { "address": "0x00401050", "comment": "Validate argument count", "type": "inline", "success": true }
```

---

### 6.6 `set_breakpoint`

**Beschreibung:** Setzt einen ESIL-Breakpoint an einer bestimmten Adresse. Breakpoints werden waehrend der ESIL-Emulation ausgewertet und stoppen die Ausfuehrung an der markierten Stelle.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "description": "Session-ID"
    },
    "address": {
      "type": "string",
      "description": "Breakpoint-Adresse (hex)"
    },
    "enabled": {
      "type": "boolean",
      "default": true,
      "description": "Breakpoint aktiviert/deaktiviert"
    },
    "temporary": {
      "type": "boolean",
      "default": false,
      "description": "Temporaerer Breakpoint (wird nach erstem Hit entfernt)"
    },
    "condition": {
      "type": "string",
      "default": null,
      "description": "Optionale Bedingung als ESIL-Ausdruck (z.B. 'rax,0,==')"
    }
  },
  "required": ["session_id", "address"]
}
```

**Output-Format:**
```json
{
  "address": "0x00401050",
  "id": 0,
  "enabled": true,
  "temporary": false,
  "condition": null,
  "success": true
}
```

**r2-Befehl:** `db <addr>` (Breakpoint setzen), `dbc <addr> <cmd>` (Conditional), `dbs <addr>` (Toggle)

**Beispiel:**
```
Input:  { "session_id": "a1b2c3d4...", "address": "0x00401050", "temporary": true }
Output: { "address": "0x00401050", "id": 0, "enabled": true, "temporary": true, "success": true }
```

---

### 6.7 `list_breakpoints`

**Beschreibung:** Listet alle gesetzten Breakpoints in der aktuellen Session auf.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "description": "Session-ID"
    }
  },
  "required": ["session_id"]
}
```

**Output-Format:**
```json
{
  "breakpoints": [
    {
      "id": 0,
      "address": "0x00401050",
      "enabled": true,
      "temporary": false,
      "hits": 0,
      "condition": null
    }
  ],
  "total": 1
}
```

**r2-Befehl:** `dbj` (Breakpoints als JSON)

**Beispiel:**
```
Input:  { "session_id": "a1b2c3d4..." }
Output: {
  "breakpoints": [
    { "id": 0, "address": "0x00401050", "enabled": true, "temporary": false, "hits": 2 },
    { "id": 1, "address": "0x00401200", "enabled": true, "temporary": true, "hits": 0 }
  ],
  "total": 2
}
```

---

### 6.8 `rename_variable`

**Beschreibung:** Benennt eine lokale Variable oder einen Funktionsparameter in einer Funktion um. Verbessert die Lesbarkeit der Decompiler-Ausgabe.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "description": "Session-ID"
    },
    "function_name": {
      "type": "string",
      "default": null,
      "description": "Funktionsname"
    },
    "function_address": {
      "type": "string",
      "default": null,
      "description": "Funktionsadresse (hex)"
    },
    "old_name": {
      "type": "string",
      "description": "Aktueller Variablenname (z.B. 'var_8h', 'arg_0h')"
    },
    "new_name": {
      "type": "string",
      "description": "Neuer Variablenname"
    }
  },
  "required": ["session_id", "old_name", "new_name"],
  "oneOf_note": "Mindestens function_name oder function_address muss angegeben werden"
}
```

**Output-Format:**
```json
{
  "function": "main",
  "old_name": "var_8h",
  "new_name": "buffer",
  "success": true
}
```

**r2-Befehl:** `afvn <new_name> <old_name> @ <func>` (Rename local variable)

**Beispiel:**
```
Input:  { "session_id": "a1b2c3d4...", "function_name": "main", "old_name": "var_8h", "new_name": "user_input" }
Output: { "function": "main", "old_name": "var_8h", "new_name": "user_input", "success": true }
```

---

### 6.9 `set_function_type`

**Beschreibung:** Setzt den Prototyp (Signatur) einer Funktion. Dies verbessert die Decompiler-Ausgabe erheblich, indem korrekte Parametertypen und Rueckgabewerte angezeigt werden.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "description": "Session-ID"
    },
    "function_name": {
      "type": "string",
      "default": null,
      "description": "Funktionsname"
    },
    "address": {
      "type": "string",
      "default": null,
      "description": "Funktionsadresse (hex)"
    },
    "prototype": {
      "type": "string",
      "description": "C-Funktionsprototyp (z.B. 'int check_password(const char *password)')"
    }
  },
  "required": ["session_id", "prototype"],
  "oneOf_note": "Mindestens function_name oder address muss angegeben werden"
}
```

**Output-Format:**
```json
{
  "function": "check_password",
  "address": "0x00401200",
  "prototype": "int check_password(const char *password)",
  "success": true
}
```

**r2-Befehl:** `aft <prototype> @ <addr>` oder `afs <signature> @ <addr>`

**Beispiel:**
```
Input:  { "session_id": "a1b2c3d4...", "function_name": "check_password", "prototype": "int check_password(const char *password)" }
Output: { "function": "check_password", "address": "0x00401200", "prototype": "int check_password(const char *password)", "success": true }
```

---

### 6.10 `get_function_variables`

**Beschreibung:** Listet alle lokalen Variablen und Parameter einer Funktion auf, inklusive Stack-Offset, Typ und Name.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "description": "Session-ID"
    },
    "function_name": {
      "type": "string",
      "default": null,
      "description": "Funktionsname"
    },
    "address": {
      "type": "string",
      "default": null,
      "description": "Funktionsadresse (hex)"
    }
  },
  "required": ["session_id"],
  "oneOf_note": "Mindestens function_name oder address muss angegeben werden"
}
```

**Output-Format:**
```json
{
  "function": "main",
  "address": "0x00401000",
  "variables": [
    {
      "name": "var_8h",
      "kind": "var",
      "type": "int",
      "storage": "stack",
      "offset": -8
    },
    {
      "name": "argc",
      "kind": "arg",
      "type": "int",
      "storage": "reg",
      "register": "edi"
    }
  ],
  "total": 5
}
```

**r2-Befehl:** `afvj @ <func>` (Funktionsvariablen als JSON)

**Beispiel:**
```
Input:  { "session_id": "a1b2c3d4...", "function_name": "main" }
Output: {
  "function": "main",
  "variables": [
    { "name": "argc", "kind": "arg", "type": "int", "storage": "reg", "register": "edi" },
    { "name": "argv", "kind": "arg", "type": "char **", "storage": "reg", "register": "rsi" },
    { "name": "var_8h", "kind": "var", "type": "int64_t", "storage": "stack", "offset": -8 }
  ],
  "total": 3
}
```

---

### 6.11 `assemble`

**Beschreibung:** Assembliert Assembly-Instruktionen in Maschinencode. Die Umkehroperation zu `disassemble_bytes`. Nuetzlich fuer Patching und Shellcode-Erstellung.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "assembly": {
      "type": "string",
      "description": "Assembly-Code (z.B. 'nop; push rbp; mov rbp, rsp')"
    },
    "architecture": {
      "type": "string",
      "default": "x86",
      "description": "Architektur"
    },
    "bits": {
      "type": "integer",
      "enum": [16, 32, 64],
      "default": 64,
      "description": "Bitbreite"
    },
    "base_address": {
      "type": "string",
      "default": "0x00000000",
      "description": "Basisadresse (wichtig fuer relative Spruenge)"
    }
  },
  "required": ["assembly"]
}
```

**Output-Format:**
```json
{
  "assembly": "nop; push rbp; mov rbp, rsp",
  "hex": "90554889e5",
  "bytes": [144, 85, 72, 137, 229],
  "size": 5,
  "architecture": "x86",
  "bits": 64
}
```

**r2-Befehl:** `rasm2 -a <arch> -b <bits> '<assembly>'` oder inline: `pa <assembly>`

**Beispiel:**
```
Input:  { "assembly": "xor eax, eax; push eax; mov al, 1; int 0x80", "architecture": "x86", "bits": 32 }
Output: {
  "assembly": "xor eax, eax; push eax; mov al, 1; int 0x80",
  "hex": "31c050b001cd80",
  "bytes": [49, 192, 80, 176, 1, 205, 128],
  "size": 7
}
```

---

### 6.12 `get_flags`

**Beschreibung:** Listet alle Flags (benannte Adressen/Labels) im Binary auf. Flags sind r2-interne Marker fuer wichtige Adressen wie Funktionen, Strings, Imports, Sections, etc.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "description": "Session-ID"
    },
    "flagspace": {
      "type": "string",
      "default": null,
      "description": "Flagspace-Filter (z.B. 'symbols', 'strings', 'imports', 'sections', 'functions'). Null fuer alle."
    },
    "filter": {
      "type": "string",
      "default": null,
      "description": "Optionaler Namensfilter (Substring-Match)"
    },
    "offset": {
      "type": "integer",
      "default": 0,
      "description": "Pagination: Startindex"
    },
    "limit": {
      "type": "integer",
      "default": 100,
      "description": "Pagination: Max. Anzahl"
    }
  },
  "required": ["session_id"]
}
```

**Output-Format:**
```json
{
  "flags": [
    {
      "name": "sym.main",
      "address": "0x00401000",
      "size": 245,
      "space": "symbols"
    }
  ],
  "total": 250,
  "offset": 0,
  "limit": 100
}
```

**r2-Befehl:** `fj` (Flags als JSON), `fs <space>; fj` (gefiltert nach Flagspace)

**Beispiel:**
```
Input:  { "session_id": "a1b2c3d4...", "flagspace": "imports" }
Output: {
  "flags": [
    { "name": "sym.imp.puts", "address": "0x00401030", "size": 6, "space": "imports" },
    { "name": "sym.imp.strcmp", "address": "0x00401040", "size": 6, "space": "imports" }
  ],
  "total": 15,
  "offset": 0,
  "limit": 100
}
```

---

### 6.13 `set_variable_type`

**Beschreibung:** Setzt den Typ einer lokalen Variable in einer Funktion. Verbessert die Decompiler-Ausgabe durch korrekte Typ-Informationen.

**Parameter (JSON Schema):**
```json
{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "description": "Session-ID"
    },
    "function_name": {
      "type": "string",
      "default": null,
      "description": "Funktionsname"
    },
    "function_address": {
      "type": "string",
      "default": null,
      "description": "Funktionsadresse (hex)"
    },
    "variable_name": {
      "type": "string",
      "description": "Variablenname"
    },
    "new_type": {
      "type": "string",
      "description": "Neuer C-Typ (z.B. 'char *', 'int', 'struct sockaddr_in *')"
    }
  },
  "required": ["session_id", "variable_name", "new_type"],
  "oneOf_note": "Mindestens function_name oder function_address muss angegeben werden"
}
```

**Output-Format:**
```json
{
  "function": "main",
  "variable": "var_8h",
  "old_type": "int64_t",
  "new_type": "char *",
  "success": true
}
```

**r2-Befehl:** `afvt <variable_name> <new_type> @ <func>`

**Beispiel:**
```
Input:  { "session_id": "a1b2c3d4...", "function_name": "main", "variable_name": "var_8h", "new_type": "char *" }
Output: { "function": "main", "variable": "var_8h", "old_type": "int64_t", "new_type": "char *", "success": true }
```

---

## Fehlerbehandlung

Alle Tool Calls folgen einem einheitlichen Fehlerformat:

```json
{
  "error": true,
  "error_code": "string",
  "error_message": "string",
  "details": {}
}
```

### Fehlercodes

| Code | Beschreibung |
|------|-------------|
| `SESSION_NOT_FOUND` | Session-ID existiert nicht oder wurde bereits geschlossen |
| `FILE_NOT_FOUND` | Angegebene Datei existiert nicht |
| `INVALID_ADDRESS` | Ungueltige Adresse (falsches Format oder ausserhalb des Speicherbereichs) |
| `FUNCTION_NOT_FOUND` | Funktion mit angegebenem Namen/Adresse nicht gefunden |
| `ESIL_NOT_INITIALIZED` | ESIL VM wurde nicht initialisiert (esil_init fehlt) |
| `ESIL_ERROR` | Fehler waehrend der ESIL-Emulation |
| `TIMEOUT` | Befehl hat das Timeout ueberschritten |
| `INVALID_PARAMETER` | Ungueltiger Parameter-Wert |
| `R2_ERROR` | Interner radare2-Fehler |
| `ANALYSIS_REQUIRED` | Befehl erfordert vorherige Analyse (analyze_binary) |
| `DECOMPILER_NOT_AVAILABLE` | Angeforderter Decompiler (r2ghidra/r2dec) ist nicht installiert |
| `PERMISSION_DENIED` | Schreibzugriff auf Binary nicht erlaubt |
| `SHELLCODE_PARSE_ERROR` | Shellcode-Hex-String konnte nicht geparst werden |

### Beispiel Fehler-Antwort

```json
{
  "error": true,
  "error_code": "FUNCTION_NOT_FOUND",
  "error_message": "Function 'check_password' not found. Run analyze_binary first or check the function name.",
  "details": {
    "searched_name": "check_password",
    "suggestion": "Did you mean 'sym.check_pw'? Use list_functions to see all available functions."
  }
}
```

---

## Empfohlene Workflows

### Workflow 1: Basis-Analyse eines Binaries
```
1. open_binary(file_path="/tmp/target", analyze=true)
2. get_binary_info(session_id=...)
3. list_functions(session_id=...)
4. get_strings(session_id=...)
5. get_imports(session_id=...)
6. disassemble_function(session_id=..., function_name="main")
7. decompile_function(session_id=..., function_name="main")
```

### Workflow 2: Shellcode-Analyse
```
1. analyze_shellcode(shellcode="31c050...", architecture="x86", bits=32)
2. detect_shellcode_patterns(shellcode="31c050...")
3. emulate_shellcode(shellcode="31c050...", trace_syscalls=true)
```

### Workflow 3: ESIL-basierte Emulation einer Funktion
```
1. open_binary(file_path="/tmp/target", analyze=true)
2. esil_init(session_id=..., address="0x00401200")
3. esil_set_register(session_id=..., register="rdi", value="0x00402050")
4. esil_set_memory(session_id=..., address="0x00402050", data="s:test_password")
5. esil_run(session_id=..., until_address="0x004012f0", max_steps=5000)
6. esil_get_registers(session_id=..., registers=["rax"])
7. esil_get_memory(session_id=..., address="0x0012ffd0", size=64)
```

### Workflow 4: Reverse Engineering mit Annotationen
```
1. open_binary(file_path="/tmp/crackme", analyze=true)
2. list_functions(session_id=...)
3. disassemble_function(session_id=..., function_name="fcn.00401200")
4. rename_function(session_id=..., old_name="fcn.00401200", new_name="validate_license")
5. get_function_variables(session_id=..., function_name="validate_license")
6. rename_variable(session_id=..., function_name="validate_license", old_name="var_8h", new_name="license_key")
7. set_variable_type(session_id=..., function_name="validate_license", variable_name="license_key", new_type="char *")
8. add_comment(session_id=..., address="0x00401250", comment="XOR decode loop for license check")
9. decompile_function(session_id=..., function_name="validate_license")
```

---

## Zusammenfassung aller Tool Calls

| Nr | Name | Kategorie | r2-Befehl(e) |
|----|------|-----------|---------------|
| 1 | `open_binary` | Session | `r2 <file>` + `aaa` |
| 2 | `close_session` | Session | `quit` |
| 3 | `list_sessions` | Session | intern |
| 4 | `analyze_binary` | Analysis | `aa` / `aac` / `aaa` / `aaaa` |
| 5 | `get_binary_info` | Analysis | `ij` / `iIj` |
| 6 | `list_functions` | Analysis | `aflj` |
| 7 | `disassemble_function` | Analysis | `s <addr>; pdfj` |
| 8 | `decompile_function` | Analysis | `s <addr>; pdc` / `pdg` / `pdd` |
| 9 | `get_strings` | Analysis | `izj` / `izzj` |
| 10 | `get_imports` | Analysis | `iij` |
| 11 | `get_exports` | Analysis | `iEj` |
| 12 | `get_sections` | Analysis | `iSj` |
| 13 | `get_entry_points` | Analysis | `iej` |
| 14 | `get_xrefs_to` | Analysis | `axtj @ <addr>` |
| 15 | `get_xrefs_from` | Analysis | `axfj @ <addr>` |
| 16 | `esil_init` | ESIL | `aei; aeim; aeip` |
| 17 | `esil_step` | ESIL | `aes` / `aesj` |
| 18 | `esil_run` | ESIL | `aec` / `aecu <addr>` |
| 19 | `esil_get_registers` | ESIL | `aerj` |
| 20 | `esil_set_register` | ESIL | `aer <reg>=<val>` |
| 21 | `esil_get_memory` | ESIL | `px <n> @ <addr>` |
| 22 | `esil_set_memory` | ESIL | `wx <hex> @ <addr>` |
| 23 | `esil_expression` | ESIL | `ae <expr>` |
| 24 | `analyze_shellcode` | Shellcode | kombiniert |
| 25 | `detect_shellcode_patterns` | Shellcode | `/x` + Heuristik |
| 26 | `emulate_shellcode` | Shellcode | kombiniert (ESIL) |
| 27 | `disassemble_bytes` | Shellcode | `pad <hex>` / `rasm2 -d` |
| 28 | `seek` | Memory | `s <target>` |
| 29 | `read_bytes` | Memory | `px` / `p8` / `pc` |
| 30 | `write_bytes` | Memory | `wx` / `w` / `wa` |
| 31 | `search_bytes` | Memory | `/x` / `/` / `/e` / `/R` |
| 32 | `search_string` | Memory | `/` / `/e` |
| 33 | `run_r2_command` | Advanced | beliebig |
| 34 | `get_callgraph` | Advanced | `agcj` / `agCj` |
| 35 | `get_cfg` | Advanced | `agfj` |
| 36 | `rename_function` | Advanced | `afn` |
| 37 | `add_comment` | Advanced | `CC` |
| 38 | `set_breakpoint` | Advanced | `db` |
| 39 | `list_breakpoints` | Advanced | `dbj` |
| 40 | `rename_variable` | Advanced | `afvn` |
| 41 | `set_function_type` | Advanced | `aft` / `afs` |
| 42 | `get_function_variables` | Advanced | `afvj` |
| 43 | `assemble` | Advanced | `pa` / `rasm2` |
| 44 | `get_flags` | Advanced | `fj` |
| 45 | `set_variable_type` | Advanced | `afvt` |
