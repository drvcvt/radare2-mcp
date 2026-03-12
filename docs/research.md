# Radare2 MCP - Research Documentation

> Umfassende Dokumentation zu radare2 und dem Model Context Protocol (MCP).
> Quellen: book.rada.re, r2wiki.readthedocs.io, modelcontextprotocol.io, GitHub Repositories.

---

## 1. radare2 Grundlagen

### 1.1 Wichtige Befehle

radare2 (r2) ist ein Open-Source-Framework fuer Reverse Engineering und Binary-Analyse. Es bietet eine kommandozeilenbasierte Oberflaeche mit hunderten von Befehlen.

#### 1.1.1 Starten und Oeffnen

```bash
# Datei oeffnen
r2 binary
r2 -d binary            # Im Debug-Modus oeffnen
r2 -w binary            # Im Schreibmodus oeffnen
r2 -A binary            # Oeffnen + automatische Analyse (aaa)
r2 -a arm -b 32 binary  # Architektur und Bitbreite setzen
r2 -               # Von stdin lesen (z.B. fuer Shellcode)
r2 malloc://512          # Leeren Speicherblock oeffnen

# Shellcode direkt analysieren
echo -ne '\x31\xc0\x50...' | r2 -a x86 -b 32 -
r2 -a x86 -b 32 -c 'pd 20' shellcode.bin
```

#### 1.1.2 Analyse-Befehle (a)

| Befehl | Beschreibung |
|--------|-------------|
| `a`    | Analyse-Hilfe anzeigen |
| `aa`   | Analyse aller Funktionen (basic) |
| `aaa`  | Erweiterte automatische Analyse (empfohlen) |
| `aaaa`  | Experimentelle, noch tiefere Analyse |
| `afl`  | Alle erkannten Funktionen auflisten |
| `afll` | Funktionen mit Details auflisten (Groesse, Aufrufe) |
| `afn name addr` | Funktion umbenennen |
| `af`   | Funktion an aktueller Adresse analysieren |
| `af+`  | Funktion manuell definieren |
| `af-`  | Funktion entfernen |
| `afi`  | Funktions-Info anzeigen |
| `afv`  | Lokale Variablen anzeigen |
| `afvn old new` | Variable umbenennen |
| `ax`   | Cross-References anzeigen |
| `axt addr` | Xrefs TO addr (wer referenziert diese Adresse) |
| `axf addr` | Xrefs FROM addr (was referenziert diese Adresse) |
| `ag`   | ASCII-Art Graph erzeugen |
| `agf`  | Funktions-Graph im ASCII-Format |
| `agC`  | Callgraph als Graphviz-DOT |
| `ahi`  | Hinweise zu Immediate-Werten setzen |
| `ah`   | Analyse-Hinweise verwalten |
| `ao`   | Opcode-Info anzeigen |
| `aoj`  | Opcode-Info als JSON |

#### 1.1.3 Print/Display-Befehle (p)

| Befehl | Beschreibung |
|--------|-------------|
| `pd N` | N Instruktionen disassemblieren |
| `pd -N` | N Instruktionen rueckwaerts disassemblieren |
| `pdf`  | Aktuelle Funktion disassemblieren |
| `pdr`  | Rekursive Disassembly (folgt Spruengen) |
| `pdc`  | Pseudocode / C-aehnliche Ausgabe |
| `pdg`  | Ghidra-Decompiler (mit r2ghidra Plugin) |
| `px N` | N Bytes als Hexdump anzeigen |
| `pxw N` | Hexdump in 32-bit Woertern |
| `pxq N` | Hexdump in 64-bit Woertern |
| `ps`   | String an aktueller Position drucken |
| `psz`  | Zero-terminated String drucken |
| `pf`   | Formatierte Daten drucken (Struct-Parser) |
| `pf xx` | Zwei 32-bit Hex-Werte drucken |
| `p8 N` | N Bytes als Hex-String |
| `pi N` | N Instruktionen ohne Adressen |
| `pD N` | N Bytes disassemblieren |
| `pr N` | Raw-Bytes drucken |

#### 1.1.4 Suchen-Befehle (/)

| Befehl | Beschreibung |
|--------|-------------|
| `/ string` | String im Speicher suchen |
| `/x hex`   | Hex-Pattern suchen |
| `/R opcode` | ROP-Gadgets suchen |
| `/r addr`  | Referenzen zu Adresse suchen |
| `/a`       | Alle AES-Keys suchen |
| `/c`       | Kryptografische Materialien suchen |
| `/m`       | Magic-Bytes suchen |
| `/p prelude` | Funktions-Preludes suchen |
| `/v value` | Numerischen Wert suchen |
| `/V min max` | Wert in Range suchen |
| `/w string` | Wide-String suchen |
| `/i string` | Case-insensitive Suche |
| `/e regex`  | Regex-Suche |

#### 1.1.5 Seek-Befehle (s)

| Befehl | Beschreibung |
|--------|-------------|
| `s addr`   | Zu Adresse springen |
| `s+ N`     | N Bytes vorwaerts |
| `s- N`     | N Bytes rueckwaerts |
| `s main`   | Zu Symbol "main" springen |
| `sf`       | Zur naechsten Funktion springen |
| `sf.`      | Zum Anfang der aktuellen Funktion |
| `sr rsp`   | Zum Wert des Registers springen |
| `s-`       | Undo (letzte Seek-Position) |
| `s+`       | Redo |

#### 1.1.6 Flags und Metadaten (f)

| Befehl | Beschreibung |
|--------|-------------|
| `f name addr` | Flag (Bookmark) setzen |
| `f- name`     | Flag entfernen |
| `fl`           | Alle Flags auflisten |
| `fs`           | Flag-Spaces anzeigen |
| `fs strings`   | Zu Flag-Space "strings" wechseln |
| `f~name`       | Flags filtern (grep) |

#### 1.1.7 Informations-Befehle (i)

| Befehl | Beschreibung |
|--------|-------------|
| `i`    | Datei-Info anzeigen |
| `ia`   | Alle Infos anzeigen |
| `ie`   | Entrypoints anzeigen |
| `ii`   | Imports anzeigen |
| `iE`   | Exports anzeigen |
| `is`   | Symbols anzeigen |
| `iz`   | Strings in der Data-Section |
| `izz`  | Strings in der gesamten Datei |
| `iS`   | Sections anzeigen |
| `iSS`  | Segmente anzeigen |
| `il`   | Libraries anzeigen |
| `ir`   | Relocations anzeigen |
| `ic`   | Klassen anzeigen (C++, ObjC) |
| `ih`   | Header-Info anzeigen |

#### 1.1.8 Write-Befehle (w)

| Befehl | Beschreibung |
|--------|-------------|
| `w string`  | String schreiben |
| `wx hex`    | Hex-Bytes schreiben |
| `wa asm`    | Assembler-Instruktion schreiben |
| `wao nop`   | Instruktion mit NOP ueberschreiben |
| `wc`        | Write-Cache verwalten |

#### 1.1.9 Debug-Befehle (d)

| Befehl | Beschreibung |
|--------|-------------|
| `db addr`  | Breakpoint setzen |
| `db- addr` | Breakpoint entfernen |
| `dc`       | Continue (weiterlaufen) |
| `ds`       | Step Into |
| `dso`      | Step Over |
| `dr`       | Register anzeigen |
| `dr=`      | Register-Uebersicht |
| `drr`      | Register mit Referenzen |
| `drt`      | Register-Typen |
| `dm`       | Memory-Maps anzeigen |
| `dmp`      | Memory-Permissions aendern |
| `dk signal` | Signal senden |
| `dp`       | Prozess-Info |
| `dbt`      | Backtrace anzeigen |

#### 1.1.10 Visuelle Modi (V)

| Befehl | Beschreibung |
|--------|-------------|
| `V`    | Visuellen Modus starten |
| `VV`   | Graph-Modus starten |
| `Vp`   | Visuell mit Panel-Layout |
| `v`    | Panels-Modus |

Im visuellen Modus:
- `p/P` - Ansicht wechseln
- `hjkl` - Navigation (vim-style)
- `:` - Befehlszeile
- `q` - Zurueck

#### 1.1.11 Projekt- und Session-Verwaltung

| Befehl | Beschreibung |
|--------|-------------|
| `Ps name` | Projekt speichern |
| `Po name` | Projekt oeffnen |
| `Pl`      | Projekte auflisten |

#### 1.1.12 Allgemeine Modifikatoren

| Suffix | Beschreibung |
|--------|-------------|
| `j`    | JSON-Ausgabe (z.B. `aflj`, `pdj`, `ij`) |
| `q`    | Quiet/kurze Ausgabe |
| `*`    | r2-Befehle als Ausgabe (scriptable) |
| `~pattern` | Internes grep |
| `~:N`  | N-te Zeile auswaehlen |
| `~[N]` | N-te Spalte auswaehlen |
| `@@`   | Befehl auf mehrere Adressen anwenden |
| `@`    | Temporaer Adresse wechseln |

```bash
# Beispiele fuer Modifikatoren
afl~main          # Funktionen filtern nach "main"
afl~:0            # Erste Funktion
aflj               # Funktionen als JSON
pdf @ main        # main disassemblieren ohne seek
pd 5 @@ sym.*    # 5 Instruktionen fuer jede Funktion
iz~password       # Strings nach "password" filtern
```

---

### 1.2 r2pipe API

r2pipe ist die offizielle Scripting-Schnittstelle fuer radare2. Sie erlaubt es, r2-Befehle programmatisch aus verschiedenen Sprachen heraus auszufuehren.

#### 1.2.1 Architektur

r2pipe kommuniziert mit radare2 ueber verschiedene Transportwege:
- **Pipes** (stdin/stdout) - Standard fuer lokale Prozesse
- **HTTP** - Ueber den r2 Webserver (`r2 -c '=h 8080' binary`)
- **TCP** - Ueber TCP-Sockets (`r2 -c '=t 9090' binary`)

#### 1.2.2 Python r2pipe

**Installation:**
```bash
pip install r2pipe
```

**Grundlegende Nutzung:**
```python
import r2pipe

# Datei oeffnen
r2 = r2pipe.open("/path/to/binary")

# Alternativ: Verbindung zu laufender Instanz
r2 = r2pipe.open("http://localhost:8080")

# Befehle ausfuehren
r2.cmd("aaa")                    # Analyse durchfuehren
print(r2.cmd("afl"))             # Funktionen auflisten

# JSON-Ausgabe direkt als Python-Dict
functions = r2.cmdj("aflj")      # Gibt Liste von Dicts zurueck
for func in functions:
    print(f"{func['name']} at {func['offset']:#x}, size: {func['size']}")

# Info als JSON
info = r2.cmdj("ij")
print(f"Architecture: {info['bin']['arch']}")
print(f"Bits: {info['bin']['bits']}")
print(f"OS: {info['bin']['os']}")

# Disassembly
disasm = r2.cmdj("pdj 10")       # 10 Instruktionen als JSON
for insn in disasm:
    print(f"  {insn['offset']:#x}: {insn['opcode']}")

# Hex-Daten lesen
hexdump = r2.cmd("px 64")
print(hexdump)

# Session beenden
r2.quit()
```

**Wichtige Methoden:**

| Methode | Beschreibung |
|---------|-------------|
| `r2pipe.open(target)` | Oeffnet Verbindung zu r2 |
| `r2.cmd(command)` | Fuehrt Befehl aus, gibt String zurueck |
| `r2.cmdj(command)` | Fuehrt Befehl aus, parst JSON-Ausgabe |
| `r2.quit()` | Schliesst die r2-Session |

**Erweiterte Nutzung:**
```python
import r2pipe

r2 = r2pipe.open("/path/to/binary")
r2.cmd("aaa")

# Strings extrahieren
strings = r2.cmdj("izj")
for s in strings:
    print(f"  {s['vaddr']:#x}: {s['string']}")

# Sections
sections = r2.cmdj("iSj")
for sec in sections:
    print(f"  {sec['name']}: {sec['vaddr']:#x} - size {sec['size']}")

# Imports
imports = r2.cmdj("iij")
for imp in imports:
    print(f"  {imp.get('name', 'unknown')} (type: {imp.get('type', '?')})")

# Exports
exports = r2.cmdj("iEj")

# Cross-References
xrefs = r2.cmdj("axtj @ sym.vulnerable_func")

# Funktion disassemblieren
r2.cmd("s main")
main_disasm = r2.cmdj("pdfj")
for op in main_disasm.get('ops', []):
    print(f"  {op['offset']:#x}: {op.get('opcode', '')}")

# Hex-Bytes lesen
r2.cmd("s 0x08048000")
bytes_hex = r2.cmd("p8 16")      # 16 Bytes als Hex-String

# Suchen
results = r2.cmdj("/j /bin/sh")  # String suchen, JSON

# Shellcode analysieren
r2 = r2pipe.open("malloc://4096")
r2.cmd("e asm.arch=x86")
r2.cmd("e asm.bits=32")
shellcode = "31c050682f2f7368682f62696e89e3505389e1b00bcd80"
r2.cmd(f"wx {shellcode}")
r2.cmd("aaa")
print(r2.cmd("pd 20"))

r2.quit()
```

#### 1.2.3 TypeScript/JavaScript r2pipe

**Installation:**
```bash
npm install r2pipe
```

**Nutzung:**
```typescript
import r2pipe from 'r2pipe';

// Callback-basiert
r2pipe.open('/path/to/binary', (err: Error | null, r2: any) => {
    if (err) throw err;

    r2.cmd('aaa', (err: Error | null, output: string) => {
        console.log('Analysis done');
    });

    r2.cmdj('aflj', (err: Error | null, functions: any[]) => {
        functions.forEach(f => {
            console.log(`${f.name} @ 0x${f.offset.toString(16)}`);
        });
    });
});

// Promise-basiert (mit r2pipe-promise oder Wrapper)
async function analyze(path: string) {
    return new Promise((resolve, reject) => {
        r2pipe.open(path, (err, r2) => {
            if (err) return reject(err);

            r2.cmd('aaa', () => {
                r2.cmdj('aflj', (err, functions) => {
                    if (err) return reject(err);
                    resolve(functions);
                    r2.quit();
                });
            });
        });
    });
}
```

**r2pipe-promise (Alternative mit async/await):**
```typescript
// npm install r2pipe-promise
import r2pipe from 'r2pipe-promise';

async function main() {
    const r2 = await r2pipe.open('/path/to/binary');
    await r2.cmd('aaa');

    const functions = await r2.cmdj('aflj');
    console.log(`Found ${functions.length} functions`);

    const info = await r2.cmdj('ij');
    console.log(`Arch: ${info.bin.arch}, Bits: ${info.bin.bits}`);

    await r2.quit();
}
```

#### 1.2.4 r2pipe Flags und Optionen

```python
import r2pipe

# Mit Flags oeffnen
r2 = r2pipe.open("/path/to/binary", flags=["-2"])  # stderr ignorieren

# Shellcode aus Datei
r2 = r2pipe.open("malloc://1024", flags=["-a", "x86", "-b", "32"])

# Von stdin (shellcode bytes)
r2 = r2pipe.open("-", flags=["-a", "x86", "-b", "32"])
```

---

### 1.3 ESIL (Evaluable Strings Intermediate Language)

#### 1.3.1 Was ist ESIL?

ESIL ist die Intermediate Language (IL) von radare2 fuer die Emulation von Maschinencode. Es ermoeglicht:
- Code-Emulation ohne nativen Prozessor
- Symbolische Ausfuehrung
- Datenflussanalyse
- Werteverfolgung ueber mehrere Instruktionen

ESIL verwendet eine **postfix-Notation** (Reverse Polish Notation / Stack-basiert), aehnlich wie Forth.

#### 1.3.2 ESIL-Syntax

Grundformat: `Operand1,Operand2,OPERATION`

**Beispiele:**
```
# x86: mov eax, 5
5,eax,=

# x86: add eax, 3
3,eax,+=

# x86: sub eax, 1
1,eax,-=

# x86: push eax
4,esp,-=,eax,esp,=[4]

# x86: pop eax
esp,[4],eax,=,4,esp,+=

# x86: xor eax, eax
eax,eax,^=

# x86: mov [eax], ebx
ebx,eax,=[4]

# x86: mov eax, [ebx]
ebx,[4],eax,=

# x86: cmp eax, 5  (setzt Flags)
5,eax,==,$z,zf,:=,$s,sf,:=,$c,cf,:=

# x86: jz addr
zf,?{,addr,eip,=,}

# x86: call addr
4,esp,-=,$$,esp,=[4],addr,eip,=
```

#### 1.3.3 ESIL-Operatoren

| Operator | Beschreibung | Beispiel |
|----------|-------------|---------|
| `=`      | Zuweisung | `5,eax,=` |
| `+=`     | Addition + Zuweisung | `3,eax,+=` |
| `-=`     | Subtraktion + Zuweisung | `1,eax,-=` |
| `*=`     | Multiplikation + Zuweisung | `2,eax,*=` |
| `/=`     | Division + Zuweisung | `2,eax,/=` |
| `%=`     | Modulo + Zuweisung | `3,eax,%=` |
| `<<=`    | Links-Shift + Zuweisung | `4,eax,<<=` |
| `>>=`    | Rechts-Shift + Zuweisung | `2,eax,>>=` |
| `&=`     | AND + Zuweisung | `0xff,eax,&=` |
| `\|=`    | OR + Zuweisung | `0x01,eax,\|=` |
| `^=`     | XOR + Zuweisung | `eax,eax,^=` |
| `==`     | Vergleich | `5,eax,==` |
| `<`      | Kleiner als | `5,eax,<` |
| `<=`     | Kleiner gleich | `5,eax,<=` |
| `>`      | Groesser als | `5,eax,>` |
| `>=`     | Groesser gleich | `5,eax,>=` |
| `!`      | Logisches NOT | `eax,!` |
| `++`     | Inkrement | `eax,++=` |
| `--`     | Dekrement | `eax,--=` |
| `=[N]`   | N Bytes in Speicher schreiben | `eax,ebx,=[4]` |
| `[N]`    | N Bytes aus Speicher lesen | `eax,[4]` |
| `?{`     | If (bedingter Block) | `zf,?{,label,eip,=,}` |
| `}`      | End If | |
| `$$`     | Aktuelle Adresse | |
| `TRAP`   | Trap/Interrupt | |
| `$z`     | Zero-Flag Ergebnis | |
| `$s`     | Sign-Flag Ergebnis | |
| `$c`     | Carry-Flag Ergebnis | |
| `$o`     | Overflow-Flag Ergebnis | |
| `$p`     | Parity-Flag Ergebnis | |

#### 1.3.4 ESIL-Befehle in r2

| Befehl | Beschreibung |
|--------|-------------|
| `ae`   | ESIL-Ausdruck auswerten |
| `ae expr` | ESIL-Ausdruck ausfuehren |
| `aei`  | ESIL VM initialisieren |
| `aeim`  | ESIL-Speicher-Stack initialisieren |
| `aes`  | ESIL Step (eine Instruktion emulieren) |
| `aeso` | ESIL Step Over |
| `aesu addr` | ESIL Step Until addr |
| `aec`  | ESIL Continue (bis Breakpoint/Ende) |
| `aep`  | ESIL-Pin setzen (Breakpoint) |
| `aepc addr` | ESIL PC auf Adresse setzen |
| `aer`  | ESIL Register anzeigen |
| `aer reg=val` | ESIL Register setzen |
| `aets+` | ESIL Tracing starten |
| `aets-` | ESIL Tracing stoppen |
| `aef`  | ESIL: Funktion emulieren |
| `aek`  | ESIL Stack anzeigen |
| `aeip` | ESIL: PC auf Entry-Point setzen |

**Typischer Workflow:**
```bash
# 1. ESIL initialisieren
aei           # VM initialisieren
aeim          # Stack-Speicher anlegen

# 2. Zum Startpunkt navigieren
s main        # oder s entry0

# 3. Register pruefen
aer           # Alle Register anzeigen
aer eax       # Bestimmtes Register

# 4. Step-by-Step emulieren
aes           # Ein Step
aes           # Noch ein Step
aer           # Register pruefen

# 5. Bis zu bestimmter Adresse emulieren
aesu 0x08048100

# 6. ESIL-Expression manuell auswerten
ae 5,eax,=    # eax = 5
aer eax       # Ergebnis pruefen
```

#### 1.3.5 ESIL mit r2pipe

```python
import r2pipe

r2 = r2pipe.open("binary")
r2.cmd("aaa")

# ESIL initialisieren
r2.cmd("aei")
r2.cmd("aeim")

# Zum Entry Point
r2.cmd("s entry0")
r2.cmd("aeip")

# Emulation schrittweise
for i in range(100):
    r2.cmd("aes")
    eax = r2.cmd("aer eax").strip()
    eip = r2.cmd("aer eip").strip()
    print(f"Step {i}: EIP={eip}, EAX={eax}")

# ESIL-Ausdruck direkt auswerten
r2.cmd("ae 0x41414141,eax,=")
print(r2.cmd("aer eax"))

r2.quit()
```

---

### 1.4 Shellcode-Analyse

#### 1.4.1 Shellcode in r2 laden

```bash
# Aus Datei
r2 -a x86 -b 32 shellcode.bin

# Aus Hex-String
r2 -a x86 -b 32 -c 'wx 31c050682f2f7368682f62696e89e3505389e1b00bcd80; pd 20' malloc://1024

# Raw-Shellcode (kein Format)
r2 -n -a x86 -b 32 shellcode.bin     # -n = kein Binary-Format parsen

# 64-bit Shellcode
r2 -a x86 -b 64 shellcode.bin

# ARM Shellcode
r2 -a arm -b 32 shellcode.bin
r2 -a arm -b 64 shellcode.bin

# MIPS Shellcode
r2 -a mips -b 32 shellcode.bin
```

#### 1.4.2 Shellcode-Analyse-Workflow

```bash
# 1. Datei oeffnen und Analyse
r2 -a x86 -b 32 shellcode.bin
aaa

# 2. Disassembly anzeigen
pd 50              # Erste 50 Instruktionen
pd @@ fcn.*        # Alle erkannten Funktionen

# 3. Strings suchen
iz                  # Eingebettete Strings
/                   # Strings in allen Sections
/ /bin/sh           # Spezifischen String suchen

# 4. Syscalls identifizieren
/a int 0x80         # Linux x86 Syscalls
/a syscall          # Linux x86_64 Syscalls
/a svc              # ARM Syscalls

# 5. Pattern erkennen
e asm.emu=true      # ESIL-Emulation in Disassembly einblenden
e asm.emustr=true   # Emulierte Strings anzeigen

# 6. Hex-Dump
px 256              # Hex-Dump
pxw 64              # Word-View

# 7. Opcodes analysieren
ao @ 0x00           # Opcode-Details an Adresse 0
aoj 10              # Naechste 10 Opcodes als JSON
```

#### 1.4.3 Shellcode-Patterns erkennen

**Typische x86/x86_64 Shellcode-Muster:**

```bash
# XOR-Decoder erkennen
/x 31c9             # xor ecx, ecx (Counter loeschen)
/x 80340e           # xor byte [esi+ecx], reg (XOR-Loop)

# NOP-Sled erkennen
/x 90909090         # Klassischer NOP-Sled

# Egg-Hunter
/x 6681caff0f       # or dx, 0xfff (Egg-Hunter Pattern)

# GetPC (Position-Independent Code)
/a call              # CALL-Instruktionen suchen
/a jmp               # JMP-Instruktionen suchen
/x e800000000       # call $+5 (GetPC Pattern)

# Stack-basierte String-Konstruktion
/a push              # Push-Instruktionen
```

**Syscall-Referenz (Linux x86):**

| Syscall | Nr. | Register | Zweck |
|---------|-----|----------|-------|
| `exit`  | 1   | ebx=exitcode | Prozess beenden |
| `read`  | 3   | ebx=fd, ecx=buf, edx=len | Daten lesen |
| `write` | 4   | ebx=fd, ecx=buf, edx=len | Daten schreiben |
| `execve`| 11  | ebx=path, ecx=argv, edx=envp | Programm ausfuehren |
| `socketcall` | 102 | ebx=call#, ecx=args | Netzwerk |
| `mprotect` | 125 | ebx=addr, ecx=len, edx=prot | Speicher-Schutz |

#### 1.4.4 Shellcode-Emulation mit ESIL

```bash
# Shellcode emulieren
r2 -a x86 -b 32 malloc://4096
wx 31c050682f2f7368682f62696e89e3505389e1b00bcd80
aei
aeim 0xffffd000 0x2000 stack
aeip

# Schritt fuer Schritt
aes
aer          # Register pruefen
aes
aer
# ...wiederholen bis Syscall

# Oder bis zu bestimmtem Punkt
aesu 0x00000016   # Bis zum int 0x80
aer                # Jetzt Register = Syscall-Argumente
```

#### 1.4.5 Shellcode-Analyse mit r2pipe (Python)

```python
import r2pipe
import json

def analyze_shellcode(shellcode_hex: str, arch: str = "x86", bits: int = 32):
    """Analysiert Shellcode mit radare2."""
    r2 = r2pipe.open(f"malloc://4096", flags=["-a", arch, "-b", str(bits)])

    # Shellcode laden
    r2.cmd(f"wx {shellcode_hex}")
    r2.cmd("aaa")

    result = {
        "disassembly": [],
        "strings": [],
        "syscalls": [],
        "xrefs": [],
        "functions": []
    }

    # Disassembly
    disasm = r2.cmdj("pdj 100") or []
    for insn in disasm:
        result["disassembly"].append({
            "offset": insn.get("offset"),
            "opcode": insn.get("opcode", ""),
            "bytes": insn.get("bytes", ""),
            "type": insn.get("type", ""),
            "esil": insn.get("esil", "")
        })
        # Syscalls erkennen
        opcode = insn.get("opcode", "")
        if "int 0x80" in opcode or "syscall" in opcode or "svc" in opcode:
            result["syscalls"].append(insn)

    # Strings
    strings = r2.cmdj("izj") or []
    result["strings"] = strings

    # Funktionen
    functions = r2.cmdj("aflj") or []
    result["functions"] = functions

    r2.quit()
    return result

# Nutzung
shellcode = "31c050682f2f7368682f62696e89e3505389e1b00bcd80"
analysis = analyze_shellcode(shellcode)

print("=== Disassembly ===")
for insn in analysis["disassembly"]:
    if insn["opcode"]:
        print(f"  0x{insn['offset']:08x}: {insn['opcode']}")

print(f"\n=== Syscalls found: {len(analysis['syscalls'])} ===")
for sc in analysis["syscalls"]:
    print(f"  0x{sc['offset']:08x}: {sc['opcode']}")
```

---

## 2. MCP (Model Context Protocol)

### 2.1 Protokoll-Spezifikation

#### 2.1.1 Ueberblick

Das Model Context Protocol (MCP) ist ein offenes Protokoll, das von Anthropic entwickelt wurde, um eine standardisierte Kommunikation zwischen KI-Modellen (LLMs) und externen Tools/Datenquellen zu ermoeglichen. Es folgt einer Client-Server-Architektur.

**Kernkonzepte:**
- **Host**: Die Anwendung, die einen LLM nutzt (z.B. Claude Desktop, IDE)
- **Client**: Wird vom Host erstellt, verbindet sich mit einem Server (1:1-Beziehung)
- **Server**: Stellt Tools, Resources und Prompts bereit

**Architektur:**
```
Host Application (z.B. Claude Desktop)
  |
  +-- MCP Client 1 <---> MCP Server 1 (z.B. Dateisystem)
  |
  +-- MCP Client 2 <---> MCP Server 2 (z.B. Datenbank)
  |
  +-- MCP Client 3 <---> MCP Server 3 (z.B. radare2)
```

#### 2.1.2 Protokoll-Basis: JSON-RPC 2.0

MCP basiert auf JSON-RPC 2.0. Es gibt drei Nachrichtentypen:

**Request:**
```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
        "name": "analyze_binary",
        "arguments": {
            "path": "/path/to/binary"
        }
    }
}
```

**Response:**
```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "result": {
        "content": [
            {
                "type": "text",
                "text": "Analysis complete: 42 functions found"
            }
        ]
    }
}
```

**Notification (kein `id`, keine Antwort erwartet):**
```json
{
    "jsonrpc": "2.0",
    "method": "notifications/progress",
    "params": {
        "progressToken": "abc123",
        "progress": 50,
        "total": 100
    }
}
```

**Error Response:**
```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "error": {
        "code": -32600,
        "message": "Invalid request",
        "data": {
            "details": "Missing required parameter 'path'"
        }
    }
}
```

#### 2.1.3 Lifecycle

1. **Initialization**: Client sendet `initialize` Request mit seinen Capabilities
2. **Server Response**: Server antwortet mit seinen Capabilities
3. **Initialized Notification**: Client sendet `notifications/initialized`
4. **Operation**: Normale Tool-Aufrufe, Resource-Zugriffe etc.
5. **Shutdown**: Client sendet `close` oder trennt die Verbindung

**Initialize Request:**
```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {
            "roots": { "listChanged": true },
            "sampling": {}
        },
        "clientInfo": {
            "name": "MyApp",
            "version": "1.0.0"
        }
    }
}
```

**Initialize Response:**
```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "result": {
        "protocolVersion": "2024-11-05",
        "capabilities": {
            "tools": { "listChanged": true },
            "resources": { "subscribe": true, "listChanged": true },
            "prompts": { "listChanged": true },
            "logging": {}
        },
        "serverInfo": {
            "name": "radare2-mcp",
            "version": "0.1.0"
        }
    }
}
```

#### 2.1.4 Transports

**stdio Transport:**
- Server wird als Child-Process gestartet
- Kommunikation ueber stdin/stdout
- Jede JSON-RPC-Nachricht wird als einzelne Zeile gesendet (newline-delimited)
- stderr wird fuer Logging verwendet
- Empfohlener Standard-Transport

```
Client (Host) ---stdin--->  MCP Server Process
Client (Host) <--stdout---  MCP Server Process
                 stderr --> Logs
```

**Streamable HTTP Transport (aktuell, ersetzt SSE):**
- Server lauscht auf einem HTTP-Endpoint
- Client sendet POST-Requests
- Server kann Server-Sent Events (SSE) fuer Streaming nutzen
- Geeignet fuer Remote-Server
- Endpoint: typischerweise `/mcp`

```
POST /mcp HTTP/1.1
Content-Type: application/json

{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}
```

**SSE Transport (aelter / deprecated):**
- Server bietet SSE-Endpoint fuer Server-zu-Client-Nachrichten
- Client sendet ueber separaten POST-Endpoint
- Wird durch Streamable HTTP ersetzt

#### 2.1.5 Capabilities

Server und Client deklarieren ihre Faehigkeiten beim Handshake:

**Server Capabilities:**
| Capability | Beschreibung |
|-----------|-------------|
| `tools`   | Server bietet Tools an |
| `tools.listChanged` | Server kann Tool-Liste aendern |
| `resources` | Server bietet Resources an |
| `resources.subscribe` | Clients koennen Resources abonnieren |
| `resources.listChanged` | Resource-Liste kann sich aendern |
| `prompts` | Server bietet Prompt-Templates an |
| `prompts.listChanged` | Prompt-Liste kann sich aendern |
| `logging` | Server unterstuetzt Logging |

**Client Capabilities:**
| Capability | Beschreibung |
|-----------|-------------|
| `roots`   | Client stellt Root-URIs bereit |
| `roots.listChanged` | Client kann Root-Liste aendern |
| `sampling` | Client unterstuetzt LLM-Sampling |

---

### 2.2 TypeScript SDK

#### 2.2.1 Installation

```bash
npm install @modelcontextprotocol/sdk
```

#### 2.2.2 Grundstruktur eines MCP Servers

```typescript
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

// Server erstellen
const server = new McpServer({
    name: "my-mcp-server",
    version: "1.0.0",
    capabilities: {
        tools: {},
        resources: {},
    }
});

// Tools registrieren (siehe 2.3)
// Resources registrieren (siehe 2.4)

// Transport starten
const transport = new StdioServerTransport();
await server.connect(transport);
```

#### 2.2.3 Low-Level Server (mit McpServer)

Fuer mehr Kontrolle kann man den Low-Level-Server verwenden:

```typescript
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
    CallToolRequestSchema,
    ListToolsRequestSchema,
    ListResourcesRequestSchema,
    ReadResourceRequestSchema,
    ErrorCode,
    McpError,
} from "@modelcontextprotocol/sdk/types.js";

const server = new Server(
    {
        name: "my-server",
        version: "1.0.0",
    },
    {
        capabilities: {
            tools: {},
            resources: {},
        },
    }
);

// Tool-Liste Handler
server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
        tools: [
            {
                name: "analyze_function",
                description: "Analyze a function in a binary",
                inputSchema: {
                    type: "object",
                    properties: {
                        name: {
                            type: "string",
                            description: "Function name to analyze"
                        }
                    },
                    required: ["name"]
                }
            }
        ]
    };
});

// Tool-Aufruf Handler
server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    switch (name) {
        case "analyze_function":
            const result = await analyzeFunction(args.name);
            return {
                content: [
                    {
                        type: "text",
                        text: result
                    }
                ]
            };
        default:
            throw new McpError(
                ErrorCode.MethodNotFound,
                `Unknown tool: ${name}`
            );
    }
});

// Starten
const transport = new StdioServerTransport();
await server.connect(transport);
```

#### 2.2.4 High-Level Server (McpServer mit Zod)

```typescript
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({
    name: "radare2-mcp",
    version: "1.0.0",
});

// Tool mit Zod-Schema definieren
server.tool(
    "disassemble",
    "Disassemble instructions at a given address",
    {
        address: z.string().describe("Address to disassemble (hex format)"),
        count: z.number().optional().default(10).describe("Number of instructions"),
    },
    async ({ address, count }) => {
        // Tool-Logik hier
        const result = `Disassembled ${count} instructions at ${address}`;
        return {
            content: [{ type: "text", text: result }],
        };
    }
);

// Resource definieren
server.resource(
    "binary-info",
    "binary://info",
    { mimeType: "application/json" },
    async (uri) => {
        return {
            contents: [{
                uri: uri.href,
                mimeType: "application/json",
                text: JSON.stringify({ arch: "x86", bits: 64 }),
            }],
        };
    }
);

// Starten
const transport = new StdioServerTransport();
await server.connect(transport);
```

#### 2.2.5 HTTP/SSE Transport

```typescript
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import express from "express";

const app = express();
const server = new McpServer({ name: "my-server", version: "1.0.0" });

// Tools registrieren...

// SSE Endpoint
app.get("/sse", async (req, res) => {
    const transport = new SSEServerTransport("/messages", res);
    await server.connect(transport);
});

// Message Endpoint
app.post("/messages", async (req, res) => {
    // Handle incoming messages
});

app.listen(3000);
```

**Streamable HTTP Transport:**
```typescript
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => crypto.randomUUID(),
});
await server.connect(transport);

// In Express:
app.post("/mcp", async (req, res) => {
    await transport.handleRequest(req, res);
});
```

#### 2.2.6 MCP Client (TypeScript)

```typescript
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const transport = new StdioClientTransport({
    command: "node",
    args: ["path/to/server.js"],
});

const client = new Client({
    name: "my-client",
    version: "1.0.0",
});

await client.connect(transport);

// Tools auflisten
const tools = await client.listTools();
console.log("Available tools:", tools);

// Tool aufrufen
const result = await client.callTool({
    name: "disassemble",
    arguments: {
        address: "0x08048000",
        count: 10
    }
});
console.log("Result:", result);

// Resources auflisten
const resources = await client.listResources();

// Resource lesen
const resource = await client.readResource({
    uri: "binary://info"
});

await client.close();
```

---

### 2.3 Tool-Definition

#### 2.3.1 Tool-Schema

Tools sind das Kernkonzept fuer Aktionen, die ein LLM ausfuehren kann. Jedes Tool hat:
- **name**: Eindeutiger Bezeichner
- **description**: Menschenlesbare Beschreibung (wird dem LLM angezeigt)
- **inputSchema**: JSON Schema fuer die Eingabeparameter

**JSON Schema Format:**
```json
{
    "name": "analyze_binary",
    "description": "Perform comprehensive analysis of a binary file including function detection, string extraction, and import/export analysis",
    "inputSchema": {
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Path to the binary file to analyze"
            },
            "depth": {
                "type": "string",
                "enum": ["basic", "standard", "deep"],
                "description": "Analysis depth: basic (aa), standard (aaa), deep (aaaa)",
                "default": "standard"
            },
            "arch": {
                "type": "string",
                "description": "Override architecture (e.g., x86, arm, mips)",
                "default": null
            },
            "bits": {
                "type": "number",
                "enum": [16, 32, 64],
                "description": "Override bit width",
                "default": null
            }
        },
        "required": ["path"]
    }
}
```

#### 2.3.2 Tool-Antworten (Content Types)

Tools geben Inhalte als Array von Content-Bloecken zurueck:

**Text Content:**
```json
{
    "content": [
        {
            "type": "text",
            "text": "Found 42 functions in binary"
        }
    ]
}
```

**Image Content:**
```json
{
    "content": [
        {
            "type": "image",
            "data": "base64-encoded-image-data",
            "mimeType": "image/png"
        }
    ]
}
```

**Embedded Resource:**
```json
{
    "content": [
        {
            "type": "resource",
            "resource": {
                "uri": "file:///path/to/output.json",
                "mimeType": "application/json",
                "text": "{\"functions\": 42}"
            }
        }
    ]
}
```

**Fehler in Tool-Antworten:**
```json
{
    "content": [
        {
            "type": "text",
            "text": "Error: Binary file not found at /path/to/binary"
        }
    ],
    "isError": true
}
```

#### 2.3.3 Tool-Implementierung mit Zod (High-Level)

```typescript
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "r2-mcp", version: "1.0.0" });

// Einfaches Tool
server.tool(
    "list_functions",
    "List all functions found in the currently loaded binary",
    {},  // Keine Parameter
    async () => {
        const functions = await getFunctions();
        return {
            content: [{
                type: "text",
                text: JSON.stringify(functions, null, 2)
            }]
        };
    }
);

// Tool mit Parametern
server.tool(
    "disassemble_function",
    "Disassemble a specific function by name and return its assembly code",
    {
        name: z.string().describe("Name of the function to disassemble"),
        format: z.enum(["asm", "esil", "pseudo"]).optional()
            .describe("Output format: asm (assembly), esil, or pseudo (C-like)"),
    },
    async ({ name, format = "asm" }) => {
        try {
            const disasm = await disassembleFunction(name, format);
            return {
                content: [{ type: "text", text: disasm }]
            };
        } catch (error) {
            return {
                content: [{
                    type: "text",
                    text: `Error disassembling ${name}: ${error.message}`
                }],
                isError: true
            };
        }
    }
);

// Tool mit komplexen Parametern
server.tool(
    "search_bytes",
    "Search for a byte pattern in the binary",
    {
        pattern: z.string().describe("Hex byte pattern to search for (e.g., '31c050')"),
        section: z.string().optional().describe("Limit search to specific section"),
        maxResults: z.number().optional().default(20)
            .describe("Maximum number of results to return"),
    },
    async ({ pattern, section, maxResults }) => {
        // Implementation
        return {
            content: [{ type: "text", text: "Results..." }]
        };
    }
);
```

#### 2.3.4 Tool-Annotationen

Tools koennen Annotationen haben, die dem Client Hinweise geben:

```typescript
server.tool(
    "write_bytes",
    "Write bytes to the binary (destructive operation)",
    {
        address: z.string(),
        bytes: z.string(),
    },
    async ({ address, bytes }) => { /* ... */ },
    {
        // Annotationen
        destructiveHint: true,     // Tool veraendert Daten
        readOnlyHint: false,       // Tool ist NICHT nur lesend
        idempotentHint: true,      // Mehrfaches Aufrufen hat gleichen Effekt
        openWorldHint: false,      // Tool interagiert nicht mit der Aussenwelt
    }
);
```

---

### 2.4 Resource-Definition

#### 2.4.1 Was sind Resources?

Resources repraesentieren Datenquellen, die ein LLM lesen kann. Sie sind aehnlich zu REST-Endpunkten:
- Identifiziert durch URIs
- Koennen Text oder binaere Daten enthalten
- Koennen statisch oder dynamisch sein
- Unterstuetzen Subscriptions fuer Live-Updates

#### 2.4.2 Resource-Typen

**Statische Resource (feste URI):**
```typescript
server.resource(
    "binary-info",
    "binary://info",
    {
        description: "Information about the currently loaded binary",
        mimeType: "application/json"
    },
    async (uri) => ({
        contents: [{
            uri: uri.href,
            mimeType: "application/json",
            text: JSON.stringify({
                filename: "example.bin",
                arch: "x86_64",
                format: "ELF",
                size: 12345
            })
        }]
    })
);
```

**Resource Template (dynamische URI):**
```typescript
server.resource(
    "function-disasm",
    new ResourceTemplate("function://{name}/disasm", { list: undefined }),
    {
        description: "Disassembly of a specific function",
        mimeType: "text/plain"
    },
    async (uri, { name }) => ({
        contents: [{
            uri: uri.href,
            mimeType: "text/plain",
            text: await getDisassembly(name)
        }]
    })
);
```

#### 2.4.3 Resource-Listing (Low-Level)

```typescript
server.setRequestHandler(ListResourcesRequestSchema, async () => {
    return {
        resources: [
            {
                uri: "binary://info",
                name: "Binary Information",
                description: "Metadata about the loaded binary",
                mimeType: "application/json"
            },
            {
                uri: "binary://strings",
                name: "Strings",
                description: "Extracted strings from the binary",
                mimeType: "application/json"
            },
            {
                uri: "binary://imports",
                name: "Imports",
                description: "Imported symbols",
                mimeType: "application/json"
            }
        ]
    };
});

server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
    const { uri } = request.params;

    switch (uri) {
        case "binary://info":
            return {
                contents: [{
                    uri,
                    mimeType: "application/json",
                    text: JSON.stringify(await getBinaryInfo())
                }]
            };
        case "binary://strings":
            return {
                contents: [{
                    uri,
                    mimeType: "application/json",
                    text: JSON.stringify(await getStrings())
                }]
            };
        default:
            throw new McpError(
                ErrorCode.InvalidRequest,
                `Unknown resource: ${uri}`
            );
    }
});
```

#### 2.4.4 Resource Templates (Low-Level)

```typescript
server.setRequestHandler(ListResourceTemplatesRequestSchema, async () => {
    return {
        resourceTemplates: [
            {
                uriTemplate: "function://{name}/disasm",
                name: "Function Disassembly",
                description: "Get disassembly for a specific function",
                mimeType: "text/plain"
            },
            {
                uriTemplate: "address://{addr}/hex/{size}",
                name: "Hex Dump",
                description: "Get hex dump at address with given size",
                mimeType: "text/plain"
            }
        ]
    };
});
```

#### 2.4.5 Resource Subscriptions

```typescript
// Server signalisiert Resource-Aenderung
server.notification({
    method: "notifications/resources/updated",
    params: {
        uri: "binary://info"
    }
});

// Server signalisiert neue Resource-Liste
server.notification({
    method: "notifications/resources/list_changed"
});
```

---

### 2.5 Best Practices

#### 2.5.1 Fehlerbehandlung

```typescript
import { McpError, ErrorCode } from "@modelcontextprotocol/sdk/types.js";

// Standard JSON-RPC Error Codes
// -32700 Parse Error
// -32600 Invalid Request
// -32601 Method Not Found
// -32602 Invalid Params
// -32603 Internal Error

// In Tool-Handlern:
server.tool("my_tool", "description", { param: z.string() },
    async ({ param }) => {
        try {
            const result = await doSomething(param);
            return {
                content: [{ type: "text", text: result }]
            };
        } catch (error) {
            // Option 1: Fehler als Tool-Ergebnis (LLM sieht den Fehler)
            if (error instanceof NotFoundError) {
                return {
                    content: [{
                        type: "text",
                        text: `Not found: ${param}. Available options: ${await listOptions()}`
                    }],
                    isError: true
                };
            }

            // Option 2: MCP-Fehler werfen (Protokollebene)
            throw new McpError(
                ErrorCode.InternalError,
                `Failed to process: ${error.message}`
            );
        }
    }
);
```

**Fehler-Hierarchie:**
- **Tool-Fehler** (`isError: true`): Das LLM sieht den Fehler und kann darauf reagieren (z.B. andere Parameter versuchen)
- **MCP-Fehler** (`McpError`): Protokoll-Level-Fehler, fuer schwerwiegende Probleme

#### 2.5.2 Logging

```typescript
// Server kann Log-Nachrichten senden
server.server.sendLoggingMessage({
    level: "info",
    logger: "radare2",
    data: "Binary loaded successfully"
});

server.server.sendLoggingMessage({
    level: "error",
    logger: "radare2",
    data: "Failed to analyze: corrupted binary"
});

// Log-Levels: "debug", "info", "notice", "warning", "error", "critical", "alert", "emergency"
```

Fuer stdio Transport: stderr fuer Logging verwenden:
```typescript
console.error("[INFO] Server started");  // Geht nach stderr
// NICHT console.log verwenden - das wuerde das JSON-RPC-Protokoll stoeren!
```

#### 2.5.3 Progress Reporting

```typescript
server.tool("analyze_binary", "Analyze binary", { path: z.string() },
    async ({ path }, { meta }) => {
        const progressToken = meta?.progressToken;

        // Progress melden (wenn Client es unterstuetzt)
        if (progressToken) {
            server.server.sendProgress(progressToken, 0, 100);
        }

        await step1();
        if (progressToken) server.server.sendProgress(progressToken, 33, 100);

        await step2();
        if (progressToken) server.server.sendProgress(progressToken, 66, 100);

        await step3();
        if (progressToken) server.server.sendProgress(progressToken, 100, 100);

        return { content: [{ type: "text", text: "Done" }] };
    }
);
```

#### 2.5.4 Testing

```typescript
// Unit-Test mit in-memory Transport
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

describe("MCP Server", () => {
    let server: Server;
    let client: Client;

    beforeEach(async () => {
        server = createMyServer();
        client = new Client({ name: "test", version: "1.0.0" });

        const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

        await Promise.all([
            server.connect(serverTransport),
            client.connect(clientTransport)
        ]);
    });

    afterEach(async () => {
        await client.close();
        await server.close();
    });

    it("should list tools", async () => {
        const result = await client.listTools();
        expect(result.tools).toHaveLength(5);
        expect(result.tools[0].name).toBe("analyze_binary");
    });

    it("should call tool successfully", async () => {
        const result = await client.callTool({
            name: "analyze_binary",
            arguments: { path: "/test/binary" }
        });
        expect(result.content[0].type).toBe("text");
        expect(result.isError).toBeFalsy();
    });

    it("should handle errors gracefully", async () => {
        const result = await client.callTool({
            name: "analyze_binary",
            arguments: { path: "/nonexistent" }
        });
        expect(result.isError).toBe(true);
    });
});
```

#### 2.5.5 Claude Desktop Konfiguration

MCP Server werden in `claude_desktop_config.json` konfiguriert:

```json
{
    "mcpServers": {
        "radare2": {
            "command": "node",
            "args": ["C:/path/to/radare2-mcp/dist/index.js"],
            "env": {
                "R2_PATH": "C:/radare2/bin/radare2.exe"
            }
        },
        "filesystem": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", "C:/Users/user/projects"]
        }
    }
}
```

Speicherort:
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`

#### 2.5.6 Design-Prinzipien

1. **Beschreibende Tool-Namen und Descriptions**: Das LLM waehlt Tools basierend auf Namen und Beschreibungen aus.
2. **Granulare Tools**: Lieber viele kleine, fokussierte Tools als wenige grosse.
3. **Idempotenz**: Tools sollten bei mehrfachem Aufruf das gleiche Ergebnis liefern (wenn moeglich).
4. **Fehlertoleranz**: Tools sollten hilfreiche Fehlermeldungen zurueckgeben, nicht einfach abstuerzen.
5. **Minimale Seiteneffekte**: Read-Only-Tools bevorzugen, destruktive Operationen klar kennzeichnen.
6. **Validierung**: Eingabeparameter mit JSON Schema / Zod validieren.
7. **Streaming**: Fuer grosse Ausgaben Content in sinnvolle Teile aufteilen.

#### 2.5.7 Sicherheit

- **Input-Validierung**: Alle Eingaben validieren (Path-Traversal, Injection etc.)
- **Sandboxing**: Tools sollten nur auf erlaubte Ressourcen zugreifen
- **Timeouts**: Langlaeufer-Operationen mit Timeouts absichern
- **Rate Limiting**: Bei HTTP-Transport Rate-Limiting einsetzen
- **Keine Secrets in Responses**: Sensible Daten nicht an das LLM zurueckgeben

---

## 3. Code-Beispiele

### 3.1 r2pipe Beispiele

#### 3.1.1 Vollstaendige Binary-Analyse (Python)

```python
import r2pipe
import json
import sys

def full_analysis(binary_path: str) -> dict:
    """Fuehrt eine vollstaendige Analyse einer Binary durch."""
    r2 = r2pipe.open(binary_path)
    r2.cmd("aaa")  # Analyse

    report = {}

    # 1. Datei-Info
    info = r2.cmdj("ij")
    report["info"] = {
        "format": info.get("core", {}).get("format", "unknown"),
        "arch": info.get("bin", {}).get("arch", "unknown"),
        "bits": info.get("bin", {}).get("bits", 0),
        "os": info.get("bin", {}).get("os", "unknown"),
        "endian": info.get("bin", {}).get("endian", "unknown"),
        "canary": info.get("bin", {}).get("canary", False),
        "nx": info.get("bin", {}).get("nx", False),
        "pic": info.get("bin", {}).get("pic", False),
        "stripped": info.get("bin", {}).get("stripped", False),
    }

    # 2. Funktionen
    functions = r2.cmdj("aflj") or []
    report["functions"] = [{
        "name": f["name"],
        "offset": f["offset"],
        "size": f["size"],
        "nbbs": f.get("nbbs", 0),   # Anzahl Basic Blocks
        "cc": f.get("cc", 0),       # Cyclomatic Complexity
        "calls": f.get("outdegree", 0),
        "called_by": f.get("indegree", 0),
    } for f in functions]

    # 3. Strings
    strings = r2.cmdj("izj") or []
    report["strings"] = [{
        "value": s.get("string", ""),
        "address": s.get("vaddr", 0),
        "type": s.get("type", ""),
        "section": s.get("section", ""),
        "length": s.get("length", 0),
    } for s in strings]

    # 4. Imports
    imports = r2.cmdj("iij") or []
    report["imports"] = [{
        "name": imp.get("name", ""),
        "type": imp.get("type", ""),
        "bind": imp.get("bind", ""),
        "lib": imp.get("lib", ""),
    } for imp in imports]

    # 5. Exports
    exports = r2.cmdj("iEj") or []
    report["exports"] = [{
        "name": exp.get("name", ""),
        "address": exp.get("vaddr", 0),
        "type": exp.get("type", ""),
    } for exp in exports]

    # 6. Sections
    sections = r2.cmdj("iSj") or []
    report["sections"] = [{
        "name": sec.get("name", ""),
        "size": sec.get("size", 0),
        "vaddr": sec.get("vaddr", 0),
        "perm": sec.get("perm", ""),
    } for sec in sections]

    # 7. Entrypoints
    entries = r2.cmdj("iej") or []
    report["entrypoints"] = entries

    r2.quit()
    return report

if __name__ == "__main__":
    result = full_analysis(sys.argv[1])
    print(json.dumps(result, indent=2))
```

#### 3.1.2 Vulnerability-Pattern-Scanner (Python)

```python
import r2pipe
import re

def scan_vulnerabilities(binary_path: str) -> list:
    """Scannt eine Binary nach haeufigen Vulnerability-Patterns."""
    r2 = r2pipe.open(binary_path)
    r2.cmd("aaa")

    findings = []

    # 1. Gefaehrliche Funktionen suchen
    dangerous_functions = [
        "strcpy", "strcat", "sprintf", "gets",
        "scanf", "vsprintf", "realpath",
        "getwd", "streadd", "strecpy",
    ]

    imports = r2.cmdj("iij") or []
    for imp in imports:
        name = imp.get("name", "")
        for dangerous in dangerous_functions:
            if dangerous in name.lower():
                # Xrefs finden
                xrefs = r2.cmdj(f"axtj @@ sym.imp.{name}") or []
                findings.append({
                    "type": "dangerous_function",
                    "function": name,
                    "severity": "high",
                    "xrefs": len(xrefs) if isinstance(xrefs, list) else 0,
                    "description": f"Use of dangerous function {name}"
                })

    # 2. Format-String Vulnerabilities
    format_funcs = ["printf", "fprintf", "sprintf", "snprintf", "syslog"]
    for func_name in format_funcs:
        result = r2.cmd(f"axt @ sym.imp.{func_name}")
        if result.strip():
            findings.append({
                "type": "potential_format_string",
                "function": func_name,
                "severity": "medium",
                "description": f"Calls to {func_name} - check for format string vulnerabilities"
            })

    # 3. Sicherheits-Features pruefen
    info = r2.cmdj("ij") or {}
    bin_info = info.get("bin", {})

    if not bin_info.get("canary", False):
        findings.append({
            "type": "missing_protection",
            "severity": "medium",
            "description": "Stack canary is not enabled"
        })

    if not bin_info.get("nx", False):
        findings.append({
            "type": "missing_protection",
            "severity": "high",
            "description": "NX (No-Execute) is not enabled - stack is executable"
        })

    if not bin_info.get("pic", False):
        findings.append({
            "type": "missing_protection",
            "severity": "low",
            "description": "PIC/PIE is not enabled - no ASLR for main binary"
        })

    r2.quit()
    return findings
```

#### 3.1.3 Shellcode-Extractor und -Analysator (Python)

```python
import r2pipe
import json

class ShellcodeAnalyzer:
    def __init__(self, shellcode_hex: str, arch: str = "x86", bits: int = 32):
        self.r2 = r2pipe.open("malloc://4096", flags=["-a", arch, "-b", str(bits)])
        self.r2.cmd(f"wx {shellcode_hex}")
        self.r2.cmd("aaa")
        self.arch = arch
        self.bits = bits

    def get_disassembly(self, count: int = 50) -> list:
        """Gibt die Disassembly als Liste von Instruktionen zurueck."""
        return self.r2.cmdj(f"pdj {count}") or []

    def get_strings(self) -> list:
        """Findet eingebettete Strings."""
        strings = []
        # In Shellcode sind Strings oft nach Calls versteckt
        result = self.r2.cmd("/ /bin")
        if "/bin" in result:
            strings.append("/bin/sh or similar")

        # Manuelle String-Suche
        izz = self.r2.cmdj("izzj") or []
        for s in izz:
            if len(s.get("string", "")) > 3:
                strings.append(s)

        return strings

    def detect_syscalls(self) -> list:
        """Erkennt Syscalls im Shellcode."""
        syscalls = []
        disasm = self.get_disassembly(200)

        for i, insn in enumerate(disasm):
            opcode = insn.get("opcode", "")

            if "int 0x80" in opcode:
                # Linux x86 syscall - Register pruefen via ESIL
                syscalls.append({
                    "type": "int 0x80",
                    "address": insn["offset"],
                    "arch": "x86_32"
                })
            elif "syscall" in opcode and "x86" in self.arch:
                syscalls.append({
                    "type": "syscall",
                    "address": insn["offset"],
                    "arch": "x86_64"
                })
            elif "svc" in opcode:
                syscalls.append({
                    "type": "svc",
                    "address": insn["offset"],
                    "arch": "arm"
                })

        return syscalls

    def detect_techniques(self) -> list:
        """Erkennt gaengige Shellcode-Techniken."""
        techniques = []
        disasm = self.get_disassembly(200)
        opcodes = [i.get("opcode", "") for i in disasm]
        bytecodes = [i.get("bytes", "") for i in disasm]

        # XOR-Decoder
        for op in opcodes:
            if "xor" in op and "byte" in op:
                techniques.append("XOR decoder (single-byte)")
                break

        # GetPC via CALL
        for b in bytecodes:
            if b.startswith("e800000000"):
                techniques.append("GetPC via CALL $+5")
                break

        # Stack-based string construction
        push_count = sum(1 for op in opcodes if op.startswith("push"))
        if push_count > 3:
            techniques.append(f"Stack-based string construction ({push_count} pushes)")

        # NOP sled
        nop_run = 0
        max_nop = 0
        for op in opcodes:
            if op == "nop":
                nop_run += 1
                max_nop = max(max_nop, nop_run)
            else:
                nop_run = 0
        if max_nop > 2:
            techniques.append(f"NOP sled detected ({max_nop} NOPs)")

        # Self-modifying code
        for op in opcodes:
            if "mov byte" in op or "mov word" in op:
                if any(reg in op for reg in ["[e", "[r"]):
                    techniques.append("Potential self-modifying code")
                    break

        return techniques

    def emulate(self, steps: int = 100) -> dict:
        """Emuliert den Shellcode und gibt den Endzustand zurueck."""
        self.r2.cmd("aei")
        self.r2.cmd("aeim 0xffffd000 0x2000 stack")
        self.r2.cmd("aeip")

        trace = []
        for i in range(steps):
            pc = self.r2.cmd("aer PC").strip()
            opcode_info = self.r2.cmdj(f"aoj 1 @ {pc}")
            if not opcode_info:
                break

            current_op = opcode_info[0].get("opcode", "invalid")
            if current_op == "invalid" or "int" in current_op:
                trace.append({"step": i, "pc": pc, "opcode": current_op, "note": "STOP"})
                break

            trace.append({"step": i, "pc": pc, "opcode": current_op})
            self.r2.cmd("aes")

        # Endregister
        registers = {}
        reg_output = self.r2.cmd("aer")
        for line in reg_output.strip().split("\n"):
            if "=" in line:
                parts = line.split("=")
                if len(parts) == 2:
                    registers[parts[0].strip()] = parts[1].strip()

        return {
            "trace_length": len(trace),
            "last_steps": trace[-5:] if len(trace) > 5 else trace,
            "registers": registers
        }

    def full_report(self) -> dict:
        """Erstellt einen vollstaendigen Analyse-Bericht."""
        return {
            "disassembly": self.get_disassembly(),
            "syscalls": self.detect_syscalls(),
            "techniques": self.detect_techniques(),
            "strings": self.get_strings(),
        }

    def close(self):
        self.r2.quit()

# Nutzung:
if __name__ == "__main__":
    # Linux x86 execve("/bin/sh") Shellcode
    shellcode = "31c050682f2f7368682f62696e89e3505389e1b00bcd80"

    analyzer = ShellcodeAnalyzer(shellcode, arch="x86", bits=32)
    report = analyzer.full_report()

    print("=== Shellcode Analysis Report ===\n")

    print("Disassembly:")
    for insn in report["disassembly"]:
        if insn.get("opcode"):
            print(f"  0x{insn['offset']:08x}: {insn['opcode']}")

    print(f"\nSyscalls: {len(report['syscalls'])}")
    for sc in report["syscalls"]:
        print(f"  {sc['type']} at 0x{sc['address']:08x}")

    print(f"\nTechniques: {len(report['techniques'])}")
    for tech in report["techniques"]:
        print(f"  - {tech}")

    analyzer.close()
```

#### 3.1.4 Cross-Reference Analyse (Python)

```python
import r2pipe

def xref_analysis(binary_path: str, target_func: str):
    """Analysiert Cross-References zu einer Funktion."""
    r2 = r2pipe.open(binary_path)
    r2.cmd("aaa")

    # Funktion finden
    functions = r2.cmdj("aflj") or []
    target = None
    for f in functions:
        if target_func in f["name"]:
            target = f
            break

    if not target:
        print(f"Function {target_func} not found")
        r2.quit()
        return

    addr = target["offset"]
    print(f"Analyzing xrefs for {target['name']} @ 0x{addr:x}")

    # Wer ruft diese Funktion auf?
    xrefs_to = r2.cmdj(f"axtj @ {addr}") or []
    print(f"\nCalled by ({len(xrefs_to)} references):")
    for xref in xrefs_to:
        caller = xref.get("fcn_name", "unknown")
        from_addr = xref.get("from", 0)
        print(f"  {caller} @ 0x{from_addr:x} (type: {xref.get('type', '?')})")

    # Was ruft diese Funktion auf?
    r2.cmd(f"s {addr}")
    xrefs_from = r2.cmdj(f"axfj") or []
    print(f"\nCalls to ({len(xrefs_from)} references):")
    for xref in xrefs_from:
        target_name = xref.get("name", "unknown")
        to_addr = xref.get("to", 0)
        print(f"  {target_name} @ 0x{to_addr:x} (type: {xref.get('type', '?')})")

    r2.quit()
```

---

### 3.2 MCP Server Beispiele

#### 3.2.1 Minimaler MCP Server (TypeScript)

```typescript
// minimal-server.ts
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({
    name: "minimal-example",
    version: "1.0.0",
});

// Ein einfaches Tool
server.tool(
    "greet",
    "Greet a user by name",
    {
        name: z.string().describe("Name of the person to greet"),
    },
    async ({ name }) => ({
        content: [{ type: "text", text: `Hello, ${name}!` }],
    })
);

// Server starten
async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("Minimal MCP server running on stdio");
}

main().catch(console.error);
```

#### 3.2.2 Radare2 MCP Server Struktur (TypeScript)

```typescript
// radare2-mcp-server.ts
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { spawn, ChildProcess } from "child_process";

// r2pipe-Wrapper Klasse
class R2Session {
    private process: ChildProcess | null = null;
    private buffer: string = "";

    async open(path: string, flags: string[] = []): Promise<void> {
        return new Promise((resolve, reject) => {
            this.process = spawn("r2", ["-q0", ...flags, path]);

            this.process.stdout?.once("data", () => {
                resolve();
            });

            this.process.on("error", reject);
        });
    }

    async cmd(command: string): Promise<string> {
        return new Promise((resolve, reject) => {
            if (!this.process?.stdin || !this.process?.stdout) {
                reject(new Error("r2 not running"));
                return;
            }

            let output = "";
            const handler = (data: Buffer) => {
                output += data.toString();
                if (output.includes("\x00")) {
                    this.process?.stdout?.removeListener("data", handler);
                    resolve(output.replace(/\x00/g, "").trim());
                }
            };

            this.process.stdout.on("data", handler);
            this.process.stdin.write(command + "\n");
        });
    }

    async cmdj(command: string): Promise<any> {
        const result = await this.cmd(command);
        try {
            return JSON.parse(result);
        } catch {
            return null;
        }
    }

    async close(): Promise<void> {
        if (this.process) {
            this.process.stdin?.write("q\n");
            this.process.kill();
            this.process = null;
        }
    }
}

// MCP Server
const server = new McpServer({
    name: "radare2-mcp",
    version: "1.0.0",
});

let r2: R2Session | null = null;

// Tool: Binary oeffnen
server.tool(
    "open_binary",
    "Open a binary file for analysis in radare2",
    {
        path: z.string().describe("Path to the binary file"),
        arch: z.string().optional().describe("Architecture override (x86, arm, mips)"),
        bits: z.number().optional().describe("Bit width override (16, 32, 64)"),
        analyze: z.boolean().optional().default(true).describe("Run automatic analysis"),
    },
    async ({ path, arch, bits, analyze }) => {
        try {
            if (r2) await r2.close();
            r2 = new R2Session();

            const flags: string[] = [];
            if (arch) flags.push("-a", arch);
            if (bits) flags.push("-b", String(bits));

            await r2.open(path, flags);

            if (analyze) {
                await r2.cmd("aaa");
            }

            const info = await r2.cmdj("ij");
            return {
                content: [{
                    type: "text",
                    text: `Binary loaded: ${path}\n${JSON.stringify(info, null, 2)}`
                }]
            };
        } catch (error: any) {
            return {
                content: [{ type: "text", text: `Error: ${error.message}` }],
                isError: true
            };
        }
    }
);

// Tool: Funktionen auflisten
server.tool(
    "list_functions",
    "List all detected functions in the loaded binary",
    {
        filter: z.string().optional().describe("Filter functions by name pattern"),
    },
    async ({ filter }) => {
        if (!r2) {
            return {
                content: [{ type: "text", text: "No binary loaded. Use open_binary first." }],
                isError: true
            };
        }

        let functions = await r2.cmdj("aflj") || [];

        if (filter) {
            functions = functions.filter((f: any) =>
                f.name.toLowerCase().includes(filter.toLowerCase())
            );
        }

        const summary = functions.map((f: any) =>
            `${f.name} @ 0x${f.offset.toString(16)} (size: ${f.size}, blocks: ${f.nbbs || 0})`
        ).join("\n");

        return {
            content: [{
                type: "text",
                text: `Found ${functions.length} functions:\n${summary}`
            }]
        };
    }
);

// Tool: Funktion disassemblieren
server.tool(
    "disassemble_function",
    "Disassemble a function by name or address",
    {
        target: z.string().describe("Function name or address (hex)"),
    },
    async ({ target }) => {
        if (!r2) {
            return {
                content: [{ type: "text", text: "No binary loaded." }],
                isError: true
            };
        }

        await r2.cmd(`s ${target}`);
        const disasm = await r2.cmd("pdf");

        return {
            content: [{ type: "text", text: disasm || "Could not disassemble" }]
        };
    }
);

// Tool: Hex-Dump
server.tool(
    "hex_dump",
    "Show hex dump at an address",
    {
        address: z.string().describe("Address (hex format, e.g., 0x08048000)"),
        size: z.number().optional().default(256).describe("Number of bytes to dump"),
    },
    async ({ address, size }) => {
        if (!r2) {
            return {
                content: [{ type: "text", text: "No binary loaded." }],
                isError: true
            };
        }

        const dump = await r2.cmd(`px ${size} @ ${address}`);
        return {
            content: [{ type: "text", text: dump }]
        };
    }
);

// Tool: Strings extrahieren
server.tool(
    "extract_strings",
    "Extract strings from the binary",
    {
        minLength: z.number().optional().default(4).describe("Minimum string length"),
    },
    async ({ minLength }) => {
        if (!r2) {
            return {
                content: [{ type: "text", text: "No binary loaded." }],
                isError: true
            };
        }

        await r2.cmd(`e bin.str.min=${minLength}`);
        const strings = await r2.cmdj("izj") || [];

        const formatted = strings.map((s: any) =>
            `0x${s.vaddr.toString(16)}: "${s.string}" (${s.type}, ${s.length} bytes)`
        ).join("\n");

        return {
            content: [{
                type: "text",
                text: `Found ${strings.length} strings:\n${formatted}`
            }]
        };
    }
);

// Tool: Shellcode analysieren
server.tool(
    "analyze_shellcode",
    "Load and analyze shellcode from hex bytes",
    {
        hex: z.string().describe("Shellcode as hex string (e.g., '31c050...')"),
        arch: z.string().optional().default("x86").describe("Architecture"),
        bits: z.number().optional().default(32).describe("Bit width"),
    },
    async ({ hex, arch, bits }) => {
        try {
            if (r2) await r2.close();
            r2 = new R2Session();

            await r2.open("malloc://4096", ["-a", arch, "-b", String(bits)]);
            await r2.cmd(`wx ${hex}`);
            await r2.cmd("aaa");

            const disasm = await r2.cmd("pd 50");
            const info = await r2.cmdj("ij");

            return {
                content: [{
                    type: "text",
                    text: `Shellcode loaded (${arch} ${bits}-bit, ${hex.length / 2} bytes)\n\n${disasm}`
                }]
            };
        } catch (error: any) {
            return {
                content: [{ type: "text", text: `Error: ${error.message}` }],
                isError: true
            };
        }
    }
);

// Tool: ESIL Emulation
server.tool(
    "emulate",
    "Emulate code using ESIL from current position",
    {
        steps: z.number().optional().default(10).describe("Number of steps to emulate"),
        address: z.string().optional().describe("Start address (uses current if not set)"),
    },
    async ({ steps, address }) => {
        if (!r2) {
            return {
                content: [{ type: "text", text: "No binary loaded." }],
                isError: true
            };
        }

        await r2.cmd("aei");
        await r2.cmd("aeim 0xffffd000 0x2000 stack");

        if (address) {
            await r2.cmd(`s ${address}`);
        }
        await r2.cmd("aeip");

        const trace: string[] = [];
        for (let i = 0; i < steps; i++) {
            const pc = await r2.cmd("aer PC");
            const regs = await r2.cmd("aer");
            trace.push(`Step ${i}: PC=${pc.trim()}\n${regs}`);

            await r2.cmd("aes");
        }

        const finalRegs = await r2.cmd("aer");

        return {
            content: [{
                type: "text",
                text: `Emulated ${steps} steps.\n\nFinal registers:\n${finalRegs}`
            }]
        };
    }
);

// Tool: r2 Befehl direkt ausfuehren
server.tool(
    "r2_command",
    "Execute a raw radare2 command",
    {
        command: z.string().describe("The radare2 command to execute"),
    },
    async ({ command }) => {
        if (!r2) {
            return {
                content: [{ type: "text", text: "No binary loaded." }],
                isError: true
            };
        }

        try {
            const result = await r2.cmd(command);
            return {
                content: [{ type: "text", text: result || "(no output)" }]
            };
        } catch (error: any) {
            return {
                content: [{ type: "text", text: `Error: ${error.message}` }],
                isError: true
            };
        }
    }
);

// Resources
server.resource(
    "binary-info",
    "binary://info",
    { description: "Current binary information", mimeType: "application/json" },
    async (uri) => {
        if (!r2) {
            return {
                contents: [{
                    uri: uri.href,
                    mimeType: "application/json",
                    text: JSON.stringify({ error: "No binary loaded" })
                }]
            };
        }

        const info = await r2.cmdj("ij");
        return {
            contents: [{
                uri: uri.href,
                mimeType: "application/json",
                text: JSON.stringify(info, null, 2)
            }]
        };
    }
);

// Server starten
async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("radare2 MCP server running on stdio");

    // Cleanup bei Exit
    process.on("SIGINT", async () => {
        if (r2) await r2.close();
        process.exit(0);
    });
}

main().catch(console.error);
```

#### 3.2.3 MCP Server mit Error Handling und Logging (TypeScript)

```typescript
// robust-server.ts
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({
    name: "robust-example",
    version: "1.0.0",
});

// Logging-Helper
function log(level: string, message: string) {
    const timestamp = new Date().toISOString();
    console.error(`[${timestamp}] [${level.toUpperCase()}] ${message}`);
}

// Timeout-Wrapper
async function withTimeout<T>(
    promise: Promise<T>,
    ms: number,
    operation: string
): Promise<T> {
    const timeout = new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error(`${operation} timed out after ${ms}ms`)), ms)
    );
    return Promise.race([promise, timeout]);
}

// Tool mit robustem Error Handling
server.tool(
    "safe_operation",
    "Perform an operation with comprehensive error handling",
    {
        input: z.string().describe("Input to process"),
        timeout: z.number().optional().default(30000).describe("Timeout in ms"),
    },
    async ({ input, timeout }) => {
        log("info", `Processing: ${input}`);

        try {
            const result = await withTimeout(
                processInput(input),
                timeout,
                "processInput"
            );

            log("info", `Success: ${input}`);
            return {
                content: [{ type: "text", text: result }]
            };
        } catch (error: any) {
            log("error", `Failed: ${error.message}`);

            // Unterscheide verschiedene Fehlertypen
            if (error.message.includes("timed out")) {
                return {
                    content: [{
                        type: "text",
                        text: `Operation timed out after ${timeout}ms. Try with a simpler input or increase timeout.`
                    }],
                    isError: true
                };
            }

            if (error.message.includes("not found")) {
                return {
                    content: [{
                        type: "text",
                        text: `Input not found: ${input}. Check available options with list_options tool.`
                    }],
                    isError: true
                };
            }

            // Generischer Fehler
            return {
                content: [{
                    type: "text",
                    text: `Unexpected error: ${error.message}`
                }],
                isError: true
            };
        }
    }
);

async function processInput(input: string): Promise<string> {
    // Platzhalter-Implementation
    return `Processed: ${input}`;
}

// Server starten
async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    log("info", "Server started");
}

main().catch((error) => {
    log("error", `Fatal: ${error.message}`);
    process.exit(1);
});
```

#### 3.2.4 MCP Server Unit Tests (TypeScript / Vitest)

```typescript
// server.test.ts
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createServer } from "./server.js"; // Your server factory

describe("Radare2 MCP Server", () => {
    let client: Client;
    let cleanup: () => Promise<void>;

    beforeEach(async () => {
        const server = createServer();
        client = new Client({ name: "test-client", version: "1.0.0" });

        const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

        await Promise.all([
            server.connect(serverTransport),
            client.connect(clientTransport),
        ]);

        cleanup = async () => {
            await client.close();
            await server.close();
        };
    });

    afterEach(async () => {
        await cleanup();
    });

    describe("tools/list", () => {
        it("should list all available tools", async () => {
            const result = await client.listTools();

            expect(result.tools.length).toBeGreaterThan(0);

            const toolNames = result.tools.map(t => t.name);
            expect(toolNames).toContain("open_binary");
            expect(toolNames).toContain("list_functions");
            expect(toolNames).toContain("disassemble_function");
        });

        it("tools should have descriptions", async () => {
            const result = await client.listTools();

            for (const tool of result.tools) {
                expect(tool.description).toBeTruthy();
                expect(tool.description.length).toBeGreaterThan(10);
            }
        });

        it("tools should have valid input schemas", async () => {
            const result = await client.listTools();

            for (const tool of result.tools) {
                expect(tool.inputSchema).toBeDefined();
                expect(tool.inputSchema.type).toBe("object");
            }
        });
    });

    describe("tools/call", () => {
        it("should return error when no binary is loaded", async () => {
            const result = await client.callTool({
                name: "list_functions",
                arguments: {},
            });

            expect(result.isError).toBe(true);
        });

        it("should handle unknown tool gracefully", async () => {
            await expect(
                client.callTool({
                    name: "nonexistent_tool",
                    arguments: {},
                })
            ).rejects.toThrow();
        });
    });

    describe("resources", () => {
        it("should list resources", async () => {
            const result = await client.listResources();
            expect(result.resources.length).toBeGreaterThan(0);
        });
    });
});
```

---

## Anhang

### A. Nuetzliche Referenzen

| Quelle | URL |
|--------|-----|
| radare2 Book | https://book.rada.re |
| r2wiki | https://r2wiki.readthedocs.io |
| radare2 GitHub | https://github.com/radareorg/radare2 |
| r2pipe GitHub | https://github.com/radareorg/radare2-r2pipe |
| MCP Spezifikation | https://modelcontextprotocol.io/specification |
| MCP TypeScript SDK | https://github.com/modelcontextprotocol/typescript-sdk |
| MCP SDK npm | https://www.npmjs.com/package/@modelcontextprotocol/sdk |
| Zod (Schema-Validierung) | https://zod.dev |

### B. radare2 Architektur-Kuerzel

| Kuerzel | Architektur |
|---------|-------------|
| `x86`   | Intel x86 (32/64-bit) |
| `arm`   | ARM (32/64-bit, inkl. Thumb) |
| `mips`  | MIPS (32/64-bit) |
| `ppc`   | PowerPC |
| `sparc` | SPARC |
| `avr`   | AVR (Microcontroller) |
| `dalvik` | Android Dalvik VM |
| `java`  | Java Bytecode |
| `wasm`  | WebAssembly |
| `evm`   | Ethereum VM |
| `6502`  | MOS 6502 |
| `z80`   | Zilog Z80 |
| `riscv` | RISC-V |

### C. JSON-RPC 2.0 Error Codes

| Code | Bedeutung |
|------|-----------|
| `-32700` | Parse Error |
| `-32600` | Invalid Request |
| `-32601` | Method Not Found |
| `-32602` | Invalid Params |
| `-32603` | Internal Error |
| `-32000` bis `-32099` | Server-definierte Fehler |

### D. MCP Methoden-Uebersicht

| Methode | Richtung | Beschreibung |
|---------|----------|-------------|
| `initialize` | Client -> Server | Handshake initiieren |
| `notifications/initialized` | Client -> Server | Handshake abgeschlossen |
| `tools/list` | Client -> Server | Tools auflisten |
| `tools/call` | Client -> Server | Tool aufrufen |
| `resources/list` | Client -> Server | Resources auflisten |
| `resources/read` | Client -> Server | Resource lesen |
| `resources/templates/list` | Client -> Server | Resource-Templates auflisten |
| `resources/subscribe` | Client -> Server | Resource abonnieren |
| `resources/unsubscribe` | Client -> Server | Abo beenden |
| `prompts/list` | Client -> Server | Prompts auflisten |
| `prompts/get` | Client -> Server | Prompt abrufen |
| `logging/setLevel` | Client -> Server | Log-Level setzen |
| `notifications/resources/updated` | Server -> Client | Resource geaendert |
| `notifications/resources/list_changed` | Server -> Client | Resource-Liste geaendert |
| `notifications/tools/list_changed` | Server -> Client | Tool-Liste geaendert |
| `notifications/progress` | Server -> Client | Fortschritt melden |
| `sampling/createMessage` | Server -> Client | LLM-Sampling anfordern |
| `ping` | Bidirektional | Verbindungstest |

### E. ESIL Kurzreferenz

```
# Arithmetik
value,register,=        # Register = value
value,register,+=       # Register += value
value,register,-=       # Register -= value

# Logik
value,register,&=       # AND
value,register,|=       # OR
value,register,^=       # XOR
register,!=             # NOT (bitwise)

# Speicher
register,[N],dest,=     # dest = *register (N bytes)
value,register,=[N]     # *register = value (N bytes)

# Stack (x86)
4,esp,-=,val,esp,=[4]   # push val
esp,[4],reg,=,4,esp,+=  # pop reg

# Kontrollfluss
cond,?{,code,}          # if (cond) { code }
addr,eip,=              # jmp addr
$$,addr,==,$z,?{,...,}  # bedingter Sprung

# Spezielle Variablen
$$                      # Aktuelle Adresse
$z                      # Zero-Flag
$s                      # Sign-Flag
$c                      # Carry-Flag
$o                      # Overflow-Flag
$p                      # Parity-Flag
$ds                     # Delay-Slot-Flag
```
