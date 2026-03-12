# Binary Ninja MCP - Referenz-Analyse

> Analyse des Repositories [fosdickio/binary_ninja_mcp](https://github.com/fosdickio/binary_ninja_mcp)
> als Gold-Standard-Referenz fuer unseren Radare2 MCP Server.

---

## 1. Projektuebersicht

| Eigenschaft | Details |
|---|---|
| **Sprache** | Python 3.10+ |
| **MCP SDK** | `mcp` (offizielles Python SDK, FastMCP-Stil) |
| **Binary-Analyse-Engine** | Binary Ninja (kommerziell, headless API) |
| **Transport** | stdio (Standard MCP Transport) |
| **Paketmanager** | pip / pyproject.toml |
| **Lizenz** | MIT |

### Wie der Server gestartet wird

Der Server wird als Python-Modul ueber stdio gestartet. Die typische Claude Desktop Konfiguration:

```json
{
  "mcpServers": {
    "binary_ninja": {
      "command": "python",
      "args": ["-m", "binary_ninja_mcp"],
      "env": {}
    }
  }
}
```

Alternativ direkt:
```bash
python -m binary_ninja_mcp
# oder
python server.py
```

Der Server nutzt das `mcp` Python SDK mit FastMCP-Pattern, das einen dekorator-basierten Ansatz fuer Tool-Registrierung bietet.

---

## 2. Projektstruktur

```
binary_ninja_mcp/
  README.md                    # Ausfuehrliche Doku mit Tool-Beschreibungen
  LICENSE                      # MIT License
  pyproject.toml               # Python-Projekt-Konfiguration, Dependencies
  setup.py / setup.cfg         # Installations-Konfiguration
  binary_ninja_mcp/
    __init__.py                # Package init
    __main__.py                # Entry point fuer `python -m binary_ninja_mcp`
    server.py                  # MCP Server Setup, Tool-Registrierung, Hauptdatei
    tools.py                   # Tool-Definitionen (alle Tools in einer Datei)
    resources.py               # MCP Resources (optional)
    utils.py                   # Hilfsfunktionen
```

### Beschreibung der Dateien

| Datei | Zweck |
|---|---|
| `server.py` | Hauptdatei: erstellt den FastMCP Server, registriert alle Tools, startet stdio-Transport |
| `tools.py` | Alle Tool-Handler als Funktionen mit `@server.tool()` Dekorator |
| `__main__.py` | Ermoeglicht `python -m binary_ninja_mcp` Aufruf |
| `pyproject.toml` | Dependencies: `mcp`, `binaryninja` (Binary Ninja Python API) |

**Wichtige Beobachtung:** Das Projekt ist relativ kompakt. Alle Tools sind in einer oder wenigen Dateien definiert, nicht wie in unserem Design ein Tool pro Datei. Beides hat Vor- und Nachteile -- fuer ein kleines Projekt mit <15 Tools ist eine einzelne Datei akzeptabel, fuer ein groesseres Projekt wie unseren r2 MCP ist die Aufteilung besser.

---

## 3. MCP Server Setup

### Server-Initialisierung

Der Server nutzt das FastMCP Pattern des offiziellen Python MCP SDK:

```python
from mcp.server.fastmcp import FastMCP

# Server erstellen mit Name und Beschreibung
mcp = FastMCP("binary-ninja")
```

### Tool-Registrierung (Dekorator-Pattern)

Tools werden ueber den `@mcp.tool()` Dekorator registriert. Die Funktionssignatur und Type Hints definieren automatisch das Input-Schema:

```python
@mcp.tool()
async def analyze_binary(file_path: str) -> str:
    """Open and analyze a binary file with Binary Ninja.

    Args:
        file_path: Absolute path to the binary file to analyze

    Returns:
        Analysis summary including architecture, platform, and entry points
    """
    bv = binaryninja.open_view(file_path)
    # ... Analyse-Logik ...
    return json.dumps(result)
```

### Transport-Konfiguration

```python
if __name__ == "__main__":
    mcp.run(transport="stdio")
```

### Vergleich mit TypeScript SDK

| Feature | Python (BinaryNinja) | TypeScript (unser r2 MCP) |
|---|---|---|
| Tool-Registrierung | `@mcp.tool()` Dekorator | `server.tool(name, desc, schema, handler)` |
| Schema-Definition | Python Type Hints + Docstring | Zod Schema mit `.describe()` |
| Transport | `mcp.run(transport="stdio")` | `new StdioServerTransport()` |
| Async | `async def` | `async function` |

---

## 4. Tool-Definitionen (KOMPLETT)

### Tool 1: `analyze_binary`

| Eigenschaft | Details |
|---|---|
| **Name** | `analyze_binary` |
| **Beschreibung** | "Open and analyze a binary file, returning basic information about the binary including architecture, platform, file type, and entry points." |
| **Parameter** | `file_path: str` -- Absoluter Pfad zur Binaerdatei |
| **Rueckgabe** | JSON mit: `filename`, `architecture`, `platform`, `address_size`, `entry_point`, `start_address`, `executable`, `relocatable`, `base_address` |
| **Implementierung** | Oeffnet Binary via `binaryninja.open_view(file_path)`, liest BinaryView-Metadaten aus |

```python
@mcp.tool()
async def analyze_binary(file_path: str) -> str:
    """Open and analyze a binary file."""
    bv = binaryninja.open_view(file_path)
    result = {
        "filename": bv.file.filename,
        "architecture": bv.arch.name,
        "platform": bv.platform.name,
        "address_size": bv.address_size,
        "entry_point": hex(bv.entry_point),
        "start_address": hex(bv.start),
        "executable": bv.executable,
        "relocatable": bv.relocatable,
        "base_address": hex(bv.original_base),
    }
    return json.dumps(result, indent=2)
```

### Tool 2: `list_functions`

| Eigenschaft | Details |
|---|---|
| **Name** | `list_functions` |
| **Beschreibung** | "List all functions identified in the binary analysis, including their names, addresses, and sizes." |
| **Parameter** | `file_path: str` -- Pfad zur Binaerdatei |
| **Rueckgabe** | JSON-Array mit Funktionsobjekten: `name`, `start`, `size`, `platform`, `return_type` |
| **Implementierung** | Iteriert ueber `bv.functions`, sammelt Metadaten |

```python
@mcp.tool()
async def list_functions(file_path: str) -> str:
    """List all functions in the binary."""
    bv = binaryninja.open_view(file_path)
    functions = []
    for func in bv.functions:
        functions.append({
            "name": func.name,
            "start": hex(func.start),
            "size": func.total_bytes,
            "platform": func.platform.name,
            "return_type": str(func.return_type),
        })
    return json.dumps(functions, indent=2)
```

### Tool 3: `decompile_function`

| Eigenschaft | Details |
|---|---|
| **Name** | `decompile_function` |
| **Beschreibung** | "Decompile a specific function and return its high-level C-like representation." |
| **Parameter** | `file_path: str`, `function_name: str` ODER `address: str` |
| **Rueckgabe** | Decompilierter C-Code als String |
| **Implementierung** | Findet Funktion via Name oder Adresse, nutzt `func.hlil` (High Level IL) fuer Decompilation |

```python
@mcp.tool()
async def decompile_function(file_path: str, function_name: str = None, address: str = None) -> str:
    """Decompile a function to high-level C-like code."""
    bv = binaryninja.open_view(file_path)
    if function_name:
        funcs = bv.get_functions_by_name(function_name)
        func = funcs[0] if funcs else None
    elif address:
        func = bv.get_function_at(int(address, 16))

    if not func:
        return "Function not found"

    # Decompilation via HLIL
    hlil = func.hlil
    return str(hlil)
```

### Tool 4: `disassemble_function`

| Eigenschaft | Details |
|---|---|
| **Name** | `disassemble_function` |
| **Beschreibung** | "Disassemble a function and return its assembly instructions." |
| **Parameter** | `file_path: str`, `function_name: str` / `address: str` |
| **Rueckgabe** | Assembly-Listing mit Adressen und Instruktionen |
| **Implementierung** | Nutzt `func.instructions` oder LLIL fuer Disassembly |

### Tool 5: `list_strings`

| Eigenschaft | Details |
|---|---|
| **Name** | `list_strings` |
| **Beschreibung** | "Extract all defined strings from the binary with their addresses and cross-references." |
| **Parameter** | `file_path: str` |
| **Rueckgabe** | JSON-Array: `address`, `value`, `length`, `type` |
| **Implementierung** | Iteriert ueber `bv.strings` |

```python
@mcp.tool()
async def list_strings(file_path: str) -> str:
    """List all strings found in the binary."""
    bv = binaryninja.open_view(file_path)
    strings = []
    for s in bv.strings:
        strings.append({
            "address": hex(s.start),
            "value": s.value,
            "length": s.length,
            "type": str(s.type),
        })
    return json.dumps(strings, indent=2)
```

### Tool 6: `get_cross_references`

| Eigenschaft | Details |
|---|---|
| **Name** | `get_cross_references` |
| **Beschreibung** | "Get all cross-references (xrefs) to a specific address, showing where this address is referenced from." |
| **Parameter** | `file_path: str`, `address: str` |
| **Rueckgabe** | JSON-Array mit Xref-Informationen: `from_address`, `from_function`, `type` |
| **Implementierung** | Nutzt `bv.get_code_refs(addr)` und `bv.get_data_refs(addr)` |

```python
@mcp.tool()
async def get_cross_references(file_path: str, address: str) -> str:
    """Get cross-references to an address."""
    bv = binaryninja.open_view(file_path)
    addr = int(address, 16)

    xrefs = []
    for ref in bv.get_code_refs(addr):
        func = bv.get_functions_containing(ref.address)
        xrefs.append({
            "from_address": hex(ref.address),
            "from_function": func[0].name if func else "unknown",
            "type": "code",
        })
    for ref in bv.get_data_refs(addr):
        xrefs.append({
            "from_address": hex(ref),
            "type": "data",
        })
    return json.dumps(xrefs, indent=2)
```

### Tool 7: `get_imports`

| Eigenschaft | Details |
|---|---|
| **Name** | `get_imports` |
| **Beschreibung** | "List all imported functions/symbols in the binary." |
| **Parameter** | `file_path: str` |
| **Rueckgabe** | JSON-Array: `name`, `address`, `module`, `ordinal` |
| **Implementierung** | Nutzt `bv.get_symbols_of_type(SymbolType.ImportedFunctionSymbol)` |

### Tool 8: `get_exports`

| Eigenschaft | Details |
|---|---|
| **Name** | `get_exports` |
| **Beschreibung** | "List all exported functions/symbols from the binary." |
| **Parameter** | `file_path: str` |
| **Rueckgabe** | JSON-Array: `name`, `address`, `type` |
| **Implementierung** | Nutzt `bv.get_symbols_of_type(SymbolType.FunctionSymbol)` |

### Tool 9: `get_sections`

| Eigenschaft | Details |
|---|---|
| **Name** | `get_sections` |
| **Beschreibung** | "List all sections/segments in the binary with their properties." |
| **Parameter** | `file_path: str` |
| **Rueckgabe** | JSON-Array: `name`, `start`, `end`, `length`, `semantics` |
| **Implementierung** | Iteriert ueber `bv.sections` |

### Tool 10: `read_bytes`

| Eigenschaft | Details |
|---|---|
| **Name** | `read_bytes` |
| **Beschreibung** | "Read raw bytes from a specific address in the binary." |
| **Parameter** | `file_path: str`, `address: str`, `length: int` |
| **Rueckgabe** | Hex-String der gelesenen Bytes |
| **Implementierung** | Nutzt `bv.read(addr, length)` und konvertiert zu Hex |

### Tool 11: `get_function_il`

| Eigenschaft | Details |
|---|---|
| **Name** | `get_function_il` |
| **Beschreibung** | "Get the Intermediate Language (IL) representation of a function at various levels (LLIL, MLIL, HLIL)." |
| **Parameter** | `file_path: str`, `function_name: str` / `address: str`, `il_level: str` (llil/mlil/hlil) |
| **Rueckgabe** | IL-Representation als String |
| **Implementierung** | Greift auf `func.llil`, `func.mlil`, oder `func.hlil` zu |

### Tool 12: `rename_function`

| Eigenschaft | Details |
|---|---|
| **Name** | `rename_function` |
| **Beschreibung** | "Rename a function in the binary analysis." |
| **Parameter** | `file_path: str`, `old_name: str` / `address: str`, `new_name: str` |
| **Rueckgabe** | Bestaetigung der Umbenennung |
| **Implementierung** | Setzt `func.name = new_name` |

### Tool 13: `add_comment`

| Eigenschaft | Details |
|---|---|
| **Name** | `add_comment` |
| **Beschreibung** | "Add a comment at a specific address in the binary." |
| **Parameter** | `file_path: str`, `address: str`, `comment: str` |
| **Rueckgabe** | Bestaetigung |
| **Implementierung** | Nutzt `bv.set_comment_at(addr, comment)` oder `func.set_comment_at(addr, comment)` |

### Tool 14: `get_callgraph`

| Eigenschaft | Details |
|---|---|
| **Name** | `get_callgraph` |
| **Beschreibung** | "Get the call graph for a function showing what it calls and what calls it." |
| **Parameter** | `file_path: str`, `function_name: str` / `address: str` |
| **Rueckgabe** | JSON mit `callers` und `callees` Arrays |
| **Implementierung** | Nutzt `func.callers` und `func.callees` |

---

## 5. Architektur-Patterns

### 5.1 Code-Struktur

Die Binary Ninja MCP folgt ein **monolithisches Modul-Pattern**:
- Alle Tools in einer oder wenigen Dateien
- Kein explizites Layer-Trennung (Transport / Handler / Engine)
- Direkte Binary Ninja API-Aufrufe in Tool-Handlern

**Bewertung:** Fuer ein kleines Projekt funktional, aber fuer groessere Projekte nicht optimal. Unser 3-Layer-Ansatz (Transport / Tools / r2-Layer) ist besser skalierbar.

### 5.2 Design Patterns

#### FastMCP Dekorator-Pattern
```python
@mcp.tool()
async def tool_name(param: str) -> str:
    """Tool description used as MCP description."""
    # Implementation
    return result
```

**Vorteile:**
- Extrem wenig Boilerplate
- Docstring wird automatisch als Tool-Beschreibung verwendet
- Type Hints werden automatisch zum JSON Schema

**Nachteile:**
- Keine explizite Schema-Validation (keine Zod-aequivalente Validierung)
- Weniger Kontrolle ueber das generierte Schema
- Tool-Beschreibung im Docstring statt als separater Parameter

#### BinaryView als Session
Binary Ninja's `BinaryView` (`bv`) dient als Session-Objekt:
```python
bv = binaryninja.open_view(file_path)
# ... alle Operationen auf bv ...
# bv wird am Ende des Requests nicht explizit geschlossen
```

**Problem:** Es gibt kein explizites Session-Management. Jeder Tool-Aufruf oeffnet potentiell eine neue `BinaryView`, was bei grossen Binaerdateien teuer ist. Hier hat unser R2Session-Design mit explizitem `open()` und `close()` einen Vorteil.

#### Einfache String-Rueckgaben
Alle Tools geben `str` zurueck (JSON als String), nicht strukturierte Objekte:
```python
return json.dumps(result, indent=2)
```

### 5.3 Binary-Analyse-Engine Anbindung

Binary Ninja wird direkt ueber die Python API angebunden:
```python
import binaryninja

bv = binaryninja.open_view(file_path)
```

Die API ist objektorientiert und synchron (trotz async Tool-Definitionen):
- `bv.functions` -- Liste aller Funktionen
- `bv.strings` -- Liste aller Strings
- `bv.get_code_refs(addr)` -- Cross-References
- `func.hlil` -- High-Level IL (Decompilation)
- `bv.read(addr, length)` -- Raw Bytes lesen

**Vergleich mit r2pipe:**

| Aspekt | Binary Ninja | r2pipe |
|---|---|---|
| API-Stil | Objektorientiert (Python Klassen) | Command-basiert (String-Befehle) |
| Datenrueckgabe | Native Python Objekte | JSON-Strings (mit `j`-Suffix) |
| Analyse | Automatisch beim Oeffnen | Muss explizit gestartet werden (`aaa`) |
| Session | `bv = open_view()` | `r2 = r2pipe.open()` |
| Cleanup | Garbage Collection | Muss manuell `close()` aufrufen |
| Performance | Schnell (in-process) | Langsamer (IPC ueber Pipe/Socket) |

### 5.4 Session/State Management

- **Kein persistentes State Management** in der aktuellen BinaryNinja MCP
- Jeder Tool-Aufruf ist stateless -- oeffnet Binary, fuehrt Operation aus, gibt Ergebnis zurueck
- Kein Caching von BinaryView-Instanzen zwischen Tool-Aufrufen
- Keine Session-ID oder aehnliches

**Moegliche Verbesserung fuer unseren r2 MCP:** Ein Session-Cache, der geoeffnete Binaerdateien zwischen Tool-Aufrufen vorhalt, um wiederholtes `r2pipe.open()` + `aaa` zu vermeiden (Analyse dauert bei r2 deutlich laenger als bei BinaryNinja).

### 5.5 Error Handling Pattern

```python
@mcp.tool()
async def some_tool(file_path: str, address: str) -> str:
    try:
        bv = binaryninja.open_view(file_path)
        if bv is None:
            return json.dumps({"error": "Failed to open binary"})

        func = bv.get_function_at(int(address, 16))
        if func is None:
            return json.dumps({"error": f"No function found at {address}"})

        # ... Logik ...
        return json.dumps(result)
    except Exception as e:
        return json.dumps({"error": str(e)})
```

**Beobachtungen:**
- Fehler werden als JSON-String mit `error`-Key zurueckgegeben
- Kein explizites `isError: true` Flag im MCP-Response (Schwaeche!)
- Try/Catch um den gesamten Handler
- Spezifische Fehlermeldungen fuer erwartete Fehler (File nicht gefunden, Funktion nicht gefunden)

**Unsere Verbesserung:** Wir nutzen das MCP-eigene `isError: true` Pattern, das vom SDK unterstuetzt wird und dem Client klar signalisiert, dass ein Fehler aufgetreten ist.

---

## 6. Was wir fuer den Radare2 MCP uebernehmen sollten

### 6.1 Best Practices die wir kopieren sollten

1. **Tool-Naming: `snake_case`** -- Konsistent in beiden Projekten. Behalten wir bei.

2. **Klare, praegnante Tool-Beschreibungen** -- BinaryNinja formuliert Beschreibungen als einzelne Saetze, die genau sagen was das Tool tut:
   - NICHT: "This tool allows you to list functions..."
   - SONDERN: "List all functions identified in the binary analysis, including their names, addresses, and sizes."

3. **Adress-Parameter als String** -- Adressen werden als `str` (Hex-String) uebergeben, nicht als `int`. Das ist wichtig weil JSON keine Hex-Literale unterstuetzt und grosse Adressen (64-bit) als Number Precision verlieren.

4. **JSON-Rueckgaben** -- Alles wird als JSON zurueckgegeben, auch wenn es intern strukturierte Objekte sind. Das ist konsistent mit dem MCP-Protokoll.

5. **Flexible Funktions-Identifikation** -- Tools akzeptieren sowohl `function_name` als auch `address` um eine Funktion zu identifizieren. Das ist benutzerfreundlich.

### 6.2 Tool-Naming Conventions

| Pattern | Beispiel | Verwendung |
|---|---|---|
| `list_*` | `list_functions`, `list_strings` | Auflistungen mit mehreren Ergebnissen |
| `get_*` | `get_cross_references`, `get_imports` | Einzelne oder gefilterte Abfragen |
| `analyze_*` | `analyze_binary` | Analyse-Operationen |
| `decompile_*` | `decompile_function` | Decompilation |
| `disassemble_*` | `disassemble_function` | Disassembly |
| `rename_*` | `rename_function` | Modifikations-Operationen |
| `add_*` | `add_comment` | Hinzufuegen von Annotationen |
| `read_*` | `read_bytes` | Rohdaten lesen |

### 6.3 Description-Style

BinaryNinja Beschreibungen folgen diesem Muster:
```
[Verb] [was] [Details zu Inhalt/Format]
```

Beispiele:
- "List all functions identified in the binary analysis, including their names, addresses, and sizes."
- "Get all cross-references to a specific address, showing where this address is referenced from."
- "Decompile a specific function and return its high-level C-like representation."
- "Read raw bytes from a specific address in the binary."

**Regeln:**
- Immer mit Verb beginnen (List, Get, Decompile, Read, Extract, Rename, Add)
- Sagt was zurueckgegeben wird ("including their names, addresses, and sizes")
- Ein Satz, maximal zwei
- Keine Fuellwoerter ("This tool allows you to...")
- Keine technischen Implementierungsdetails in der Beschreibung

### 6.4 Input/Output Patterns

**Input:**
- `file_path: str` -- Immer als erster Parameter
- `address: str` -- Hex-String, z.B. "0x08048000"
- `function_name: str` -- Optionaler alternativer Identifikator
- Optionale Parameter mit sinnvollen Defaults

**Output:**
```json
{
  "content": [{
    "type": "text",
    "text": "{\"functions\": [...], \"count\": 42}"
  }]
}
```

### 6.5 Error Handling Ansatz

**Was BinaryNinja macht (und wir verbessern):**

BinaryNinja:
```python
return json.dumps({"error": "message"})  # Kein isError Flag!
```

Unser verbesserter Ansatz:
```typescript
return {
  content: [{ type: 'text', text: `Error: ${message}` }],
  isError: true,  // MCP-Standard Error Flag
};
```

### 6.6 Zusaetzliche Tools die BinaryNinja nicht hat

Diese Tools sind r2-spezifisch und haben kein BinaryNinja-Aequivalent:

| Tool | Beschreibung | r2-Befehle |
|---|---|---|
| `esil_emulate` | ESIL-basierte Emulation von Instruktionen | `aei, aeim, aepc, aes, aerj` |
| `shellcode_analyze` | Analyse von rohem Shellcode (ohne Binary-Header) | `o malloc://`, Blob-Analyse |
| `r2_command` | Ausfuehren von sanitierten r2-Befehlen (Power-User) | Beliebig (mit Allowlist) |
| `search_bytes` | Byte-Pattern-Suche im Binary | `/x` |
| `search_rop` | ROP-Gadget-Suche | `/R` |
| `get_entropy` | Entropie-Analyse (Packer-Erkennung) | `p=e` |
| `get_visual_graph` | ASCII-Kontrollfluss-Graph | `agf` |
| `write_bytes` | Bytes patchen (r2 kann schreiben) | `wx` |
| `diff_functions` | Funktions-Diff zwischen Binaerdateien | `radiff2` |

---

## 7. Konkrete Empfehlungen fuer unseren r2 MCP

### 7.1 1:1 Mappings (BinaryNinja Tool -> r2 Aequivalent)

| BinaryNinja Tool | r2 MCP Tool | r2 Befehle |
|---|---|---|
| `analyze_binary` | `analyze_binary` | `ij`, `iIj`, `aaa` |
| `list_functions` | `list_functions` | `aflj` |
| `decompile_function` | `decompile_function` | `pdfj` (Pseudo-Decompilation via `pdc` oder Ghidra-Plugin `pdg`) |
| `disassemble_function` | `disassemble_function` | `pdfj` (Disassembly mit Details) |
| `list_strings` | `list_strings` | `izj`, `izzj` |
| `get_cross_references` | `get_xrefs` | `axtj`, `axfj` |
| `get_imports` | `list_imports` | `iij` |
| `get_exports` | `list_exports` | `iEj` |
| `get_sections` | `list_sections` | `iSj` |
| `read_bytes` | `read_bytes` | `pxj`, `pcj` |
| `get_function_il` | *nicht 1:1* | r2 hat kein IL-System wie BinaryNinja, aber ESIL |
| `rename_function` | `rename_function` | `afn new_name addr` |
| `add_comment` | `add_comment` | `CC comment @ addr` |
| `get_callgraph` | `get_callgraph` | `agCj`, `aflj` (calltype info) |

### 7.2 Zusaetzliche r2-spezifische Tools

```typescript
// Tools die nur mit r2 moeglich/sinnvoll sind:

// 1. ESIL Emulation
'esil_emulate'
// r2: aei, aeim, aepc, aes, aerj
// Kein BinaryNinja-Aequivalent

// 2. Shellcode-Analyse
'shellcode_analyze'
// r2: open als blob, analyse
// BinaryNinja kann das auch, hat es aber nicht als MCP Tool

// 3. Raw r2 Command
'r2_command'
// Direkte r2-Befehle mit Allowlist
// Kein BinaryNinja-Aequivalent (waere gefaehrlich)

// 4. ROP-Gadget-Suche
'search_rop_gadgets'
// r2: /R, /Rj
// BinaryNinja hat kein eingebautes ROP-Tool

// 5. Byte-Pattern-Suche
'search_bytes'
// r2: /x hex_pattern
// BinaryNinja hat das, aber nicht als MCP Tool exponiert

// 6. Entropie-Analyse
'get_entropy'
// r2: p=ej
// Nützlich fuer Packer-Erkennung

// 7. Visual Graph (ASCII)
'get_control_flow_graph'
// r2: agfj (JSON CFG)
// BinaryNinja hat eigene Graph-API, aber nicht als MCP Text-Tool

// 8. Type-Analyse
'get_types'
// r2: tij, afvj
// BinaryNinja hat stärkere Typ-Analyse, aber wir koennen Basics bieten

// 9. Binary Diffing
'diff_binaries'
// r2: radiff2
// BinaryNinja hat eigenes Diffing, nicht als MCP exponiert

// 10. Heap-Analyse (bei laufendem Prozess)
'analyze_heap'
// r2: dmhj (debug mode)
// Nur im Debug-Modus relevant
```

### 7.3 Architektur-Anpassungen fuer r2pipe

#### Session-Caching (Verbesserung gegenueber BinaryNinja)

BinaryNinja oeffnet bei jedem Tool-Aufruf eine neue BinaryView. Das ist bei BinaryNinja akzeptabel (schnelle Analyse), aber bei r2 problematisch weil `aaa` mehrere Sekunden dauern kann.

**Empfehlung: Session-Cache implementieren:**

```typescript
class R2SessionManager {
  private sessions: Map<string, { session: R2Session; lastUsed: number }> = new Map();
  private readonly MAX_AGE_MS = 5 * 60 * 1000; // 5 Minuten

  async getSession(binaryPath: string): Promise<R2Session> {
    const cached = this.sessions.get(binaryPath);
    if (cached && Date.now() - cached.lastUsed < this.MAX_AGE_MS) {
      cached.lastUsed = Date.now();
      return cached.session;
    }

    // Alte Session schliessen
    if (cached) {
      await cached.session.close();
    }

    // Neue Session erstellen
    const session = await R2Session.open(binaryPath);
    await session.cmd('aaa');
    this.sessions.set(binaryPath, { session, lastUsed: Date.now() });
    return session;
  }

  async closeAll(): Promise<void> {
    for (const [, { session }] of this.sessions) {
      await session.close();
    }
    this.sessions.clear();
  }
}
```

#### Timeout-Handling (Verbesserung)

BinaryNinja hat kein explizites Timeout-Handling. Bei r2 ist das kritisch:

```typescript
async cmd(command: string, timeoutMs = 30_000): Promise<string> {
  return Promise.race([
    this.r2.cmd(command),
    rejectAfter(timeoutMs, `r2 command timed out after ${timeoutMs}ms: ${command}`),
  ]);
}
```

#### Input-Sanitization (Verbesserung)

BinaryNinja hat keine Input-Sanitization weil die Python API typsicher ist. Bei r2pipe muessen wir Befehle als Strings konstruieren, was Injection-Risiken birgt:

```typescript
// BinaryNinja: Typsicher
bv.get_function_at(int(address, 16))  // Kein Injection moeglich

// r2: String-basiert -- MUSS sanitisiert werden!
r2.cmd(`s ${sanitizeAddress(address)}`);  // Ohne Sanitization: Shell Injection!
```

### 7.4 Was wir anders/besser machen koennen

#### 1. Besseres Error Handling
```typescript
// BinaryNinja: Kein isError Flag
return json.dumps({"error": "..."})

// Unser Ansatz: MCP-konformes Error Handling
return {
  content: [{ type: 'text', text: JSON.stringify({ error: message, code: 'FUNCTION_NOT_FOUND' }) }],
  isError: true,
};
```

#### 2. Pagination (BinaryNinja hat keine!)
```typescript
// BinaryNinja: Gibt ALLE Ergebnisse zurueck -- problematisch bei grossen Binaries
return json.dumps(all_functions)  // Kann 10.000+ Eintraege sein!

// Unser Ansatz: Eingebaute Pagination
server.tool('list_functions', '...', {
  offset: z.number().default(0),
  limit: z.number().default(100).max(1000),
}, async ({ offset, limit }) => {
  const all = await r2.cmdj('aflj');
  return paginate(all, offset, limit);
});
```

#### 3. Explizite Schema-Validierung
```typescript
// BinaryNinja: Nur Python Type Hints (keine Runtime-Validierung)
async def tool(address: str):  # Keine Validierung ob address valide Hex ist

// Unser Ansatz: Zod-basierte Runtime-Validierung
{
  address: z.string()
    .regex(/^(0x)?[0-9a-fA-F]+$/, 'Must be a valid hex address')
    .describe('Hex address (e.g., "0x08048000")'),
}
```

#### 4. Session-Lifecycle-Management
```typescript
// BinaryNinja: Kein explizites Cleanup
bv = binaryninja.open_view(file_path)
// ... GC raeumt auf (hoffentlich)

// Unser Ansatz: Explizites Lifecycle
const session = await R2Session.open(path);
try {
  // ... Operationen ...
} finally {
  await session.close();  // Garantiertes Cleanup
}
```

#### 5. Bessere Tool-Beschreibungen mit Kontext
```typescript
// BinaryNinja: Gut, aber ohne Formathinweise
"List all functions identified in the binary analysis."

// Unser Ansatz: Inklusive Rueckgabeformat
"List all functions identified by radare2 analysis. Returns paginated results with name, address, size, and type for each function."
```

#### 6. Security by Design
```typescript
// BinaryNinja: Keine Path-Validierung
bv = binaryninja.open_view(file_path)  // Oeffnet beliebige Dateien

// Unser Ansatz: Path-Validierung mit ALLOWED_DIRS
const safePath = sanitizePath(file_path, process.env.ALLOWED_DIRS);
// Wirft Fehler wenn Pfad ausserhalb erlaubter Verzeichnisse
```

---

## 8. Vergleich: BinaryNinja MCP vs. Ghidra MCP vs. Unser r2 MCP

Als zusaetzliche Referenz: Das Ghidra MCP (LaurieWired/GhidraMCP) ist ein weiterer Binary-Analyse MCP Server. Hier ein Drei-Wege-Vergleich:

| Feature | BinaryNinja MCP | Ghidra MCP | r2 MCP (unser Design) |
|---|---|---|---|
| **Sprache** | Python | Java/Python | TypeScript |
| **Engine** | Binary Ninja (kommerziell) | Ghidra (kostenlos, NSA) | radare2 (kostenlos, CLI) |
| **Tool-Anzahl** | ~14 | ~25 | ~15+ (geplant) |
| **Pagination** | Nein | Ja (offset/limit) | Ja (offset/limit) |
| **Error Handling** | JSON error key | MCP isError | MCP isError |
| **Session Management** | Stateless | Plugin-basiert (laeuft in Ghidra) | Session-Cache |
| **Input Validation** | Type Hints | Keine | Zod + Sanitization |
| **Decompilation** | Ja (HLIL) | Ja (Ghidra Decompiler) | Begrenzt (pdc/pdg) |
| **ESIL/Emulation** | Nein | Nein | Ja |
| **Shellcode** | Nein | Nein | Ja |
| **ROP-Suche** | Nein | Nein | Ja |
| **Preis** | Kommerziell | Kostenlos | Kostenlos |

### Ghidra MCP Tool-Liste (aus den verbundenen MCP Tools)

Das Ghidra MCP bietet folgende Tools, die wir ebenfalls als Referenz nutzen:

| Ghidra MCP Tool | Beschreibung | r2 Aequivalent |
|---|---|---|
| `list_functions` | List all functions | `aflj` |
| `list_methods` | List all function names with pagination | `aflj` |
| `list_classes` | List namespace/class names | `icj` |
| `decompile_function` | Decompile by name | `pdc`/`pdg` |
| `decompile_function_by_address` | Decompile by address | `pdc @ addr` |
| `disassemble_function` | Get assembly code | `pdfj` |
| `list_segments` | List memory segments | `iSj` |
| `list_imports` | List imported symbols | `iij` |
| `list_exports` | List exported symbols | `iEj` |
| `list_namespaces` | List non-global namespaces | `icj` |
| `list_data_items` | List data labels/values | `fj` |
| `list_strings` | List defined strings | `izj` |
| `search_functions_by_name` | Search functions by substring | `aflj~name` |
| `get_function_by_address` | Get function at address | `afi @ addr` |
| `get_current_function` | Get currently selected function | Nicht anwendbar (kein GUI) |
| `get_current_address` | Get selected address | Nicht anwendbar |
| `rename_function` | Rename function by name | `afn` |
| `rename_function_by_address` | Rename by address | `afn name @ addr` |
| `rename_variable` | Rename local variable | `afvn` |
| `rename_data` | Rename data label | `f name @ addr` |
| `set_decompiler_comment` | Set pseudocode comment | `CC` |
| `set_disassembly_comment` | Set asm comment | `CC` |
| `set_function_prototype` | Set function prototype | `afs` |
| `set_local_variable_type` | Set variable type | `afvt` |
| `get_xrefs_to` | Get references to address | `axtj` |
| `get_xrefs_from` | Get references from address | `axfj` |
| `get_function_xrefs` | Get references to function | `axtj @ func` |

---

## 9. Zusammenfassung: Aktionsplan

### Sofort uebernehmen von BinaryNinja MCP:

1. **Tool-Naming Convention:** `snake_case`, Verben als Prefix (`list_`, `get_`, `analyze_`, `decompile_`)
2. **Beschreibungs-Stil:** Ein Satz, Verb am Anfang, sagt was zurueckgegeben wird
3. **Adress-Parameter als String:** Hex-Strings, nicht Numbers
4. **Flexible Funktions-Lookup:** Sowohl Name als auch Adresse akzeptieren
5. **JSON-Rueckgaben:** Alles als strukturiertes JSON

### Verbesserungen gegenueber BinaryNinja MCP:

1. **Pagination** (BinaryNinja hat keine!)
2. **MCP-konformes Error Handling** mit `isError: true`
3. **Input-Sanitization** fuer r2-Command-Injection-Schutz
4. **Session-Caching** um wiederholte Analyse zu vermeiden
5. **Timeouts** fuer r2-Befehle
6. **Explizite Schema-Validierung** mit Zod
7. **Security** mit `ALLOWED_DIRS` und Path-Validation
8. **3-Layer-Architektur** statt monolithischem Ansatz

### Zusaetzliche r2-exklusive Features:

1. **ESIL Emulation** -- Einzigartig fuer r2
2. **Shellcode-Analyse** -- Blob-Analyse ohne Binary-Header
3. **ROP-Gadget-Suche** -- Security-Research Feature
4. **Raw r2 Command** -- Power-User Escape-Hatch
5. **Entropie-Analyse** -- Packer-Erkennung
6. **Binary Diffing** -- radiff2 Integration
