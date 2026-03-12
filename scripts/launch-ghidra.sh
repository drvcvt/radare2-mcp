#!/bin/bash
# Launch Ghidra headless with a binary, import it into a project, and start the HTTP server
# Usage: launch-ghidra.sh <binary_path> [project_name]

GHIDRA_HOME="C:/Users/matti/ghidra/ghidra_11.3.2_PUBLIC"
GHIDRA_PROJECTS="C:/Users/matti/ghidra/projects"
ANALYZE_HEADLESS="$GHIDRA_HOME/support/analyzeHeadless"
GHIDRA_RUN="$GHIDRA_HOME/ghidraRun.bat"

if [ -z "$1" ]; then
    echo "Usage: launch-ghidra.sh <binary_path> [project_name]"
    echo ""
    echo "Example: launch-ghidra.sh /c/Users/matti/binaries/malware.exe malware_analysis"
    exit 1
fi

BINARY_PATH="$(realpath "$1" 2>/dev/null || echo "$1")"
BINARY_NAME="$(basename "$BINARY_PATH" | sed 's/\.[^.]*$//')"
PROJECT_NAME="${2:-${BINARY_NAME}_project}"

if [ ! -f "$BINARY_PATH" ]; then
    echo "Error: Binary not found: $BINARY_PATH"
    exit 1
fi

mkdir -p "$GHIDRA_PROJECTS"

echo "[*] Ghidra Headless Analysis"
echo "    Binary:  $BINARY_PATH"
echo "    Project: $PROJECT_NAME"
echo "    Dir:     $GHIDRA_PROJECTS"
echo ""

# Step 1: Headless import + analysis
echo "[1/2] Running headless analysis (this may take a while)..."
"$ANALYZE_HEADLESS" "$GHIDRA_PROJECTS" "$PROJECT_NAME" \
    -import "$BINARY_PATH" \
    -overwrite \
    -analysisTimeoutPerFile 300 2>&1

echo ""
echo "[2/2] Opening Ghidra GUI with project..."
echo "      The GhidraMCP HTTP bridge will be available on http://127.0.0.1:8080/"
echo ""

# Step 2: Open Ghidra GUI (so the GhidraMCP HTTP server plugin starts)
"$GHIDRA_RUN" "$GHIDRA_PROJECTS/${PROJECT_NAME}.gpr" &

echo "[*] Ghidra is starting. Once loaded, open the binary from the project."
echo "[*] The MCP bridge will be active on http://127.0.0.1:8080/"
echo "[*] You can now use Claude with both Ghidra and radare2 MCPs."
