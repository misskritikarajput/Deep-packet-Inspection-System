#!/usr/bin/env bash
# Compiles the DPI Engine (no external dependencies, no Maven/Gradle required).
set -euo pipefail

SRC_DIR="src/main/java"
OUT_DIR="target/classes"

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

echo "Compiling Java sources..."
find "$SRC_DIR" -name "*.java" > /tmp/dpi_sources.txt
javac -d "$OUT_DIR" @/tmp/dpi_sources.txt
rm -f /tmp/dpi_sources.txt

echo "Build complete -> $OUT_DIR"

echo "Packaging runnable JAR..."
mkdir -p target
printf 'Main-Class: com.dpi.Main\n' > /tmp/dpi_manifest.mf
jar cfm target/dpi-engine.jar /tmp/dpi_manifest.mf -C "$OUT_DIR" .
rm -f /tmp/dpi_manifest.mf
echo "JAR created -> target/dpi-engine.jar"

echo ""
echo "Run the engine with:"
echo "  java -cp $OUT_DIR com.dpi.Main <input.pcap> <output.pcap> [options]"
echo "  or: java -jar target/dpi-engine.jar <input.pcap> <output.pcap> [options]"
echo ""
echo "Generate a test capture with:"
echo "  java -cp $OUT_DIR com.dpi.tools.GenerateTestPcap test_dpi.pcap"
