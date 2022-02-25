import json
from typing import Tuple, List, Optional
import re


class Symbol:
    def __init__(self, symbol, location, size, source_path):
        self.symbol = symbol
        self.location = location
        self.size = size
        self.source_path = source_path
        self.source_file = source_path.split("/")[-1]


def parse_symbol(lines: List[str]) -> Optional[Symbol]:
    assert len(lines) > 0
    section = "\n".join(lines) + "\n"
    match = re.match(
        r" (\.[^\s]+)[\s\n]+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+([^\n]+)\n", section
    )
    if match is not None:
        symbol = match.group(1)
        location = match.group(2)
        size = match.group(3)
        source_file = match.group(4)
        return Symbol(symbol, int(location, 0), int(size, 0), source_file)
    return None


def read_symbol_table(map_file_contents: str) -> List[Symbol]:
    lines = map_file_contents.splitlines()
    symbol_table: List[Symbol] = []
    while len(lines):
        symbol_lines = []
        line = lines.pop(0)
        if line.startswith(" ."):
            symbol_lines.append(line)
            while len(lines):
                line = lines.pop(0)
                if line == "":
                    break
                elif line.startswith(" ."):
                    lines.insert(0, line)
                    break
                else:
                    symbol_lines.append(line)
            symbol = parse_symbol(symbol_lines)
            if symbol is not None:
                symbol_table.append(symbol)
    return symbol_table


def extract_source_file_data(symbol_table: List[Symbol]) -> list:
    source_map = {}
    for symbol in symbol_table:
        if symbol.size and symbol.location > 0x20000000:
            if symbol.source_file not in source_map:
                source_map[symbol.source_file] = {"total_size": 0}
            source_map[symbol.source_file]["total_size"] += symbol.size
            source_map[symbol.source_file][symbol.symbol] = symbol  # noqa
    source_file_data = list(source_map.items())
    source_file_data.sort(key=lambda x: x[1]["total_size"], reverse=True)
    return source_file_data


def main(map_file: str, threshold_bytes=None):
    if threshold_bytes is None:
        threshold_bytes = 128
    with open(map_file) as f:
        contents = f.read()
    symbol_table = read_symbol_table(contents)
    source_file_data = extract_source_file_data(symbol_table)

    print("==========================================")
    print("RAM usage summary")
    print("==========================================")
    print(f"Largest source files (threshold = {threshold_bytes} bytes)")
    total_size = 0
    total_memory = 96 * 1024

    for source_file, symbol_summary in source_file_data:
        if symbol_summary["total_size"] > threshold_bytes:
            print(f"{source_file}:  {symbol_summary['total_size']}")
            for key in symbol_summary:
                if key != "total_size":
                    symbol = symbol_summary[key]
                    print(f"  {symbol.symbol}:  {symbol.size}")
        total_size += symbol_summary["total_size"]
    print("")
    print(f"total usage: {total_size}")
    print(f"free memory: {total_memory - total_size}")


if __name__ == "__main__":
    import sys

    main(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else None)
