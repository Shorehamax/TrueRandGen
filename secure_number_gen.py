#!/usr/bin/env python3
"""
Secure Random CLI Generator

This tool uses Python's `secrets` module, which draws from the operating
system's cryptographically secure random source. It does NOT require access
to microphone, camera, location, or other permission-gated physical sensors.

Note:
- This is suitable for secure random generation in normal software usage.
- It is not a standalone physical TRNG. It relies on the OS CSPRNG.
"""

from __future__ import annotations

import argparse
import base64
import secrets
import string
import sys


BYTE_OPTIONS = [8, 16, 24, 32, 48, 64, 128]


def menu_choice(title: str, options: list[str]) -> int:
    while True:
        print(f"\n{title}")
        print("-" * len(title))
        for i, item in enumerate(options, start=1):
            print(f"{i}. {item}")
        raw = input("Select an option: ").strip()
        if raw.isdigit():
            idx = int(raw)
            if 1 <= idx <= len(options):
                return idx
        print("Invalid selection. Please enter a valid number.")


def ask_yes_no(prompt: str, default: bool = False) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    while True:
        raw = input(f"{prompt} {suffix}: ").strip().lower()
        if not raw:
            return default
        if raw in {"y", "yes"}:
            return True
        if raw in {"n", "no"}:
            return False
        print("Please answer y or n.")


def choose_byte_count() -> int:
    options = [f"{n} bytes" for n in BYTE_OPTIONS] + ["Custom byte count"]
    idx = menu_choice("Byte Length", options)

    if idx <= len(BYTE_OPTIONS):
        return BYTE_OPTIONS[idx - 1]

    while True:
        raw = input("Enter byte count (1-1048576): ").strip()
        if raw.isdigit():
            value = int(raw)
            if 1 <= value <= 1048576:
                return value
        print("Invalid byte count. Enter an integer from 1 to 1048576.")


def generate_bytes(n: int) -> bytes:
    return secrets.token_bytes(n)


def format_output(data: bytes, mode: str) -> str:
    if mode == "hex":
        return data.hex()
    if mode == "base64":
        return base64.b64encode(data).decode("ascii")
    if mode == "int":
        return str(int.from_bytes(data, "big"))
    if mode == "ascii":
        alphabet = string.ascii_letters + string.digits + string.punctuation
        return "".join(secrets.choice(alphabet) for _ in range(len(data)))
    raise ValueError(f"Unsupported mode: {mode}")


def print_summary(byte_count: int, mode: str, count: int) -> None:
    print("\nConfiguration")
    print("-------------")
    print(f"Byte count : {byte_count}")
    print(f"Format     : {mode}")
    print(f"How many   : {count}")


def interactive_mode() -> int:
    print("Secure Random CLI Generator")
    print("===========================")
    print("Source: Python secrets / OS cryptographic RNG")
    print("No microphone, camera, or other permission-gated physical entropy is used.")

    format_idx = menu_choice(
        "Output Format",
        [
            "Hex",
            "Base64",
            "Integer",
            "ASCII password-style string",
        ],
    )
    format_map = {
        1: "hex",
        2: "base64",
        3: "int",
        4: "ascii",
    }
    mode = format_map[format_idx]
    byte_count = choose_byte_count()

    while True:
        raw = input("How many values do you want to generate? (1-1000): ").strip()
        if raw.isdigit():
            count = int(raw)
            if 1 <= count <= 1000:
                break
        print("Invalid number. Enter an integer from 1 to 1000.")

    add_labels = ask_yes_no("Prefix each result with an index?", default=True)
    show_summary = ask_yes_no("Show configuration summary first?", default=True)

    if show_summary:
        print_summary(byte_count, mode, count)

    print("\nOutput")
    print("------")
    for i in range(1, count + 1):
        value = format_output(generate_bytes(byte_count), mode)
        if add_labels:
            print(f"{i:>3}: {value}")
        else:
            print(value)

    return 0


def cli_mode(args: argparse.Namespace) -> int:
    try:
        if not (1 <= args.bytes <= 1048576):
            raise ValueError("--bytes must be between 1 and 1048576")
        if not (1 <= args.count <= 1000):
            raise ValueError("--count must be between 1 and 1000")

        for i in range(1, args.count + 1):
            value = format_output(generate_bytes(args.bytes), args.format)
            if args.label:
                print(f"{i:>3}: {value}")
            else:
                print(value)

        return 0
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate secure random data using Python's secrets module."
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Launch the menu-driven interface.",
    )
    parser.add_argument(
        "--bytes",
        type=int,
        default=32,
        help="Number of random bytes per value. Default: 32",
    )
    parser.add_argument(
        "--format",
        choices=["hex", "base64", "int", "ascii"],
        default="hex",
        help="Output format. Default: hex",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=1,
        help="Number of values to generate. Default: 1",
    )
    parser.add_argument(
        "--label",
        action="store_true",
        help="Prefix each output with an index.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.interactive or len(sys.argv) == 1:
        return interactive_mode()

    return cli_mode(args)


if __name__ == "__main__":
    raise SystemExit(main())