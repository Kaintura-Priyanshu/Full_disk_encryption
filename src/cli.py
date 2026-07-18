"""
cli.py
------
Command-line interface for the educational FDE project.

Usage:
    python -m src.cli init      <container> --size-mb 10
    python -m src.cli add       <container> <file-to-add>
    python -m src.cli extract   <container> <name> --out <output-path>
    python -m src.cli list      <container>
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

from . import volume as vol


def _get_password(confirm: bool = False) -> str:
    pw = getpass.getpass("Password: ")
    if confirm:
        pw2 = getpass.getpass("Confirm password: ")
        if pw != pw2:
            print("Passwords did not match.", file=sys.stderr)
            sys.exit(1)
    return pw


def cmd_init(args: argparse.Namespace) -> None:
    password = _get_password(confirm=True)
    v = vol.Volume.create(args.container, password, args.size_mb)
    print(f"Created container '{args.container}' "
          f"({v.capacity_bytes() / (1024*1024):.2f} MiB usable).")
    v.close()


def cmd_add(args: argparse.Namespace) -> None:
    password = _get_password()
    try:
        with vol.Volume.open(args.container, password) as v:
            with open(args.file, "rb") as f:
                data = f.read()
            name = args.name or os.path.basename(args.file)
            v.add_file(name, data)
            print(f"Added '{name}' ({len(data)} bytes). "
                  f"Free space: {v.free_space_bytes()} bytes.")
    except vol.WrongPassword:
        print("Incorrect password.", file=sys.stderr)
        sys.exit(1)


def cmd_extract(args: argparse.Namespace) -> None:
    password = _get_password()
    try:
        with vol.Volume.open(args.container, password) as v:
            data = v.extract_file(args.name)
            out_path = args.out or args.name
            with open(out_path, "wb") as f:
                f.write(data)
            print(f"Extracted '{args.name}' -> '{out_path}' ({len(data)} bytes).")
    except vol.WrongPassword:
        print("Incorrect password.", file=sys.stderr)
        sys.exit(1)


def cmd_list(args: argparse.Namespace) -> None:
    password = _get_password()
    try:
        with vol.Volume.open(args.container, password) as v:
            entries = v.list_files()
            if not entries:
                print("(empty container)")
            for e in entries:
                print(f"{e.name:40s} {e.length:>10d} bytes")
            print(f"\nUsed:  {v.capacity_bytes() - v.free_space_bytes()} bytes")
            print(f"Free:  {v.free_space_bytes()} bytes")
    except vol.WrongPassword:
        print("Incorrect password.", file=sys.stderr)
        sys.exit(1)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pyfde", description="Educational full-disk-encryption container tool")
    sub = p.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Create a new encrypted container")
    p_init.add_argument("container", help="Path to the container file to create")
    p_init.add_argument("--size-mb", type=float, default=10.0, help="Container size in MiB (default: 10)")
    p_init.set_defaults(func=cmd_init)

    p_add = sub.add_parser("add", help="Add a file into the container")
    p_add.add_argument("container")
    p_add.add_argument("file", help="Path to the local file to encrypt and store")
    p_add.add_argument("--name", help="Name to store it under (default: original filename)")
    p_add.set_defaults(func=cmd_add)

    p_extract = sub.add_parser("extract", help="Extract a file from the container")
    p_extract.add_argument("container")
    p_extract.add_argument("name", help="Name of the file inside the container")
    p_extract.add_argument("--out", help="Output path (default: same as name)")
    p_extract.set_defaults(func=cmd_extract)

    p_list = sub.add_parser("list", help="List files stored in the container")
    p_list.add_argument("container")
    p_list.set_defaults(func=cmd_list)

    return p


def main(argv=None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
