"""Decode Objective-C protocol method lists from Mach-O binaries."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import struct
from typing import Any


class MachOObjCDecodeError(RuntimeError):
    """Raised when a Mach-O protocol method list cannot be decoded."""


@dataclass(frozen=True)
class _Section:
    sectname: str
    segname: str
    addr: int
    size: int
    offset: int


@dataclass
class _MachOImage:
    data: bytes
    slice_offset: int
    sections: list[_Section]
    image_base: int

    @classmethod
    def from_path(cls, path: Path, *, arch: str | None = None) -> "_MachOImage":
        data = path.read_bytes()
        slice_offset = _select_slice(data, arch=arch)
        sections = _parse_sections(data, slice_offset)
        if not sections:
            raise MachOObjCDecodeError(f"no sections found in Mach-O: {path}")
        image_base = min(section.addr for section in sections if section.addr) & ~0xFFFF_FFFF
        if not image_base:
            image_base = min(section.addr for section in sections if section.addr) & ~0xFFF
        return cls(data=data, slice_offset=slice_offset, sections=sections, image_base=image_base)

    def decode_method_list(self, address: int) -> list[dict[str, Any]]:
        offset = self.file_offset(address)
        entsize_and_flags, count = struct.unpack_from("<II", self.data, offset)
        entsize = entsize_and_flags & 0xFFFF
        if entsize <= 0:
            raise MachOObjCDecodeError(f"invalid method-list entry size at {address:#x}")
        relative = bool(entsize_and_flags & 0x8000_0000)
        methods: list[dict[str, Any]] = []
        for index in range(count):
            entry_address = address + 8 + index * entsize
            entry_offset = offset + 8 + index * entsize
            if relative:
                name_rel, types_rel, _imp_rel = struct.unpack_from("<iii", self.data, entry_offset)
                selector_ref_address = entry_address + name_rel
                type_encoding_address = entry_address + 4 + types_rel
                selector_pointer_raw = struct.unpack_from("<Q", self.data, self.file_offset(selector_ref_address))[0]
                selector_string_address = self.decode_pointer(selector_pointer_raw)
            else:
                selector_string_address, type_encoding_address, _imp = struct.unpack_from(
                    "<QQQ",
                    self.data,
                    entry_offset,
                )
                selector_ref_address = None
            methods.append(
                {
                    "selector": self.c_string(selector_string_address),
                    "type_encoding": self.c_string(type_encoding_address),
                    "method_list_address": f"{address:#x}",
                    "selector_ref_address": f"{selector_ref_address:#x}" if selector_ref_address is not None else None,
                    "selector_string_address": f"{selector_string_address:#x}",
                    "relative_method_list": relative,
                }
            )
        return methods

    def file_offset(self, address: int) -> int:
        for section in self.sections:
            if section.addr <= address < section.addr + section.size:
                return section.offset + (address - section.addr)
        raise MachOObjCDecodeError(f"virtual address not covered by sections: {address:#x}")

    def c_string(self, address: int) -> str:
        offset = self.file_offset(address)
        end = self.data.find(b"\0", offset, min(len(self.data), offset + 4096))
        if end < 0:
            end = min(len(self.data), offset + 4096)
        return self.data[offset:end].decode("utf-8", "replace")

    def decode_pointer(self, raw: int) -> int:
        if self._address_exists(raw):
            return raw
        candidates = []
        low32 = raw & 0xFFFF_FFFF
        if self.image_base:
            candidates.append(self.image_base + low32)
        low48 = raw & 0x0000_FFFF_FFFF_FFFF
        if self.image_base and low48 < self.image_base:
            candidates.append(self.image_base + low48)
        candidates.append(low48)
        for candidate in candidates:
            if self._address_exists(candidate):
                return candidate
        raise MachOObjCDecodeError(f"authenticated pointer target is outside known sections: {raw:#x}")

    def _address_exists(self, address: int) -> bool:
        try:
            self.file_offset(address)
        except MachOObjCDecodeError:
            return False
        return True


def decode_protocol_methods_from_macho(
    binary_path: str | Path,
    symbols_payload: dict[str, Any],
    interfaces: list[str],
    *,
    arch: str | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """Decode protocol instance methods for selected interfaces."""
    image = _MachOImage.from_path(Path(binary_path), arch=arch)
    decoded: dict[str, list[dict[str, Any]]] = {interface: [] for interface in interfaces}
    for interface in interfaces:
        for symbol in _protocol_method_symbols(symbols_payload, interface):
            address_text = str(symbol.get("address") or "")
            if not address_text or address_text.startswith("EXTERNAL"):
                continue
            try:
                address = int(address_text, 16)
            except ValueError:
                continue
            for method in image.decode_method_list(address):
                record = dict(method)
                record["source"] = "macho_protocol_method_list"
                record["method_list_symbol"] = symbol.get("name")
                decoded.setdefault(interface, []).append(record)
    return decoded


def _protocol_method_symbols(symbols_payload: dict[str, Any], interface: str) -> list[dict[str, Any]]:
    symbols = symbols_payload.get("symbols", []) if isinstance(symbols_payload, dict) else []
    hits = []
    for symbol in symbols if isinstance(symbols, list) else []:
        if not isinstance(symbol, dict):
            continue
        name = str(symbol.get("name") or symbol.get("label") or "")
        if "PROTOCOL_INSTANCE_METHODS" not in name:
            continue
        if _symbol_tail(name) == interface:
            hits.append(symbol)
    return hits


def _symbol_tail(name: str) -> str:
    tail = name.split("PROTOCOL_INSTANCE_METHODS", 1)[-1]
    return tail.lstrip("_$")


def _select_slice(data: bytes, *, arch: str | None) -> int:
    magic_be = int.from_bytes(data[:4], "big")
    if magic_be not in {0xCAFEBABE, 0xCAFEBABF}:
        return 0
    if magic_be == 0xCAFEBABF:
        raise MachOObjCDecodeError("64-bit fat Mach-O archives are not supported yet")
    count = int.from_bytes(data[4:8], "big")
    entries = []
    cursor = 8
    for _ in range(count):
        cputype = int.from_bytes(data[cursor : cursor + 4], "big", signed=True)
        cpusubtype = int.from_bytes(data[cursor + 4 : cursor + 8], "big", signed=True)
        offset = int.from_bytes(data[cursor + 8 : cursor + 12], "big")
        size = int.from_bytes(data[cursor + 12 : cursor + 16], "big")
        name = _arch_name(cputype, cpusubtype)
        entries.append({"name": name, "offset": offset, "size": size})
        cursor += 20
    if arch:
        for entry in entries:
            if entry["name"] == arch:
                return int(entry["offset"])
        raise MachOObjCDecodeError(f"architecture {arch!r} not found in fat Mach-O")
    for preferred in ("arm64e", "arm64", "x86_64"):
        for entry in entries:
            if entry["name"] == preferred:
                return int(entry["offset"])
    if not entries:
        raise MachOObjCDecodeError("fat Mach-O has no architecture entries")
    return int(entries[0]["offset"])


def _arch_name(cputype: int, cpusubtype: int) -> str:
    cpu = cputype & 0xFFFF_FFFF
    subtype = cpusubtype & 0x00FF_FFFF
    if cpu == 0x0100_000C:
        return "arm64e" if subtype == 2 else "arm64"
    if cpu == 0x0100_0007:
        return "x86_64"
    return f"cpu_{cpu:x}_{subtype:x}"


def _parse_sections(data: bytes, slice_offset: int) -> list[_Section]:
    magic = struct.unpack_from("<I", data, slice_offset)[0]
    if magic != 0xFEED_FACF:
        raise MachOObjCDecodeError(f"unsupported Mach-O magic at slice {slice_offset}: {magic:#x}")
    _magic, _cputype, _cpusubtype, _filetype, ncmds, _sizeofcmds, _flags, _reserved = struct.unpack_from(
        "<IiiIIIII",
        data,
        slice_offset,
    )
    cursor = slice_offset + 32
    sections: list[_Section] = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, cursor)
        if cmd == 0x19:  # LC_SEGMENT_64
            nsects = struct.unpack_from("<I", data, cursor + 64)[0]
            section_cursor = cursor + 72
            for _ in range(nsects):
                sectname = _fixed_string(data[section_cursor : section_cursor + 16])
                segname = _fixed_string(data[section_cursor + 16 : section_cursor + 32])
                addr, size = struct.unpack_from("<QQ", data, section_cursor + 32)
                fileoff = struct.unpack_from("<I", data, section_cursor + 48)[0]
                sections.append(
                    _Section(
                        sectname=sectname,
                        segname=segname,
                        addr=addr,
                        size=size,
                        offset=slice_offset + fileoff,
                    )
                )
                section_cursor += 80
        cursor += cmdsize
    return sections


def _fixed_string(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("utf-8", "replace")
