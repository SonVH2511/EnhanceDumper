#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IDA plugin: SP Dump Helper Radio UI

Hotkey:
    Ctrl+D

Ctrl+D opens a real Qt radio-button dialog:
    - Dump ASM of current/selected function
    - Dump BIN bytes from address + size
    - Dump PE from base/MZ address as raw/on-disk or image/memory layout
      with PE32/PE32+ arch detection; raw/image dump sizes are header-derived only
      and default output extension is selected from PE format/type

Install:
    1. Close IDA.
    2. Remove/rename old copies of this plugin from IDA/plugins.
    3. Copy this file into IDA/plugins.
    4. Start IDA and press Ctrl+D.
"""

from __future__ import annotations

import os
import re
import struct
from typing import Iterable, List, Optional, Tuple

import ida_bytes
import ida_funcs
import ida_gdl
import ida_idaapi
import ida_kernwin
import ida_nalt
import ida_segment
import idc

VERSION = "1.3"
PLUGIN_TAG = "sp_dump_helper_radio"
MAX_DUMP_SIZE = 512 * 1024 * 1024


# ---------------------------------------------------------------------------
# Common helpers
# ---------------------------------------------------------------------------


def _msg(text: str) -> None:
    ida_kernwin.msg(f"[{PLUGIN_TAG} {VERSION}] {text}\n")


def _warn(text: str) -> None:
    ida_kernwin.warning(f"[{PLUGIN_TAG}] {text}")


def _input_dir() -> str:
    try:
        path = ida_nalt.get_input_file_path()
        if path:
            folder = os.path.dirname(path)
            if folder:
                return folder
    except Exception:
        pass
    return os.getcwd()


def _sanitize_filename(name: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in name)


def _fmt_ea(ea: int) -> str:
    if ea < 0:
        return f"-0x{-ea:X}"
    return f"0x{ea:X}"


def _parse_hexish(text: str) -> int:
    """Parse IDA-style numbers: 401000, 0x401000, 401000h, $401000, or name."""
    s = (text or "").strip().replace("_", "")
    if not s:
        raise ValueError("empty number")

    # Name/symbol support first, but only when it is not clearly numeric.
    if not re.fullmatch(r"[+$\-]?(?:0x|\$)?[0-9a-fA-F]+h?", s):
        try:
            ea = idc.get_name_ea_simple(s)
            if ea != idc.BADADDR:
                return int(ea)
        except Exception:
            pass

    neg = False
    if s.startswith("-"):
        neg = True
        s = s[1:]
    if s.startswith("+"):
        s = s[1:]

    base = 16
    if s.lower().startswith("0x"):
        s = s[2:]
        base = 16
    elif s.startswith("$"):
        s = s[1:]
        base = 16
    elif s.lower().endswith("h"):
        s = s[:-1]
        base = 16
    elif s.lower().endswith("d"):
        s = s[:-1]
        base = 10

    value = int(s, base)
    return -value if neg else value


def _ensure_reasonable_size(size: int, what: str) -> None:
    if size <= 0:
        raise ValueError(f"{what} size is invalid: {size:#x}")
    if size > MAX_DUMP_SIZE:
        raise ValueError(f"{what} size {size:#x} exceeds MAX_DUMP_SIZE {MAX_DUMP_SIZE:#x}")


def _read_bytes_strict(ea: int, size: int) -> bytes:
    _ensure_reasonable_size(size, "strict read")
    data = ida_bytes.get_bytes(ea, size)
    if data is None or len(data) != size:
        got = "None" if data is None else f"{len(data):#x} bytes"
        raise ValueError(f"ida_bytes.get_bytes({ea:#x}, {size:#x}) failed, got {got}")
    return bytes(data)


def _copy_sparse_chunk(dst: bytearray, dst_off: int, ea: int, size: int, fill: int = 0) -> None:
    """Copy bytes from IDB into dst. Missing/unloaded bytes stay as fill."""
    pos = 0
    while pos < size:
        chunk_size = min(0x10000, size - pos)
        cur = ea + pos
        data = ida_bytes.get_bytes(cur, chunk_size)
        if data is not None and len(data) == chunk_size:
            dst[dst_off + pos:dst_off + pos + chunk_size] = data
        else:
            for i in range(chunk_size):
                cur_ea = cur + i
                try:
                    if hasattr(ida_bytes, "is_loaded") and not ida_bytes.is_loaded(cur_ea):
                        continue
                    dst[dst_off + pos + i] = ida_bytes.get_byte(cur_ea) & 0xFF
                except Exception:
                    dst[dst_off + pos + i] = fill
        pos += chunk_size


def _read_bytes_sparse(ea: int, size: int, fill: int = 0) -> bytes:
    """Read a potentially sparse image range. Unmapped gaps become fill bytes."""
    _ensure_reasonable_size(size, "sparse read")
    out = bytearray([fill]) * size
    start = ea
    end = ea + size
    copied_any = False

    try:
        for idx in range(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(idx)
            if not seg:
                continue
            a = max(start, int(seg.start_ea))
            b = min(end, int(seg.end_ea))
            if a >= b:
                continue
            _copy_sparse_chunk(out, a - start, a, b - a, fill=fill)
            copied_any = True
    except Exception:
        copied_any = False

    if not copied_any:
        _copy_sparse_chunk(out, 0, ea, size, fill=fill)

    return bytes(out)


def _load_qt_widgets():
    """Return QtWidgets module. IDA versions differ, so try common bindings."""
    errors = []
    for modname in ("PyQt5", "PySide6", "PyQt6", "PySide2"):
        try:
            if modname == "PyQt5":
                from PyQt5 import QtWidgets  # type: ignore
                return QtWidgets
            if modname == "PySide6":
                from PySide6 import QtWidgets  # type: ignore
                return QtWidgets
            if modname == "PyQt6":
                from PyQt6 import QtWidgets  # type: ignore
                return QtWidgets
            if modname == "PySide2":
                from PySide2 import QtWidgets  # type: ignore
                return QtWidgets
        except Exception as exc:
            errors.append(f"{modname}: {type(exc).__name__}: {exc}")
    raise RuntimeError("Qt binding not available: " + "; ".join(errors))


def _qt_exec_dialog(dlg) -> int:
    if hasattr(dlg, "exec_"):
        return int(dlg.exec_())
    return int(dlg.exec())


def _ask_save_path_qt(default_name: str, title: str) -> Optional[str]:
    default_path = os.path.join(_input_dir(), default_name)
    try:
        QtWidgets = _load_qt_widgets()
        result = QtWidgets.QFileDialog.getSaveFileName(None, title, default_path, "All files (*)")
        if isinstance(result, tuple):
            path = result[0]
        else:
            path = result
        if path:
            return os.path.abspath(path)
    except Exception:
        pass

    # File dialog fallback only; not used for choosing mode/options.
    path = ida_kernwin.ask_file(True, default_name, title)
    if path:
        return os.path.abspath(path)
    return None


# ---------------------------------------------------------------------------
# ASM dump: original behavior, current-function default
# ---------------------------------------------------------------------------


def _asm_operand_text(ea: int) -> str:
    ops: List[str] = []
    for idx in range(8):
        text = idc.print_operand(ea, idx)
        if not text:
            break
        ops.append(text)
    return ", ".join(ops)


def _render_insn_lines(ea: int, include_bytes: bool = False) -> List[str]:
    lines: List[str] = []
    label = idc.get_name(ea)
    if label:
        lines.append(f"{label}:")
    mnem = idc.print_insn_mnem(ea)
    ops = _asm_operand_text(ea)
    insn = f"{mnem} {ops}".rstrip()
    if include_bytes:
        data = idc.get_bytes(ea, idc.get_item_size(ea)) or b""
        hex_bytes = " ".join(f"{b:02X}" for b in data)
        lines.append(f"    {ea:08X}: {hex_bytes:<24} {insn}")
    else:
        lines.append(f"    {insn}")
    return lines


def _iter_func_chunks(func) -> Iterable[Tuple[int, int]]:
    yield func.start_ea, func.end_ea
    it = ida_funcs.func_tail_iterator_t(func)
    ok = it.first()
    seen = {(func.start_ea, func.end_ea)}
    while ok:
        chunk = it.chunk()
        pair = (chunk.start_ea, chunk.end_ea)
        if pair not in seen:
            seen.add(pair)
            yield pair
        ok = it.next()


def _iter_defined_heads(start_ea: int, end_ea: int) -> Iterable[int]:
    ea = start_ea
    while ea != idc.BADADDR and ea < end_ea:
        flags = idc.get_full_flags(ea)
        if idc.is_code(flags):
            yield ea
            size = max(idc.get_item_size(ea), 1)
            ea += size
            continue
        ea = idc.next_head(ea, end_ea)


def _render_chunk_dump(func, include_bytes: bool = False) -> str:
    lines = [
        f"; FUNCTION {idc.get_func_name(func.start_ea)} @ {func.start_ea:#x}",
        "",
    ]
    for idx, (start_ea, end_ea) in enumerate(sorted(_iter_func_chunks(func)), 1):
        if idx > 1:
            lines.append("")
            lines.append("")
        for ea in _iter_defined_heads(start_ea, end_ea):
            lines.extend(_render_insn_lines(ea, include_bytes=include_bytes))
    return "\n".join(lines)


def _block_sort_key(block) -> Tuple[int, int]:
    return block.start_ea, block.end_ea


def _render_block_dump(func, include_bytes: bool = False) -> str:
    lines = [
        f"; FUNCTION {idc.get_func_name(func.start_ea)} @ {func.start_ea:#x}",
        "",
    ]
    flow = ida_gdl.FlowChart(func)
    blocks = sorted(list(flow), key=_block_sort_key)
    for idx, block in enumerate(blocks, 1):
        if idx > 1:
            lines.append("")
            lines.append("")
        for ea in _iter_defined_heads(block.start_ea, block.end_ea):
            lines.extend(_render_insn_lines(ea, include_bytes=include_bytes))
    return "\n".join(lines)


def dump_function_asm(func_ea: int, mode: str = "blocks", include_bytes: bool = False) -> str:
    func = ida_funcs.get_func(func_ea)
    if not func:
        raise ValueError(f"no function at {func_ea:#x}")
    mode = mode.lower().strip()
    if mode == "chunks":
        return _render_chunk_dump(func, include_bytes=include_bytes)
    if mode == "blocks":
        return _render_block_dump(func, include_bytes=include_bytes)
    raise ValueError("mode must be 'chunks' or 'blocks'")


def _safe_func_filename(func) -> str:
    func_name = idc.get_func_name(func.start_ea) or f"sub_{func.start_ea:X}"
    safe_name = _sanitize_filename(func_name)
    return f"{safe_name}_{func.start_ea:08X}.asm"


def save_function_dump(func_addr: int) -> Optional[str]:
    func = ida_funcs.get_func(func_addr)
    if not func:
        raise ValueError(f"No function at or containing {func_addr:#x}")

    if func_addr != func.start_ea:
        _msg(f"using containing function start {func.start_ea:#x} instead of {func_addr:#x}")

    default_name = _safe_func_filename(func)
    out_path = _ask_save_path_qt(default_name, "Save function ASM dump as")
    if not out_path:
        return None

    text = dump_function_asm(func.start_ea, mode="blocks", include_bytes=False)
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
        fh.write("\n")

    _msg(f"ASM dump wrote {out_path}")
    ida_kernwin.info(f"Dumped {idc.get_func_name(func.start_ea)} to:\n{out_path}")
    return out_path


# ---------------------------------------------------------------------------
# BIN dump
# ---------------------------------------------------------------------------


def dump_bin(addr: int, size: int) -> Optional[str]:
    _ensure_reasonable_size(size, "BIN dump")
    default_name = f"dump_{addr:X}_{size:X}.bin"
    out_path = _ask_save_path_qt(default_name, "Save BIN dump as")
    if not out_path:
        return None

    data = _read_bytes_strict(addr, size)
    with open(out_path, "wb") as fh:
        fh.write(data)

    _msg(f"BIN dump wrote {len(data):#x} bytes from {addr:#x} -> {out_path}")
    ida_kernwin.info(f"Dumped {len(data):#x} bytes from {addr:#x} to:\n{out_path}")
    return out_path


# ---------------------------------------------------------------------------
# PE dump
# ---------------------------------------------------------------------------


class PESection(object):
    def __init__(self, name: str, virtual_size: int, virtual_address: int, raw_size: int, raw_ptr: int):
        self.name = name
        self.virtual_size = virtual_size
        self.virtual_address = virtual_address
        self.raw_size = raw_size
        self.raw_ptr = raw_ptr


class PEInfo(object):
    def __init__(
        self,
        base_ea: int,
        e_lfanew: int,
        machine: int,
        characteristics: int,
        optional_magic: int,
        subsystem: int,
        dll_characteristics: int,
        number_of_sections: int,
        size_of_optional_header: int,
        is_pe64: bool,
        image_base: int,
        entry_rva: int,
        size_of_image: int,
        size_of_headers: int,
        min_headers_size: int,
        sections: List[PESection],
    ):
        self.base_ea = base_ea
        self.e_lfanew = e_lfanew
        self.machine = machine
        self.characteristics = characteristics
        self.optional_magic = optional_magic
        self.subsystem = subsystem
        self.dll_characteristics = dll_characteristics
        self.number_of_sections = number_of_sections
        self.size_of_optional_header = size_of_optional_header
        self.is_pe64 = is_pe64
        self.image_base = image_base
        self.entry_rva = entry_rva
        self.size_of_image = size_of_image
        self.size_of_headers = size_of_headers
        self.min_headers_size = min_headers_size
        self.sections = sections


MACHINE_NAMES = {
    0x014C: "I386/x86",
    0x0200: "IA64",
    0x01C0: "ARM",
    0x01C4: "ARMv7",
    0xAA64: "ARM64",
    0x8664: "AMD64/x64",
}

SUBSYSTEM_NAMES = {
    0: "UNKNOWN",
    1: "NATIVE",
    2: "WINDOWS_GUI",
    3: "WINDOWS_CUI",
    5: "OS2_CUI",
    7: "POSIX_CUI",
    8: "NATIVE_WINDOWS",
    9: "WINDOWS_CE_GUI",
    10: "EFI_APPLICATION",
    11: "EFI_BOOT_SERVICE_DRIVER",
    12: "EFI_RUNTIME_DRIVER",
    13: "EFI_ROM",
    14: "XBOX",
    16: "WINDOWS_BOOT_APPLICATION",
}

IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
IMAGE_FILE_DLL = 0x2000


def _u16(buf: bytes, off: int) -> int:
    return struct.unpack_from("<H", buf, off)[0]


def _u32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def _u64(buf: bytes, off: int) -> int:
    return struct.unpack_from("<Q", buf, off)[0]


def _machine_name(machine: int) -> str:
    return MACHINE_NAMES.get(machine, f"unknown-{machine:#x}")


def _subsystem_name(subsystem: int) -> str:
    return SUBSYSTEM_NAMES.get(subsystem, f"UNKNOWN_{subsystem:#x}")


def _pe_kind_label(pe: PEInfo) -> str:
    """Return a practical PE kind for file naming/reporting.

    This is a header-based classification only. It does not inspect exports,
    resources, signatures, or repair anything. CPL/SCR/etc. can be normal
    GUI EXEs at header level, so they intentionally remain EXE unless a
    stronger header signal exists.
    """
    if pe.characteristics & IMAGE_FILE_DLL:
        return "dll"
    if pe.subsystem in (10, 11, 12, 13):
        return "efi"
    if pe.subsystem == 1:
        return "sys"
    if pe.subsystem == 16:
        return "bootapp"
    if pe.subsystem in (2, 3, 5, 7, 8, 9, 14):
        return "exe"
    return "pe"


def _pe_kind_description(pe: PEInfo) -> str:
    kind = _pe_kind_label(pe)
    descriptions = {
        "dll": "DLL image",
        "sys": "Native/driver-style image",
        "efi": "EFI image",
        "bootapp": "Windows boot application",
        "exe": "Executable image",
        "pe": "PE image",
    }
    return descriptions.get(kind, "PE image")


def _pe_raw_default_extension(pe: PEInfo) -> str:
    kind = _pe_kind_label(pe)
    if kind in ("dll", "sys", "efi", "exe"):
        return kind
    if kind == "bootapp":
        return "efi"
    return "pe"


def _pe_output_extension(pe: PEInfo, dump_mode: str) -> str:
    raw_ext = _pe_raw_default_extension(pe)
    if dump_mode == "raw":
        return raw_ext
    # Image-layout dumps are memory-layout byte dumps, not normal on-disk files.
    # Keep the PE kind visible, but avoid pretending the output is directly an EXE.
    return f"{raw_ext}.image.bin"


def _pe_arch_label(pe: PEInfo) -> str:
    # This is intentionally derived from the PE being dumped, not from the
    # current IDB/process bitness. A 32-bit loader can carry a 64-bit PE and
    # a 64-bit IDB can carry a 32-bit PE.
    return "x64" if pe.is_pe64 else "x86"


def _pe_magic_label(pe: PEInfo) -> str:
    if pe.optional_magic == 0x10B:
        return "PE32"
    if pe.optional_magic == 0x20B:
        return "PE32+"
    return f"magic-{pe.optional_magic:#x}"


def _pe_consistency_warnings(pe: PEInfo) -> List[str]:
    warnings: List[str] = []
    if pe.machine == 0x014C and pe.is_pe64:
        warnings.append("Machine is I386/x86 but OptionalHeader.Magic is PE32+")
    if pe.machine in (0x8664, 0xAA64, 0x0200) and not pe.is_pe64:
        warnings.append(f"Machine is {_machine_name(pe.machine)} but OptionalHeader.Magic is PE32")
    if not (pe.characteristics & IMAGE_FILE_EXECUTABLE_IMAGE):
        warnings.append(f"Characteristics does not include EXECUTABLE_IMAGE: {pe.characteristics:#x}")
    if pe.entry_rva and pe.entry_rva >= pe.size_of_image:
        warnings.append(f"EntryRVA {pe.entry_rva:#x} is outside SizeOfImage {pe.size_of_image:#x}")
    if pe.size_of_headers < pe.min_headers_size:
        warnings.append(
            f"SizeOfHeaders {pe.size_of_headers:#x} is smaller than NT+section headers {pe.min_headers_size:#x}"
        )
    return warnings


def parse_pe_at(base_ea: int) -> PEInfo:
    dos = _read_bytes_strict(base_ea, 0x40)
    if dos[:2] != b"MZ":
        raise ValueError(f"No MZ signature at {base_ea:#x}")

    e_lfanew = _u32(dos, 0x3C)
    if e_lfanew < 0x40 or e_lfanew > 0x100000:
        raise ValueError(f"Suspicious e_lfanew: {e_lfanew:#x}")

    nt = _read_bytes_strict(base_ea + e_lfanew, 0x18)
    if nt[:4] != b"PE\x00\x00":
        raise ValueError(f"No PE signature at {base_ea + e_lfanew:#x}")

    machine = _u16(nt, 0x04)
    number_of_sections = _u16(nt, 0x06)
    size_of_optional_header = _u16(nt, 0x14)
    characteristics = _u16(nt, 0x16)
    if number_of_sections <= 0 or number_of_sections > 96:
        raise ValueError(f"Suspicious section count: {number_of_sections}")
    if size_of_optional_header < 0x60 or size_of_optional_header > 0x1000:
        raise ValueError(f"Suspicious optional header size: {size_of_optional_header:#x}")

    opt_ea = base_ea + e_lfanew + 0x18
    opt = _read_bytes_strict(opt_ea, size_of_optional_header)
    optional_magic = _u16(opt, 0x00)
    if optional_magic == 0x10B:
        is_pe64 = False
        image_base = _u32(opt, 0x1C)
    elif optional_magic == 0x20B:
        is_pe64 = True
        image_base = _u64(opt, 0x18)
    else:
        raise ValueError(f"Unsupported PE optional header magic: {optional_magic:#x}")

    entry_rva = _u32(opt, 0x10)
    size_of_image = _u32(opt, 0x38)
    size_of_headers = _u32(opt, 0x3C)
    subsystem = _u16(opt, 0x44) if len(opt) >= 0x46 else 0
    dll_characteristics = _u16(opt, 0x46) if len(opt) >= 0x48 else 0
    _ensure_reasonable_size(size_of_image, "PE SizeOfImage")
    _ensure_reasonable_size(size_of_headers, "PE SizeOfHeaders")

    sec_ea = opt_ea + size_of_optional_header
    sec_blob_size = number_of_sections * 0x28
    sec_blob = _read_bytes_strict(sec_ea, sec_blob_size)
    min_headers_size = e_lfanew + 0x18 + size_of_optional_header + sec_blob_size

    sections: List[PESection] = []
    for idx in range(number_of_sections):
        off = idx * 0x28
        raw_name = sec_blob[off:off + 8].split(b"\x00", 1)[0]
        try:
            name = raw_name.decode("ascii", errors="replace")
        except Exception:
            name = repr(raw_name)
        virtual_size = _u32(sec_blob, off + 0x08)
        virtual_address = _u32(sec_blob, off + 0x0C)
        raw_size = _u32(sec_blob, off + 0x10)
        raw_ptr = _u32(sec_blob, off + 0x14)
        sections.append(PESection(name, virtual_size, virtual_address, raw_size, raw_ptr))

    pe = PEInfo(
        base_ea=base_ea,
        e_lfanew=e_lfanew,
        machine=machine,
        characteristics=characteristics,
        optional_magic=optional_magic,
        subsystem=subsystem,
        dll_characteristics=dll_characteristics,
        number_of_sections=number_of_sections,
        size_of_optional_header=size_of_optional_header,
        is_pe64=is_pe64,
        image_base=image_base,
        entry_rva=entry_rva,
        size_of_image=size_of_image,
        size_of_headers=size_of_headers,
        min_headers_size=min_headers_size,
        sections=sections,
    )

    _msg(
        "PE header: "
        f"{_pe_arch_label(pe)} / {_pe_magic_label(pe)}, "
        f"Machine={_machine_name(pe.machine)}, "
        f"Kind={_pe_kind_label(pe)}, Subsystem={_subsystem_name(pe.subsystem)}, "
        f"ImageBase={pe.image_base:#x}, EntryRVA={pe.entry_rva:#x}, "
        f"SizeOfImage={pe.size_of_image:#x}, Sections={len(pe.sections)}"
    )
    for warning in _pe_consistency_warnings(pe):
        _msg(f"PE warning: {warning}")

    return pe


def _pe_raw_dump_size(pe: PEInfo) -> int:
    """Return the byte count for a raw/on-disk PE dump.

    This function only computes size from headers. It does not rebuild, fix,
    remap, or convert the PE. Raw dump mode later copies this many bytes
    directly from base_ea.
    """
    file_size = pe.size_of_headers
    for sec in pe.sections:
        if sec.raw_size and sec.raw_ptr:
            file_size = max(file_size, sec.raw_ptr + sec.raw_size)
    _ensure_reasonable_size(file_size, "raw PE dump")
    return file_size


def _validate_dumped_pe_buffer(data: bytes, pe: PEInfo, dump_mode: str) -> List[str]:
    warnings: List[str] = []
    if len(data) < 0x40:
        warnings.append(f"dump is too small for DOS header: {len(data):#x}")
        return warnings

    if data[:2] != b"MZ":
        warnings.append("dump does not start with MZ")
        return warnings

    try:
        e_lfanew = _u32(data, 0x3C)
        if e_lfanew + 4 > len(data):
            warnings.append(f"dump e_lfanew points outside dumped bytes: {e_lfanew:#x}")
        elif data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            warnings.append(f"dump has no PE signature at e_lfanew={e_lfanew:#x}")
    except Exception as exc:
        warnings.append(f"could not validate dumped PE header: {type(exc).__name__}: {exc}")

    if dump_mode == "raw":
        expected = _pe_raw_dump_size(pe)
        if len(data) != expected:
            warnings.append(f"raw dump size {len(data):#x} != computed raw size {expected:#x}")
    elif dump_mode == "image":
        if len(data) != pe.size_of_image:
            warnings.append(f"image dump size {len(data):#x} != SizeOfImage {pe.size_of_image:#x}")
        if pe.entry_rva and pe.entry_rva >= len(data):
            warnings.append(f"EntryRVA {pe.entry_rva:#x} outside image dump {len(data):#x}")

    return warnings


def dump_pe_image(base_ea: int, out_path: str) -> str:
    pe = parse_pe_at(base_ea)

    # Size-only dump: do not reconstruct/remap sections. Image mode means
    # "dump SizeOfImage bytes starting at base/MZ". Sparse gaps are zero-filled
    # only because IDA may not have every byte loaded in the database.
    data = _read_bytes_sparse(base_ea, pe.size_of_image, fill=0)

    warnings = _validate_dumped_pe_buffer(data, pe, "image")
    for warning in warnings:
        _msg(f"image dump warning: {warning}")

    with open(out_path, "wb") as fh:
        fh.write(data)

    _msg(
        f"PE image dump wrote {len(data):#x} bytes from {base_ea:#x}; "
        f"SizeOfImage={pe.size_of_image:#x}, arch={_pe_arch_label(pe)}"
    )
    return out_path


def dump_pe_raw(base_ea: int, out_path: str) -> str:
    pe = parse_pe_at(base_ea)
    dump_size = _pe_raw_dump_size(pe)

    # Size-only dump: do not reconstruct/remap sections. Raw mode means
    # "dump computed raw file size bytes starting at base/MZ".
    data = _read_bytes_sparse(base_ea, dump_size, fill=0)

    warnings = _validate_dumped_pe_buffer(data, pe, "raw")
    for warning in warnings:
        _msg(f"raw dump warning: {warning}")

    with open(out_path, "wb") as fh:
        fh.write(data)

    _msg(
        f"PE raw dump wrote {len(data):#x} bytes from {base_ea:#x}; "
        f"computed raw size={dump_size:#x}, arch={_pe_arch_label(pe)}"
    )
    return out_path


def dump_pe(base_ea: int, pe_mode: str) -> Optional[str]:
    pe_mode = pe_mode.lower().strip()
    if pe_mode not in ("raw", "image"):
        raise ValueError("PE dump mode must be raw or image")

    pe = parse_pe_at(base_ea)
    bitness = _pe_arch_label(pe)
    raw_size = _pe_raw_dump_size(pe)
    dump_size = raw_size if pe_mode == "raw" else pe.size_of_image

    ext = _pe_output_extension(pe, pe_mode)
    kind = _pe_kind_label(pe)
    default_name = f"dump_pe_{base_ea:X}_{bitness}_{kind}_{pe_mode}_{dump_size:X}.{ext}"
    out_path = _ask_save_path_qt(default_name, f"Save PE {pe_mode} dump as")
    if not out_path:
        return None

    if pe_mode == "raw":
        data = _read_bytes_sparse(base_ea, raw_size, fill=0)
    else:
        data = _read_bytes_sparse(base_ea, pe.size_of_image, fill=0)

    warnings = _validate_dumped_pe_buffer(data, pe, pe_mode)
    for warning in warnings:
        _msg(f"PE dump warning: {warning}")

    with open(out_path, "wb") as fh:
        fh.write(data)

    warning_text = ""
    all_warnings = _pe_consistency_warnings(pe) + warnings
    if all_warnings:
        warning_text = "\n\nWarnings:\n" + "\n".join(f"- {w}" for w in all_warnings)

    ida_kernwin.info(
        f"Dumped PE {pe_mode} from {base_ea:#x} to:\n{out_path}\n\n"
        f"Mode: size-only dump; no rebuild/remap/fix\n"
        f"PE arch: {bitness} / {_pe_magic_label(pe)}\n"
        f"PE type: {_pe_kind_description(pe)} ({_pe_kind_label(pe)})\n"
        f"Machine: {_machine_name(pe.machine)} ({pe.machine:#x})\n"
        f"Characteristics: {pe.characteristics:#x}\n"
        f"Subsystem: {_subsystem_name(pe.subsystem)} ({pe.subsystem:#x})\n"
        f"DllCharacteristics: {pe.dll_characteristics:#x}\n"
        f"ImageBase(header): {pe.image_base:#x}\n"
        f"EntryRVA: {pe.entry_rva:#x}\n"
        f"SizeOfHeaders: {pe.size_of_headers:#x}\n"
        f"Computed raw dump size: {raw_size:#x}\n"
        f"SizeOfImage: {pe.size_of_image:#x}\n"
        f"Selected dump size: {len(data):#x}\n"
        f"Sections: {len(pe.sections)}"
        f"{warning_text}"
    )
    return out_path


# ---------------------------------------------------------------------------
# Defaults and radio option dialog
# ---------------------------------------------------------------------------


def _has_mz(ea: int) -> bool:
    try:
        return ida_bytes.get_bytes(ea, 2) == b"MZ"
    except Exception:
        return False


def _default_imagebase() -> int:
    try:
        return int(ida_nalt.get_imagebase())
    except Exception:
        pass
    try:
        return int(idc.get_imagebase())
    except Exception:
        pass
    return idc.here()


def _default_pe_base(cur: int) -> int:
    if _has_mz(cur):
        return cur
    try:
        seg = ida_segment.getseg(cur)
        if seg and _has_mz(int(seg.start_ea)):
            return int(seg.start_ea)
    except Exception:
        pass

    ib = _default_imagebase()
    if _has_mz(ib):
        return ib

    try:
        for idx in range(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(idx)
            if seg and _has_mz(int(seg.start_ea)):
                return int(seg.start_ea)
    except Exception:
        pass

    return cur


def _current_func_default(cur: int) -> int:
    func = ida_funcs.get_func(cur)
    return int(func.start_ea) if func else cur


def _ask_dump_options_radio() -> Optional[dict]:
    """Qt radio dialog. No ask_str/number mode fallback by design."""
    try:
        QtWidgets = _load_qt_widgets()
    except Exception as exc:
        _warn(f"Qt radio dialog unavailable: {exc}")
        return None

    cur = int(idc.here())
    func_default = _current_func_default(cur)
    bin_default = cur
    pe_default = _default_pe_base(cur)

    dlg = QtWidgets.QDialog()
    dlg.setWindowTitle(f"Dumper Enhanced - {VERSION}")
    dlg.setMinimumWidth(620)

    root = QtWidgets.QVBoxLayout(dlg)

    mode_group = QtWidgets.QGroupBox("Ctrl+D dump mode")
    mode_layout = QtWidgets.QVBoxLayout(mode_group)
    rb_asm = QtWidgets.QRadioButton("Dump ASM of current function")
    rb_bin = QtWidgets.QRadioButton("Dump BIN bytes from address + size")
    rb_pe = QtWidgets.QRadioButton("Dump PE from base/MZ address")
    rb_asm.setChecked(True)
    for rb in (rb_asm, rb_bin, rb_pe):
        mode_layout.addWidget(rb)
    root.addWidget(mode_group)

    grid = QtWidgets.QGridLayout()
    row = 0
    grid.addWidget(QtWidgets.QLabel("Function address:"), row, 0)
    edit_func = QtWidgets.QLineEdit(_fmt_ea(func_default))
    grid.addWidget(edit_func, row, 1)
    row += 1

    grid.addWidget(QtWidgets.QLabel("BIN address:"), row, 0)
    edit_bin_addr = QtWidgets.QLineEdit(_fmt_ea(bin_default))
    grid.addWidget(edit_bin_addr, row, 1)
    row += 1

    grid.addWidget(QtWidgets.QLabel("BIN size:"), row, 0)
    edit_bin_size = QtWidgets.QLineEdit("0x1000")
    grid.addWidget(edit_bin_size, row, 1)
    row += 1

    grid.addWidget(QtWidgets.QLabel("PE base / MZ address:"), row, 0)
    edit_pe_base = QtWidgets.QLineEdit(_fmt_ea(pe_default))
    grid.addWidget(edit_pe_base, row, 1)
    row += 1

    pe_mode_group = QtWidgets.QGroupBox("PE dump size / format")
    pe_mode_layout = QtWidgets.QHBoxLayout(pe_mode_group)
    rb_pe_raw = QtWidgets.QRadioButton("Raw / on-disk size: dump computed raw file size from base")
    rb_pe_image = QtWidgets.QRadioButton("Image / memory size: dump SizeOfImage from base")
    rb_pe_raw.setChecked(True)
    pe_mode_layout.addWidget(rb_pe_raw)
    pe_mode_layout.addWidget(rb_pe_image)
    grid.addWidget(pe_mode_group, row, 0, 1, 2)
    row += 1

    root.addLayout(grid)

    hint = QtWidgets.QLabel("Addresses accept IDA-style hex, e.g. 0x60160, 60160h, or symbol names.")
    root.addWidget(hint)

    btn_row = QtWidgets.QHBoxLayout()
    btn_row.addStretch(1)
    ok_btn = QtWidgets.QPushButton("OK")
    cancel_btn = QtWidgets.QPushButton("Cancel")
    btn_row.addWidget(ok_btn)
    btn_row.addWidget(cancel_btn)
    root.addLayout(btn_row)

    result_holder = {"data": None}

    def set_enabled():
        is_asm = rb_asm.isChecked()
        is_bin = rb_bin.isChecked()
        is_pe = rb_pe.isChecked()
        edit_func.setEnabled(is_asm)
        edit_bin_addr.setEnabled(is_bin)
        edit_bin_size.setEnabled(is_bin)
        edit_pe_base.setEnabled(is_pe)
        pe_mode_group.setEnabled(is_pe)

    def show_error(message: str) -> None:
        try:
            QtWidgets.QMessageBox.warning(dlg, "SP Dump Helper", message)
        except Exception:
            _warn(message)

    def on_ok() -> None:
        try:
            if rb_asm.isChecked():
                func_addr = _parse_hexish(edit_func.text())
                if func_addr == idc.BADADDR:
                    raise ValueError("bad function address")
                result_holder["data"] = {"mode": "asm", "func_addr": func_addr}
            elif rb_bin.isChecked():
                addr = _parse_hexish(edit_bin_addr.text())
                size = _parse_hexish(edit_bin_size.text())
                _ensure_reasonable_size(size, "BIN dump")
                result_holder["data"] = {"mode": "bin", "addr": addr, "size": size}
            else:
                base = _parse_hexish(edit_pe_base.text())
                pe_mode = "image" if rb_pe_image.isChecked() else "raw"
                result_holder["data"] = {"mode": "pe", "base": base, "pe_mode": pe_mode}
        except Exception as exc:
            show_error(f"Invalid option: {exc}")
            return
        dlg.accept()

    for rb in (rb_asm, rb_bin, rb_pe):
        try:
            rb.toggled.connect(set_enabled)
        except Exception:
            pass
    try:
        ok_btn.clicked.connect(on_ok)
        cancel_btn.clicked.connect(dlg.reject)
    except Exception:
        pass

    set_enabled()
    rc = _qt_exec_dialog(dlg)
    if rc != 1:
        return None
    return result_holder["data"]


def run_dump_ui() -> Optional[str]:
    opts = _ask_dump_options_radio()
    if not opts:
        return None

    mode = opts.get("mode")
    if mode == "asm":
        return save_function_dump(int(opts["func_addr"]))
    if mode == "bin":
        return dump_bin(int(opts["addr"]), int(opts["size"]))
    if mode == "pe":
        return dump_pe(int(opts["base"]), str(opts["pe_mode"]))

    raise ValueError(f"unknown mode: {mode}")


class SPDumpHelperRadioPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = f"Dump ASM/BIN/PE helper, radio UI, {VERSION}"
    help = "Press Ctrl+D and choose ASM, BIN, or PE dump with radio buttons"
    wanted_name = "SP Dump Helper Radio v7"
    wanted_hotkey = "Ctrl-D"

    def init(self):
        _msg("loaded; hotkey Ctrl+D; PE raw/image modes are size-only dumps with PE type extension check")
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        try:
            run_dump_ui()
        except Exception as exc:
            _warn(f"dump failed: {type(exc).__name__}: {exc}")

    def term(self):
        pass


def PLUGIN_ENTRY():
    return SPDumpHelperRadioPlugin()
