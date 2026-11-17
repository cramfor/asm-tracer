#!/usr/bin/env python3
"""
asm_tracer.py — 用 ptrace + pyelftools 逐指令追踪 x86-64 汇编程序

只记录 user.s 中定义的函数的单步执行信息：
  * 函数名单直接从 user.s 提取（顶格标签），不写死、不依赖符号表类型，
    兼容 godbolt 默认开启 "Filter directives" 的输出（此时符号是
    STT_NOTYPE 且 size=0，旧版会因此报"找不到 main"）；
  * printf 等 user.s 之外的库函数自动跨过，不记录内部指令；
  * 入口函数（默认 main，没有则用 _start，也可 --entry 指定）返回后停止。

用法:
    python3 asm_tracer.py <executable> <user.s> [-o trace.jsonl]
                          [--entry NAME] [--follow-calls] [--max-steps N]
                          [--format jsonl|myjson] [--arch x86-64] [--wordsize 8]

输出:
    --format jsonl  : 每步一行 JSON，字段 step/address/lineno/registers/stack_contents/stack_trace
    --format myjson : 单个 JSON 对象（system/instructions/code/user 四段），
                      可直接被 ASM Visualizer 前端 JSON.parse 作为 myjson 使用

对被追踪程序的要求:
    1. godbolt 建议用 -O0 -fno-omit-frame-pointer 编译（保证 rbp 帧链完整）；
    2. as --gdwarf-5 -o user.o user.s  （生成指向 user.s 的行号表；
       即使 user.s 里没有 .file/.loc，gas 也会按汇编行号生成）；
    3. gcc -no-pie -o user user.o      （PIE 也支持，自动按 /proc/<pid>/maps
       计算加载基址；静态/动态链接均可）。
"""

import argparse
import ctypes
import json
import os
import re
import sys
from ctypes.util import find_library

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

# ---------- ptrace 绑定 ----------
libc = ctypes.CDLL(find_library("c"), use_errno=True)
libc.ptrace.restype = ctypes.c_long
libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]

PTRACE_TRACEME = 0
PTRACE_PEEKDATA = 2
PTRACE_POKEDATA = 5
PTRACE_CONT = 7
PTRACE_SINGLESTEP = 9
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
SIGTRAP = 5

REG_NAMES = [
    "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10",
    "r9", "r8", "rax", "rcx", "rdx", "rsi", "rdi", "orig_rax",
    "rip", "cs", "eflags", "rsp", "ss", "fs_base", "gs_base",
    "ds", "es", "fs", "gs"
]

class UserRegs(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulonglong) for n in REG_NAMES]

def ptrace(request, pid, addr=0, data=0):
    """用于 CONT/SINGLESTEP/GETREGS/SETREGS：-1 一律视为错误。"""
    ctypes.set_errno(0)
    res = libc.ptrace(request, pid, ctypes.c_void_p(addr), ctypes.c_void_p(data))
    if res == -1:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return res

def get_regs(pid):
    regs = UserRegs()
    ptrace(PTRACE_GETREGS, pid, 0, ctypes.addressof(regs))
    return regs

def set_rip(pid, rip):
    regs = get_regs(pid)
    regs.rip = rip
    ptrace(PTRACE_SETREGS, pid, 0, ctypes.addressof(regs))

def read_word(pid, addr):
    """PTRACE_PEEKDATA 读 8 字节。失败返回 None（-1 是合法读数，靠 errno 区分）。"""
    ctypes.set_errno(0)
    res = libc.ptrace(PTRACE_PEEKDATA, pid, ctypes.c_void_p(addr), None)
    if res == -1 and ctypes.get_errno() != 0:
        return None
    return res & 0xFFFFFFFFFFFFFFFF

def write_byte(pid, addr, byte):
    """写 1 字节，保留同字其余 7 字节。失败抛异常。"""
    aligned = addr & ~7
    shift = (addr - aligned) * 8
    orig = read_word(pid, aligned)
    if orig is None:
        raise OSError(f"无法读取 0x{addr:x}，无法写入断点")
    new_word = (orig & ~(0xFF << shift)) | (byte << shift)
    ptrace(PTRACE_POKEDATA, pid, aligned, new_word)

def set_int3(pid, addr):
    """在 addr 下 int3 断点，返回原字节。"""
    orig = read_word(pid, addr)
    if orig is None:
        raise OSError(f"无法读取 0x{addr:x}，无法下断点")
    write_byte(pid, addr, 0xCC)
    return orig & 0xFF

def clear_int3(pid, addr, orig_byte):
    """撤除断点并把 rip 回退到断点处（int3 命中后 rip = addr + 1）。"""
    write_byte(pid, addr, orig_byte)
    set_rip(pid, addr)

# ---------- 从 user.s 提取函数名 ----------
def extract_functions_from_asm(asm_path):
    """
    提取 user.s 里的函数名：顶格（无缩进）、非 '.' 开头的标签。
    godbolt -O0 输出中函数体标签顶格，本地标签以 .L 开头、字符串常量
    以 .LC 开头，均可被 '.' 前缀规则排除；个别数据标签（如全局变量）
    之后会与符号表的可执行节信息取交集，自动剔除。
    """
    names, seen = [], set()
    with open(asm_path) as f:
        for line in f:
            m = re.match(r"^([A-Za-z_][A-Za-z0-9_.$]*):", line)
            if m and m.group(1) not in seen:
                seen.add(m.group(1))
                names.append(m.group(1))
    return names

# ---------- pyelftools: 行号表 + 函数地址范围 ----------
SHF_EXECINSTR = 0x4

class DwarfLookup:
    """内部保存链接时地址；查询传运行时地址，自动减 bias（PIE 基址）。"""

    def __init__(self, elf_path, func_names):
        self.f = open(elf_path, "rb")
        self.elffile = ELFFile(self.f)
        if not self.elffile.has_dwarf_info():
            raise RuntimeError("ELF 没有 DWARF 调试信息；请用 as --gdwarf-5 汇编 user.s")
        self.dwarfinfo = self.elffile.get_dwarf_info()
        self.bias = 0  # PIE 加载基址，子进程启动后由 compute_bias() 设置

        # --- 行号区间表 [(start, end, lineno)]，end_sequence 作右端 ---
        self.line_ranges = []
        for cu in self.dwarfinfo.iter_CUs():
            lp = self.dwarfinfo.line_program_for_CU(cu)
            if lp is None:
                continue
            prev = None
            for entry in lp.get_entries():
                if entry.state is None:
                    continue
                if prev is not None:
                    self.line_ranges.append((prev.address, entry.state.address, prev.line))
                prev = None if entry.state.end_sequence else entry.state
        self.line_ranges.sort(key=lambda x: x[0])

        # --- 可执行节内的全部符号 ---
        # 不限 STT_FUNC（godbolt 过滤 .type 后是 NOTYPE）；
        # size==0 的符号用"同节内下一符号地址 / 节尾"合成范围。
        sections = list(self.elffile.iter_sections())
        exec_idx = {i for i, s in enumerate(sections) if s["sh_flags"] & SHF_EXECINSTR}
        by_sec = {}
        for section in sections:
            if not isinstance(section, SymbolTableSection):
                continue
            for sym in section.iter_symbols():
                shndx = sym["st_shndx"]
                if not isinstance(shndx, int) or shndx not in exec_idx:
                    continue
                if sym["st_value"] == 0:
                    continue
                by_sec.setdefault(shndx, []).append((sym["st_value"], sym["st_size"], sym.name))
        self.all_text = []   # (low, high, name)，用于帧链函数名标注
        for shndx, syms in by_sec.items():
            syms.sort()
            sec_end = sections[shndx]["sh_addr"] + sections[shndx]["sh_size"]
            for i, (addr, size, name) in enumerate(syms):
                if size:
                    high = addr + size
                elif i + 1 < len(syms):
                    high = syms[i + 1][0]
                else:
                    high = sec_end
                if high > addr:
                    self.all_text.append((addr, high, name))
        self.all_text.sort(key=lambda x: x[0])

        # --- user.s 中定义的函数（与符号表取交集，剔除数据标签） ---
        wanted = set(func_names)
        self.user_funcs = sorted((lo, hi, n) for lo, hi, n in self.all_text if n in wanted)

    def addr_to_line(self, runtime_addr):
        addr = runtime_addr - self.bias
        for start, end, line in self.line_ranges:
            if start <= addr < end:
                return line
        return None

    def addr_to_func(self, runtime_addr):
        """仅匹配 user.s 中定义的函数；不在其中返回 ""。"""
        addr = runtime_addr - self.bias
        for low, high, name in self.user_funcs:
            if low <= addr < high:
                return name
        return ""

    def addr_to_name(self, runtime_addr):
        """匹配可执行节内的任意符号（含静态链接的 libc），用于帧链标注。"""
        addr = runtime_addr - self.bias
        for low, high, name in self.all_text:
            if low <= addr < high:
                return name
        return ""

    def func_addr(self, name):
        """符号的链接时地址，调用方自行加 bias。"""
        for low, high, fname in self.all_text:
            if fname == name:
                return low
        return None

    def is_pie(self):
        return self.elffile.header["e_type"] == "ET_DYN"

    def min_load_vaddr(self):
        return min(seg["p_vaddr"] for seg in self.elffile.iter_segments()
                   if seg["p_type"] == "PT_LOAD") & ~0xFFF

    def close(self):
        self.f.close()

def compute_bias(dwarf, pid, exe_path):
    """ET_EXEC 返回 0；PIE 从 /proc/<pid>/maps 第一条文件映射求加载基址。"""
    if not dwarf.is_pie():
        return 0
    real = os.path.realpath(exe_path)
    with open(f"/proc/{pid}/maps") as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 6 and parts[5].startswith("/") \
                    and os.path.realpath(parts[5]) == real:
                map_start = int(parts[0].split("-")[0], 16)
                return map_start - dwarf.min_load_vaddr()
    raise RuntimeError("无法从 /proc/<pid>/maps 确定 PIE 加载基址")

# ---------- 栈内容采集 ----------
def collect_stack(pid, rsp, top=None, max_bytes=8192):
    """从 RSP 起按 8 字节读取栈内容，{地址: 值}。
    top 给定上界（不含）：只收集 [rsp, top) 区间，即入口函数自己的栈帧范围，
    不包含 __libc_start_main 等调用者残留在高地址的内容。遇到不可读地址即停止。"""
    if top is None:
        top = rsp + 256          # 未指定上界时退化为固定 256 字节窗口
    result = {}
    for off in range(0, max_bytes, 8):
        addr = rsp + off
        if addr >= top:
            break
        word = read_word(pid, addr)
        if word is None:
            break
        result[f"0x{rsp + off:X}"] = f"0x{word:X}"
    return result

# ---------- 调用栈采集（RBP 链） ----------
def collect_stack_trace(pid, regs, dwarf, max_frames=64):
    """
    沿 RBP 链回溯。帧布局（含 -fno-omit-frame-pointer 的经典序言）：
        [rbp]   = 调用者的 rbp
        [rbp+8] = 返回地址（位于调用者内部）
        调用者 rsp = rbp + 16
    function 归属：frame 0 用 rip 查当前函数；frame i+1 用 frame i 的返回地址查。
    """
    frames = [{
        "SP": f"0x{regs.rsp:X}",
        "BP": f"0x{regs.rbp:X}",
        "function": dwarf.addr_to_name(regs.rip),
    }]
    bp = regs.rbp
    for _ in range(max_frames - 1):
        saved_bp = read_word(pid, bp)
        ret_addr = read_word(pid, bp + 8)
        if saved_bp is None or ret_addr is None:
            break
        if saved_bp == 0 or saved_bp <= bp:   # 链终止（如 __libc_start_main 之上）或损坏
            break
        frames.append({
            "SP": f"0x{bp + 16:X}",
            "BP": f"0x{saved_bp:X}",
            "function": dwarf.addr_to_name(ret_addr),
        })
        bp = saved_bp
    return {str(i): f for i, f in enumerate(frames)}

# ---------- 寄存器快照 ----------
def collect_registers(regs):
    return {
        "RAX": f"0x{regs.rax:X}", "RCX": f"0x{regs.rcx:X}",
        "RDX": f"0x{regs.rdx:X}", "RBX": f"0x{regs.rbx:X}",
        "RSP": f"0x{regs.rsp:X}", "RBP": f"0x{regs.rbp:X}",
        "RSI": f"0x{regs.rsi:X}", "RDI": f"0x{regs.rdi:X}",
        "R8":  f"0x{regs.r8:X}",  "R9":  f"0x{regs.r9:X}",
        "R10": f"0x{regs.r10:X}", "R11": f"0x{regs.r11:X}",
        "R12": f"0x{regs.r12:X}", "R13": f"0x{regs.r13:X}",
        "R14": f"0x{regs.r14:X}", "R15": f"0x{regs.r15:X}",
        "RFLAG": f"0x{regs.eflags:X}",
    }

# ---------- 输出格式：ASM Visualizer 前端 myjson ----------
def build_myjson(records, asm_path, dwarf, arch, wordsize):
    """把追踪记录组装成 asm.js 期望的 myjson 四段结构：
      system:       CPU 信息（arch/wordsize/numregs）
      instructions: {1基数字字符串: {address, lineno, registers, stack_trace, stack_contents}}
      code:         {行号字符串: [地址, 汇编文本]}，非指令行地址为 "0x0"
      user:         user.s 原文行数组
    """
    lines = open(asm_path).read().splitlines()

    # 行号 -> 指令地址（链接时地址 + bias，与记录中的运行时地址口径一致）
    line_addr = {}
    for start, end, ln in dwarf.line_ranges:
        line_addr.setdefault(ln, f"0x{start + dwarf.bias:X}")

    code = {}
    for i, text in enumerate(lines, 1):
        code[str(i)] = [line_addr.get(i, "0x0"), text]

    base = os.path.basename(asm_path)
    instructions = {}
    for i, rec in enumerate(records, 1):
        instructions[str(i)] = {
            "address": rec["address"],
            "lineno": f"{base}:{rec['lineno']}",
            "registers": rec["registers"],
            "stack_trace": rec["stack_trace"],
            "stack_contents": rec["stack_contents"],
        }

    return {
        "system": {
            "arch": arch,
            "wordsize": wordsize,
            "numregs": len(records[0]["registers"]) if records else 0,
        },
        "instructions": instructions,
        "code": code,
        "user": lines,
    }

# ---------- 主追踪逻辑 ----------
def trace(executable, asm_path, out, entry=None, follow_calls=False, max_steps=1_000_000,
          fmt="jsonl", arch="x86-64", wordsize=8):
    func_names = extract_functions_from_asm(asm_path)
    if not func_names:
        raise RuntimeError(f"从 {asm_path} 中没有提取到任何函数标签（顶格、非点开头的 label）")

    dwarf = DwarfLookup(executable, func_names)
    if not dwarf.user_funcs:
        raise RuntimeError(
            f"user.s 提取到的函数 {func_names} 在可执行文件的符号表里找不到对应项，"
            f"请确认 {executable} 是由该 user.s 汇编链接生成的")

    # 入口函数：--entry 指定 > main > _start
    if entry is None:
        entry = "main" if dwarf.func_addr("main") is not None else "_start"
    entry_link = dwarf.func_addr(entry)
    if entry_link is None:
        avail = [n for _, _, n in dwarf.user_funcs]
        raise RuntimeError(f"找不到入口函数 {entry}；user.s 中可用的函数: {avail}，"
                           f"请用 --entry 指定")

    print(f"# 追踪函数: {[n for _, _, n in dwarf.user_funcs]}，入口: {entry}", file=sys.stderr)

    pid = os.fork()
    if pid == 0:
        # 子进程：声明被追踪，stdout 重定向到 /dev/null 以免污染 JSON，然后 exec
        libc.ptrace(PTRACE_TRACEME, 0, None, None)
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, 1)
        os.execv(executable, [executable])
        os._exit(1)

    # exec 完成后的第一次 SIGTRAP 停止
    _, status = os.waitpid(pid, 0)
    if not os.WIFSTOPPED(status):
        raise RuntimeError("子进程未正常停止")

    dwarf.bias = compute_bias(dwarf, pid, executable)
    entry_addr = entry_link + dwarf.bias

    # ---- 在入口函数下一次性断点，跳过动态链接器和 libc 初始化 ----
    orig_byte = set_int3(pid, entry_addr)
    ptrace(PTRACE_CONT, pid)
    _, status = os.waitpid(pid, 0)
    if not (os.WIFSTOPPED(status) and os.WSTOPSIG(status) == SIGTRAP):
        raise RuntimeError(f"未在 {entry} 命中断点, status=0x{status:x}")
    clear_int3(pid, entry_addr, orig_byte)    # 恢复原字节并回退 rip

    regs = get_regs(pid)
    entry_rsp = regs.rsp
    entry_ret_addr = read_word(pid, entry_rsp)  # main 返回到 __libc_start_main 的地址
    # 栈采集上界：入口时的 rsp + 8（含返回地址槽位）。
    # 入口函数的帧只会向下增长，因此窗口 [rsp, entry_rsp+8) 恰好只包含
    # main 及其被调函数产生的内容，不含 __libc_start_main 的残留。
    stack_top = entry_rsp + 8

    records = []
    def emit(regs):
        records.append({
            "address": f"0x{regs.rip:X}",
            "lineno": dwarf.addr_to_line(regs.rip),
            "registers": collect_registers(regs),
            "stack_contents": collect_stack(pid, regs.rsp, top=stack_top),
            "stack_trace": collect_stack_trace(pid, regs, dwarf),
        })

    step = 0
    while step < max_steps:
        regs = get_regs(pid)

        # 入口函数执行 ret 后：rip == 返回地址 且 rsp == entry_rsp + 8。
        # 必须先于"跳过外部代码"判断：返回后 rip 也在 user.s 函数之外，
        # 若不先退出，会把栈上 [rsp] 误当返回地址下断点。
        if regs.rip == entry_ret_addr and regs.rsp == entry_rsp + 8:
            break

        # 跨过 user.s 函数之外的代码（PLT / printf 等 libc 函数 / ld.so）：
        # call 执行后 [rsp] 即返回地址，在那里下一次性断点继续跑，
        # 库函数内部既不逐条执行记录，也不产生记录。
        if not follow_calls and dwarf.addr_to_func(regs.rip) == "":
            ret = read_word(pid, regs.rsp)
            if not ret:      # 读不到或返回地址为 0，无法安全跳过
                break
            b = set_int3(pid, ret)
            exited = False
            while True:
                ptrace(PTRACE_CONT, pid)
                _, status = os.waitpid(pid, 0)
                if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                    exited = True
                    break
                sig = os.WSTOPSIG(status)
                if sig == SIGTRAP:
                    break
                ptrace(PTRACE_CONT, pid, 0, sig)  # 透传其他信号
            clear_int3(pid, ret, b)
            if exited:       # 库函数里直接 exit() 的情况
                break
            continue         # 回到循环顶：rip 应已回到 user.s 函数内（或入口返回处）

        # 只记录 user.s 中函数的单步信息（--follow-calls 时记录全部）
        if follow_calls or dwarf.addr_to_func(regs.rip) != "":
            emit(regs)
            step += 1

        ptrace(PTRACE_SINGLESTEP, pid)
        _, status = os.waitpid(pid, 0)
        if os.WIFEXITED(status) or os.WIFSIGNALED(status):
            break

    # ---- 写出结果 ----
    if fmt == "myjson":
        json.dump(build_myjson(records, asm_path, dwarf, arch, wordsize),
                  out, ensure_ascii=False)
        out.write("\n")
    else:
        for i, rec in enumerate(records):
            print(json.dumps({"step": i, **rec}, ensure_ascii=False), file=out)
    out.flush()

    print(f"# 共记录 {step} 步（进入 {entry} 起，到其返回/进程退出止）", file=sys.stderr)
    dwarf.close()

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="ptrace + pyelftools 汇编单步追踪器")
    ap.add_argument("executable", help="被追踪的可执行文件")
    ap.add_argument("asm", help="godbolt 生成的 user.s（追踪的函数名从这里提取）")
    ap.add_argument("-o", "--output", help="输出文件（默认 stdout，JSONL 格式）")
    ap.add_argument("--entry", help="入口函数名（默认 main，没有 main 时用 _start）")
    ap.add_argument("--follow-calls", action="store_true",
                    help="也逐条记录 user.s 之外（libc 等）的指令，默认跨过且不记录")
    ap.add_argument("--max-steps", type=int, default=1_000_000, help="步数上限")
    ap.add_argument("--format", choices=["jsonl", "myjson"], default="jsonl",
                    help="jsonl=每步一行（默认）；myjson=ASM Visualizer 前端可直接 "
                         "JSON.parse 的单个 JSON（含 system/instructions/code/user 四段）")
    ap.add_argument("--arch", default="x86-64",
                    help="myjson 的 system.arch（asm.js 支持 x86-64 / IA32 / arm64）")
    ap.add_argument("--wordsize", type=int, default=8, help="myjson 的 system.wordsize")
    args = ap.parse_args()

    out = open(args.output, "w") if args.output else sys.stdout
    try:
        trace(args.executable, args.asm, out, args.entry, args.follow_calls,
              args.max_steps, args.format, args.arch, args.wordsize)
    finally:
        if out is not sys.stdout:
            out.close()
