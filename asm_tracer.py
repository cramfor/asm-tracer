#!/usr/bin/env python3
"""
asm_tracer.py — 用 ptrace + pyelftools 追踪 Linux x86-64 汇编程序

只记录 user.s 中定义的函数的单步执行信息：
  * 函数名单直接从 user.s 提取（顶格标签），不写死、不依赖符号表类型，
    兼容 godbolt 默认开启 "Filter directives" 的输出（此时符号是
    STT_NOTYPE 且 size=0，旧版会因此报"找不到 main"）；
  * printf 等 user.s 之外的库函数不写入记录；默认在外部代码中继续
    “隐藏式单步”，直到回到 user.s，因此可处理 longjmp、库函数回调和
    其他非局部控制流；
  * 普通函数入口（默认 main，也可 --entry 指定）返回后停止；入口为
    _start 时没有调用者返回地址，追踪到进程退出或步数上限为止。

用法:
    python3 asm_tracer.py <executable> <user.s> [-o trace.jsonl]
                          [--entry NAME] [--follow-calls] [--max-steps N]
                          [--max-external-steps N]
                          [--format jsonl|myjson] [--arch x86-64] [--wordsize 8]

输出:
    --format jsonl  : 每步一行 JSON，字段 step/address/lineno/registers/stack_contents/stack_trace
    --format myjson : 单个 JSON 对象（system/instructions/code/user 四段），
                      可直接被 ASM Visualizer 前端 JSON.parse 作为 myjson 使用

对被追踪程序的要求和限制:
    1. 当前 ptrace 寄存器布局、栈布局和系统调用约定仅支持 Linux x86-64；
       --arch/--wordsize 目前只写入输出元数据，不改变 tracer 的体系结构；
    2. 建议用 -O0 -fno-omit-frame-pointer 编译（保证 rbp 帧链完整）；
    3. as --gdwarf-5 -o user.o user.s  （生成指向 user.s 的行号表；
       即使 user.s 里没有 .file/.loc，gas 也会按汇编行号生成）；
    4. gcc -no-pie -o user user.o      （PIE 也支持，自动按 /proc/<pid>/maps
       计算加载基址；静态/动态链接均可）；
    5. 当前只追踪初始线程；目标程序 fork、clone 或创建线程后的新执行流
       不会被自动跟随。
"""

import argparse
import ctypes
import json
import os
import re
import signal
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
PTRACE_SETOPTIONS = 0x4200
PTRACE_O_EXITKILL = 0x100000
SIGTRAP = signal.SIGTRAP

REG_NAMES = [
    "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10",
    "r9", "r8", "rax", "rcx", "rdx", "rsi", "rdi", "orig_rax",
    "rip", "cs", "eflags", "rsp", "ss", "fs_base", "gs_base",
    "ds", "es", "fs", "gs"
]

class UserRegs(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulonglong) for n in REG_NAMES]

def ptrace(request, pid, addr=0, data=0):
    """用于 CONT/SINGLESTEP/GETREGS/SETREGS：-1视为错误。"""
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
    """在 addr 下 int3 断点，返回原字节。读取时先按 8 字节对齐。"""
    aligned = addr & ~7
    shift = (addr - aligned) * 8
    orig = read_word(pid, aligned)
    if orig is None:
        raise OSError(f"无法读取 0x{addr:x}，无法下断点")
    write_byte(pid, addr, 0xCC)
    return (orig >> shift) & 0xFF

def clear_int3(pid, addr, orig_byte):
    """确认当前停在 addr 的 int3 后，恢复原字节并回退 rip。"""
    regs = get_regs(pid)
    if regs.rip != addr + 1:
        raise RuntimeError(
            f"当前 rip=0x{regs.rip:x}，不是 0x{addr:x} 处 int3 命中后的状态")
    write_byte(pid, addr, orig_byte)
    set_rip(pid, addr)

def single_step_wait(pid):
    """
    执行一次 PTRACE_SINGLESTEP，并透传停止时收到的非 SIGTRAP 信号。
    单步完成返回寄存器；进程退出或被信号杀死时返回 None。
    """
    pending_sig = 0
    while True:
        ptrace(PTRACE_SINGLESTEP, pid, 0, pending_sig)
        pending_sig = 0

        _, status = os.waitpid(pid, 0)
        if os.WIFEXITED(status) or os.WIFSIGNALED(status):
            return None
        if not os.WIFSTOPPED(status):
            raise RuntimeError(f"单步后收到无法处理的 wait status=0x{status:x}")

        sig = os.WSTOPSIG(status)
        if sig == SIGTRAP:
            return get_regs(pid)

        # 信号尚未真正交给 tracee；下次 ptrace 请求时继续投递。
        pending_sig = sig

def wait_for_breakpoint(pid, addr):
    """
    继续运行直到命中 addr 处的 int3；非 SIGTRAP 信号透传。
    命中返回 True，进程退出返回 False。
    """
    pending_sig = 0
    while True:
        ptrace(PTRACE_CONT, pid, 0, pending_sig)
        pending_sig = 0

        _, status = os.waitpid(pid, 0)
        if os.WIFEXITED(status) or os.WIFSIGNALED(status):
            return False
        if not os.WIFSTOPPED(status):
            raise RuntimeError(f"等待断点时收到无法处理的 wait status=0x{status:x}")

        sig = os.WSTOPSIG(status)
        if sig == SIGTRAP:
            regs = get_regs(pid)
            if regs.rip == addr + 1:
                return True
            raise RuntimeError(
                f"收到非预期 SIGTRAP：rip=0x{regs.rip:x}，"
                f"期望命中 0x{addr:x} 处的断点")

        pending_sig = sig

def terminate_child(pid):
    """异常或提前结束追踪时杀死并回收子进程，避免留下 ptrace-stopped 进程。"""
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass

# ---------- 从 user.s 提取函数名 ----------
def extract_functions_from_asm(asm_path):
    """
    提取 user.s 里的函数名：顶格（无缩进）、非 '.' 开头的标签。
    godbolt -O0 输出中函数体标签顶格，本地标签以 .L 开头、字符串常量
    以 .LC 开头，均可被 '.' 前缀规则排除；个别数据标签（如全局变量）
    之后会与符号表的可执行节信息取交集，自动剔除。
    """
    names, seen = [], set()
    with open(asm_path, encoding="utf-8", errors="replace") as f:
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
            self.f.close()
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
    top 给定上界（不含）：收集 [rsp, top) 区间。该区间通常覆盖入口函数
    及其被调函数当前使用的栈地址范围；刚进入窗口的地址可能含有历史残留，
    只有被当前调用链实际写入后，其值才属于当前栈帧。遇到不可读地址即停止。"""
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
    function 归属：frame 0 用 rip 查当前函数；frame i+1 用 frame i 的
    返回地址减一查（返回地址是 call 的下一条指令，减一可确保仍位于调用者内）。
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
            "function": dwarf.addr_to_name(ret_addr - 1),
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
    with open(asm_path, encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()

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
def trace(executable, asm_path, out, entry=None, follow_calls=False,
          max_steps=1_000_000, max_external_steps=1_000_000,
          fmt="jsonl", arch="x86-64", wordsize=8):
    if max_steps < 0:
        raise ValueError("max_steps 不能为负数")
    if max_external_steps < 1:
        raise ValueError("max_external_steps 必须大于 0")

    func_names = extract_functions_from_asm(asm_path)
    if not func_names:
        raise RuntimeError(f"从 {asm_path} 中没有提取到函数标签（顶格、非点开头的 label）")

    dwarf = DwarfLookup(executable, func_names)
    pid = None
    child_exited = False
    records = []
    step = 0
    stop_reason = f"达到记录步数上限 {max_steps}"
    trace_error = None

    def write_records():
        """成功时写完整结果；异常时若已有记录，则写部分结果。"""
        if fmt == "myjson":
            json.dump(build_myjson(records, asm_path, dwarf, arch, wordsize),
                      out, ensure_ascii=False)
            out.write("\n")
        else:
            for i, rec in enumerate(records):
                print(json.dumps({"step": i, **rec}, ensure_ascii=False), file=out)

    try:
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

        print(f"# 追踪函数: {[n for _, _, n in dwarf.user_funcs]}，入口: {entry}",
              file=sys.stderr)

        # exec 使用解析后的真实路径，避免依赖 PATH；argv[0] 仍保留用户给定形式。
        exec_path = os.path.realpath(executable)
        pid = os.fork()
        if pid == 0:
            try:
                ctypes.set_errno(0)
                if libc.ptrace(PTRACE_TRACEME, 0, None, None) == -1:
                    err = ctypes.get_errno()
                    print(f"ptrace TRACEME 失败: {os.strerror(err)}", file=sys.stderr)
                    os._exit(101)

                # stdout 重定向到 /dev/null，避免目标程序输出污染 JSON。
                devnull = os.open(os.devnull, os.O_WRONLY)
                os.dup2(devnull, 1)
                os.close(devnull)
                os.execv(exec_path, [executable])
            except BaseException as exc:
                print(f"子进程 exec 失败: {exc}", file=sys.stderr)
            os._exit(127)

        # exec 完成后的第一次 SIGTRAP 停止。
        _, status = os.waitpid(pid, 0)
        if os.WIFEXITED(status) or os.WIFSIGNALED(status):
            child_exited = True
            raise RuntimeError(f"子进程启动失败或过早退出, status=0x{status:x}")
        if not os.WIFSTOPPED(status):
            raise RuntimeError(f"子进程未正常停止, status=0x{status:x}")

        # 若 tracer 因未捕获异常、KeyboardInterrupt 等原因死亡，由内核杀死 tracee。
        ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL)

        dwarf.bias = compute_bias(dwarf, pid, exec_path)
        entry_addr = entry_link + dwarf.bias

        # ---- 在入口函数下一次性断点，跳过动态链接器和 libc 初始化 ----
        orig_byte = set_int3(pid, entry_addr)
        if not wait_for_breakpoint(pid, entry_addr):
            child_exited = True
            raise RuntimeError(f"进程在命中入口函数 {entry} 前退出")
        clear_int3(pid, entry_addr, orig_byte)    # 恢复原字节并回退 rip

        regs = get_regs(pid)
        entry_rsp = regs.rsp

        # _start 是进程入口，不是普通函数：[rsp] 是 argc，不是返回地址。
        # 其他入口默认具有普通函数栈布局，[rsp] 是调用者返回地址。
        entry_has_caller = entry != "_start"
        if entry_has_caller:
            entry_ret_addr = read_word(pid, entry_rsp)
            if entry_ret_addr is None:
                raise RuntimeError(f"无法读取入口函数 {entry} 的返回地址")
        else:
            entry_ret_addr = None

        # 栈采集上界：入口时的 rsp + 8。
        # 普通函数入口时包含返回地址槽位；_start 入口时包含 argc 槽位。
        # 窗口 [当前 rsp, entry_rsp+8) 覆盖入口函数及其被调函数当前使用的
        # 栈地址范围；刚进入窗口的地址可能含有历史残留。
        stack_top = entry_rsp + 8

        def emit(regs):
            records.append({
                "address": f"0x{regs.rip:X}",
                "lineno": dwarf.addr_to_line(regs.rip),
                "registers": collect_registers(regs),
                "stack_contents": collect_stack(pid, regs.rsp, top=stack_top),
                "stack_trace": collect_stack_trace(pid, regs, dwarf),
            })

        def is_entry_return(regs):
            return (entry_ret_addr is not None
                    and regs.rip == entry_ret_addr
                    and regs.rsp == entry_rsp + 8)

        while step < max_steps:
            regs = get_regs(pid)

            # 普通入口函数执行 ret 后：rip == 返回地址 且 rsp == entry_rsp + 8。
            # 必须先于“隐藏式单步外部代码”判断；_start 没有这种返回状态。
            if is_entry_return(regs):
                stop_reason = "入口函数返回到调用者"
                break

            # 进入 user.s 之外的代码后，采用“隐藏式单步”：外部指令仍逐条
            # 执行，但不写入 records。这里故意不使用 [rsp] 上的返回地址下
            # 断点，因为 longjmp、异常展开、库函数回调等路径可能不会普通
            # 返回到 call 的下一条指令。
            if not follow_calls and dwarf.addr_to_func(regs.rip) == "":
                stop_trace = False

                for _ in range(max_external_steps):
                    regs2 = single_step_wait(pid)
                    if regs2 is None:
                        child_exited = True
                        stop_trace = True
                        stop_reason = "进程退出"
                        break

                    if is_entry_return(regs2):
                        stop_trace = True
                        stop_reason = "入口函数返回到调用者"
                        break

                    # 回到 user.s 中的函数；longjmp、回调、异常着陆都能被捕获。
                    if dwarf.addr_to_func(regs2.rip) != "":
                        break
                else:
                    raise RuntimeError(
                        f"外部代码隐藏单步超过 {max_external_steps} 次，"
                        f"可能陷入长时间循环；可用 --max-external-steps 调大")

                if stop_trace:
                    break

                continue

            # 只记录 user.s 中函数的单步信息（--follow-calls 时记录全部）。
            if follow_calls or dwarf.addr_to_func(regs.rip) != "":
                emit(regs)
                step += 1

            regs_after_step = single_step_wait(pid)
            if regs_after_step is None:
                child_exited = True
                stop_reason = "进程退出"
                break

    except BaseException as exc:
        # 保存异常，先统一清理 tracee 并尽量写出已有记录，再重新抛出。
        trace_error = exc
    finally:
        if pid is not None and not child_exited:
            terminate_child(pid)

    try:
        if trace_error is not None:
            # 出错时只有在已有记录的情况下才生成“部分追踪结果”。
            if records:
                write_records()
                out.flush()
        else:
            write_records()
            out.flush()
    finally:
        dwarf.close()

    if trace_error is not None:
        if records:
            print(f"# 警告：追踪中断，已写出 {len(records)} 条不完整记录",
                  file=sys.stderr)
        raise trace_error

    print(f"# 共记录 {step} 步（入口: {entry}；停止原因: {stop_reason}）",
          file=sys.stderr)

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="ptrace + pyelftools 汇编单步追踪器")
    ap.add_argument("executable", help="被追踪的可执行文件")
    ap.add_argument("asm", help="godbolt 生成的 user.s（追踪的函数名从这里提取）")
    ap.add_argument("-o", "--output", help="输出文件（默认 stdout，JSONL 格式）")
    ap.add_argument("--entry", help="入口函数名（默认 main，没有 main 时用 _start）")
    ap.add_argument("--follow-calls", action="store_true",
                    help="也逐条记录 user.s 之外（libc 等）的指令；默认外部指令隐藏单步但不记录")
    ap.add_argument("--max-steps", type=int, default=1_000_000,
                    help="写入 records 的指令数上限；不包含 libc 内部隐藏单步")
    ap.add_argument("--max-external-steps", type=int, default=1_000_000,
                    help="外部代码隐藏单步上限，防止在 libc 内无限循环")
    ap.add_argument("--format", choices=["jsonl", "myjson"], default="jsonl",
                    help="jsonl=每步一行（默认）；myjson=ASM Visualizer 前端可直接 "
                         "JSON.parse 的单个 JSON（含 system/instructions/code/user 四段）")
    ap.add_argument("--arch", default="x86-64",
                    help="写入 myjson system.arch 的元数据；当前 tracer 本身仅支持 Linux x86-64")
    ap.add_argument("--wordsize", type=int, default=8,
                    help="写入 myjson system.wordsize 的元数据；当前寄存器读取固定为 x86-64 的 8 字节字")
    args = ap.parse_args()

    out = open(args.output, "w", encoding="utf-8") if args.output else sys.stdout
    try:
        trace(args.executable, args.asm, out, args.entry, args.follow_calls,
              args.max_steps, args.max_external_steps,
              args.format, args.arch, args.wordsize)
    finally:
        if out is not sys.stdout:
            out.close()
