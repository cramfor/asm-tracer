# asm-tracer

用 `ptrace` + `pyelftools` 逐指令追踪 x86-64 汇编程序，输出可直接喂给[ASM Visualizer](https://asm.diveintosystems.org/) 前端的数据，在浏览器里逐步查看每行汇编执行时的寄存器、栈内容和调用栈变化。

## 它做什么

给定一份手写汇编 `user.s` 和由它链接出的可执行文件 `user`：

1. 从 `user.s` 中自动提取函数名（顶格、非 `.` 开头的标签）；
2. 用 `ptrace` 单步执行 `user`，只记录 `user.s` 中定义的函数的指令，
   `printf` 等库函数内部自动跨过、不产生记录；
3. 每步采集：当前地址、对应 `user.s` 行号、全部通用寄存器与 RFLAG、
   入口函数栈帧范围内的栈内容、基于 RBP 链的调用栈；
4. 输出 JSONL 或单文件 `myjson`（`system/instructions/code/user` 四段），
   后者可直接作为 ASM Visualizer 前端的数据源。

## 环境要求

- Linux x86-64（依赖 `ptrace`）
- Python 3.8+
- `pyelftools`：`pip install pyelftools`
- `binutils`（`as`）与 `gcc`

被追踪程序建议用 `-O0 -fno-omit-frame-pointer` 编译，保证 RBP 帧链完整；
PIE 与非 PIE 都支持，PIE 的加载基址会从 `/proc/<pid>/maps` 自动计算。

## 快速开始

### 1. 准备汇编与可执行文件

```bash
as --gdwarf-5 -o user.o user.s
gcc -no-pie -o user user.o
```

`--gdwarf-5` 让 `as` 生成指向 `user.s` 的行号表，追踪器靠它把地址映射回源码行。  
`-no-pie` 不是必须的，但能让地址在输出里更稳定、便于对照。

### 2. 追踪并生成 trace.json

```bash
python3 asm_tracer.py ./user user.s --entry main --format myjson -o app/static/trace.json
```

常用参数：

|参数|说明|
|---|---|
|`--entry NAME`|入口函数，默认 `main`，没有 `main` 时回退 `_start`|
|`--follow-calls`|也逐条记录 `user.s` 之外的库函数指令，默认跨过|
|`--max-steps N`|步数上限，防止死循环或超长程序|
|`--format jsonl\|myjson`|`jsonl` 每步一行；`myjson` 为 ASM Visualizer 前端格式|
|`--arch` / `--wordsize`|写入 `myjson` 的 `system` 段，默认 `x86-64` / `8`|

### 3. 在浏览器中查看

```bash
cd app
python3 -m http.server
```

打开 `http://localhost:8000/x86_64.html`（或 `index.html`），页面会加载  
`static/trace.json`，用上一步/下一步按钮逐条查看指令、寄存器和栈的变化。


## 目录结构

```text
asm-tracer/
├── asm_tracer.py          # 追踪器
├── user.s                 # 示例输入：手写 x86-64 汇编，此次取自godbolt.org生成的汇编
└── app/
    ├── index.html
    ├── x86_64.html        # ASM Visualizer 前端页面
    └── static/
        ├── asm.js         # 前端可视化逻辑
        ├── base.css
        ├── bulma.min.css
        ├── trace.json     # 追踪器输出，前端的数据源
        └── ...            # 图标等静态资源
```

## myjson 格式说明

`--format myjson` 输出单个 JSON 对象，包含四段：

- `system`：`arch` / `wordsize` / `numregs`
    
- `instructions`：以 1 起始的步号为键，每步含 `address`、`lineno`  
    （形如 `user.s:42`）、`registers`、`stack_trace`、`stack_contents`
    
- `code`：以 `user.s` 行号为键，值为 `[该行首条指令地址或 "0x0", 源码文本]`
    
- `user`：`user.s` 的逐行原文
    

这个结构与 ASM Visualizer 前端 `JSON.parse` 后直接消费的 `myjson` 对齐，  
因此页面无需额外转换即可加载。


## 已知限制

- 调用栈基于 RBP 链回溯，要求被追踪代码保留帧指针；用 `-O2` 或  
    `-fomit-frame-pointer` 编译时帧链可能断裂，`stack_trace` 会提前终止。
    
- 目前只支持 x86-64 的 `ptrace` 寄存器布局；其他架构需要调整  
    `UserRegs` 和 `PTRACE_GETREGS` 的使用。
    
- `stack_contents` 只采集入口函数自己的栈帧范围（`[rsp, entry_rsp+8)`），  
    不包含调用者 `__libc_start_main` 的残留内容。
    

## 关于 ASM Visualizer 前端资源

`app/` 下的 `index.html`、`x86_64.html`、`static/asm.js` 等页面与脚本提取自 [ASM Visualizer](https://asm.diveintosystems.org/)，用于本地加载本仓库生成的 `trace.json` 进行可视化。这些前端资源的版权归其原作者所有，本仓库仅作为追踪器的配套展示层使用；如需再分发，请先确认原项目的授权条款。追踪器`asm_tracer.py` 本身不依赖这些资源，`--format jsonl` 输出可独立使用。

## 参考

- ASM Visualizer：[https://asm.diveintosystems.org/](https://asm.diveintosystems.org/)
    
- 工具介绍（PDF）：[https://par.nsf.gov/servlets/purl/10579296](https://par.nsf.gov/servlets/purl/10579296)