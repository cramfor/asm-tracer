# asm-tracer
用 `ptrace` + `pyelftools` 逐指令追踪 x86-64 汇编程序，输出可直接喂给 [ASM Visualizer](https://asm.diveintosystems.org/) 前端的数据，在浏览器里逐步查看 每行汇编执行时的寄存器、栈内容和调用栈变化。
