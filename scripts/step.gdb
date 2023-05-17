set width 0
set verbose 0

# 开启日志记录
set logging on
# 设置日志文件名
set logging file dump.log
# 重定向输出到日志文件
set logging redirect on
# 设置不分页显示
set height 0
# 设置断点在main函数
break main
# 运行程序
run
# 循环执行以下命令，直到程序结束或者出错
while 1
  # 显示当前指令
  # display/i $pc
  # 显示16个寄存器的值
  info all-registers rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15 rip eflags cs ss ds es fs gs
  # 单步执行一条指令
  stepi
end
# 停止日志记录
set logging off