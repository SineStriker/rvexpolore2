set width 0
set verbose 0

# 开启日志记录
set logging on
# 覆盖之前的日志文件
set logging overwrite on
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
  display/i $pc
  # 获取显示编号
  # set $num = $display_number
  # 取消显示当前指令
  # undisplay $num
  # 显示16个寄存器的值
  info all-registers rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15 rip eflags cs ss ds es fs gs
  # 设置在跳转指令处打断点的条件表达式，根据当前指令的助记符判断是否是跳转指令，如果是则返回真，否则返回假。
  set $cond = (strcmp($pc->asm, "jmp") == 0) || (strcmp($pc->asm, "je") == 0) || (strcmp($pc->asm, "jne") == 0) || (strcmp($pc->asm, "jg") == 0) || (strcmp($pc->asm, "jge") == 0) || (strcmp($pc->asm, "jl") == 0) || (strcmp($pc->asm, "jle") == 0) || (strcmp($pc->asm, "ja") == 0) || (strcmp($pc->asm, "jae") == 0) || (strcmp($pc->asm, "jb") == 0) || (strcmp($pc->asm, "jbe") == 0) || (strcmp($pc->asm, "jo") == 0) || (strcmp($pc->asm, "jno") == 0) || (strcmp($pc->asm, "js") == 0) || (strcmp($pc->asm, "jns") == 0) || (strcmp($pc->asm, "jz") == 0) || (strcmp($pc->asm, "jnz") == 0)
  # 设置在下一条指令处打断点，并且使用条件表达式作为断点条件，如果条件为真，则停止执行，否则继续执行。
  break-if *$pc + $pc->size if $cond
  # 继续执行程序，直到遇到断点或者结束或者出错。
  continue

end
# 停止日志记录
set logging off