break main
run
while 1
  stepi
  if $rip[0] == 0xeb || $rip[0] == 0xe9 || $rip[0] == 0x0f && ($rip[1] & 0xf0) == 0x80
    info registers
    x/10i $rip
    print "Jump instruction encountered"
  end
end