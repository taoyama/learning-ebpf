#!/usr/bin/python3  
from bcc import BPF
from time import sleep

program = r"""
#pragma clang diagnostic ignored "-Wint-conversion"
BPF_HASH(counter_table);
BPF_PROG_ARRAY(syscall, 300);

RAW_TRACEPOINT_PROBE(sys_enter) {
   u64 syscallnum = ctx->args[1];
   u64 counter = 0;
   u64 *p;

   syscall.call(ctx, syscallnum);
   p = counter_table.lookup(&syscallnum);
   if (p != 0) {
      counter = *p;
   }
   counter++;
   counter_table.update(&syscallnum, &counter);
   return 0;
}

"""

b = BPF(text=program)
#b.attach_raw_tracepoint(tp="sys_enter", fn_name="sysenterfunc")

# Attach to a tracepoint that gets hit for all syscalls 
# b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

while True:
    sleep(2)
    s = ""
    for k,v in b["counter_table"].items():
        s += f"ID {k.value}: {v.value}\t"
    print(s)
