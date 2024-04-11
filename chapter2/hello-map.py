#!/usr/bin/python3  
from bcc import BPF
from time import sleep

program = r"""
BPF_HASH(counter_table);

int execvefunc(void *ctx) {
   u64 syscallnum;
   u64 counter = 0;
   u64 *p;

   syscallnum = 59;
   p = counter_table.lookup(&syscallnum);
   if (p != 0) {
      counter = *p;
   }
   counter++;
   counter_table.update(&syscallnum, &counter);
   return 0;
}

int openatfunc(void *ctx) {
   u64 syscallnum;
   u64 counter = 0;
   u64 *p;

   syscallnum = 257;
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
execve_syscall = b.get_syscall_fnname("execve")
openat_syscall = b.get_syscall_fnname("openat")
b.attach_kprobe(event=execve_syscall, fn_name="execvefunc")
b.attach_kprobe(event=openat_syscall, fn_name="openatfunc")

# Attach to a tracepoint that gets hit for all syscalls 
# b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

while True:
    sleep(2)
    s = ""
    for k,v in b["counter_table"].items():
        s += f"ID {k.value}: {v.value}\t"
    print(s)
