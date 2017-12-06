Purpose
To hijack (intercept) system calls by writing and installing a very basic kernel module to the Linux kernel.

The module will create a new system call capable of:
REQUEST_SYSCALL_INTERCEPT: intercept the system call syscall
REQUEST_SYSCALL_RELEASE: de-intercept the system call syscall
REQUEST_START_MONITORING: start monitoring process pid for system call syscall, i.e., add pid to the syscall's list of monitored PIDs. A special case is that if pid is 0 then all processes are monitored for syscall, but only root has the permission to issue this command (see the comments for my_syscall in the starter code for more details).
REQUEST_STOP_MONITORING: stop monitoring process pid for system call syscall, i.e., remove pid from the syscall's list of monitored PIDs.

WARNING
Do NOT run on your own machine as this will override your own kernel module and possibly corrupt your system. Please create a VM and run it from there.
