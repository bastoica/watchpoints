# watchpoints-kmodule
A light-weight Linux kernel module for registering and unregistering hardware watchpoints without going trhough ptrace.

# Usage
#### Install
To load the module run `register.sh` from the top directory. This automatically compiles and loads the module into the kernel.

#### Manual compilation.
To compile the module hit `make` watchpoints on the top directory. Then, load watchpoints.ko as a normal kernel module using insmod  `$path_to_watchpoints/watchpoints.ko`

