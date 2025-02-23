# Banshee

<p align="center">
<img src="./img/Banshee.jpg" alt="Banshee" width="400" />
</p>

*DISCLAIMER: This was the first driver code I ever wrote. As such, there is some pretty bad stuff in here, which you definitely should not copy.*

Learning about Windows rootkits lately, so here is my own implementation of some techniques. For an overview, see **Features** below.

Banshee is meant to be used with [kdmapper](https://github.com/TheCruZ/kdmapper) or a similar driver mapper.

I am just learning about kernel driver development, so this is for educational purposes mainly.

A few blogposts on Banshee:

* [Keylogging in the Windows kernel with undocumented data structures](https://eversinc33.com/posts/kernel-mode-keylogging/)
* [(Anti-)Anti-Rootkit Techniques - Part I: UnKovering mapped rootkits](https://eversinc33.com/posts/anti-anti-rootkit-part-i/)

## What is a Rootkit?

http://phrack.org/issues/55/5.html

## Usage

You can integrate Banshee into your tooling, by including the `Banshee.hpp` file in your project, e.g.:

```c++
Banshee banshee = Banshee();
banshee.Initialize();

int targetPid = GetDefenderPID(); // this would be your implementation
banshee.KillProcess(targetPid);   // instruct banshee to kill the targetprocess
```

An example implementation of all the features in a command line client is found in [./BansheeClient/BansheeClient.cpp](./BansheeClient/BansheeClient.cpp):

<p align="center">
<img src="./img/CLI.png" alt="Banshee CLI" width="600"/>
</p>

## Features

*Get in everyone, we're going to Kernel Land!*

#### Kill processes

`ZwTerminateProcess` is simply called from kernel land to terminate any process.

#### Change protection levels

This is done by modifying the `EPROCESS` structure, which is an kernel object that describes a processes attributes. It also holds a value that specifies the protection level of the process. 

We can directly modify this value (aka Direct Kernel Object Modification or DKOM), since we are operating in Ring 0.

#### Elevate any process token to SYSTEM

`EPROCESS` also holds a pointer to the current access token, so we can just make it point to e.g. the token of process 4 (`SYSTEM`) to elevate any process to `SYSTEM`.

#### Enumerating and erasing kernel callbacks

For now, only Process- and Thread-Creation kernel callbacks are enumerated, by parsing the `PsSetCreateNotifyProcess/ThreadRoutine` routine to reach the private `Psp*` routine and then parsing the address of the array, where kernel callbacks are stored. With `erase`, callbacks can be erased by overwriting the function pointer to point to an empty function in Banshee instead.

#### Protecting the driver file 

By hooking the NTFS filesystem's `IRP_MJ_CREATE` handler, we can block any process from opening a handle to our driver file (This will probably change to a filter driver concept soon).

#### Keylogging from the Kernel

Using the undocumented `gafAsyncKeyState` function we can parse keystrokes from a session without using any API calls besides reading memory (https://www.unknowncheats.me/forum/c-and-c-/327461-kernel-mode-key-input.html).

## Misc

#### Communication over SharedMemory

Banshee does not communicate over IOCTLs as most drivers do, but rather over shared memory. This way no `DriverObject` needs to be registered, which would point to our unbacked memory region (if mapped to memory) and would lead anti-rootkit software directly onto us. 

## Patchguard triggering features

These should only be used with a patchguard bypass or in a lab environment as they trigger BSOD.

#### Hide Process by PID

Again, `EPROCESS` comes to help here - it contains a `LIST_ENTRY` of a doubly linked list called `ActiveProcessLink` which is queried by Windows to enumerate running processes. If we simply unlink an entry here, we can hide our process from tools like Process Monitor or Task Manager. This can cause Bluescreens, e.g. when the process is closed while being hidden or due to patchguard scanning the kernel memory. While the former can be fixed by not being so lazy when programming, the latter can not be as easily bypassed from within the driver.

## Testing & debugging the driver

I recommend to enable debugging for the kernel. Run the following from an administrative prompt and reboot afterwards:

```cmd
bcdedit /debug on
```

Afterwards load the driver with [kdmapper](https://github.com/TheCruZ/kdmapper). 

You can then run the client, after compiling the solution, with e.g.:

```cmd
.\x64\Debug\BansheeClient.exe
```

Run this in a VM, debug this VM with WinDbg and create a snapshot before. You will probably Bluescreen a lot when developing.

## TODO 

* enumerating more kernel callbacks
* map the keypress array into userspace instead of running a looping kernel thread
* ETW provider disabling à la https://securityintelligence.com/posts/direct-kernel-object-manipulation-attacks-etw-providers/

## Credits

* UnknownCheats which is literally the best resource for anti-anti-rootkit stuff
* OSROnline, although even more toxic than UC still being helpful 
* Some offset code from and feature inspiration (please check out, great project): https://github.com/Idov31/Nidhogg
* Great introduction to drivers: https://www.codeproject.com/articles/9504/driver-development-part-1-introduction-to-drivers
* Great overview of techniques: https://www.cyberark.com/resources/threat-research-blog/fantastic-rootkits-and-where-to-find-them-part-1
* WinDbg and the Windows Internals book for helping me (kinda) understand what I am doing here lol
* Windows Kernel Programming by Pavel Yosifovich. Great book that I should have read before starting this
