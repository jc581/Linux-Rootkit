# Linux-Rootkit
Implemented a Linux kernel module capable of modifying authentication files and concealing such actions

</br>

**Rootkit Definition**

A rootkit is a collection of computer software, typically malicious, designed to enable access to a computer or areas of its software that is not otherwise allowed (ex. to an unauthorized user) and often masks its existence or the existence of other software.[1]
Rootkit installation can be automated, or an attacker can install it after having obtained root or Administrator access. 
My “attack” code is represented by a small program sneaky_process.c, which loads a kernel module sneaky_mod.c that conceals the presence of my attack program as well as some of its malicious activities.

![alt text](https://cdn.spicytricks.com/wp-content/uploads/2018/02/what-is-rootkit-min-760x216.png)



</br>
</br>








**Package Files**

My Rootkit implementation includes 3 files: 
1. sneaky_mod.c – The source code for my sneaky module with functionalities as described below.
2. sneaky_process.c – The source code for my attack program
3. Makefile – A makefile that will compile “sneaky_process.c” into 
    “sneaky_process”, and will compile “sneaky_mod.c” into “sneaky_mod.ko”


![alt text](https://mk0resourcesinfm536w.kinstacdn.com/wp-content/uploads/071515_1220_RootkitsUse1.png)
