import r2pipe

syscall = [15, 5]

#r2 = r2pipe.open('reverse_shell', flags = ['-w', '-d', '-2'])
r2 = r2pipe.open('shellcode', flags = ['-w', '-d', '-2'])

r2.cmd("aaaa")
r2.cmd("ood")
r2.cmd("db entry0")
r2.cmd("dc")

def step():
    r2.cmd('ds')
    r2.cmd('sr rip')


while True:
    try:
        step()
        register_data = r2.cmdj('arj')
        rip = hex(register_data["rip"])
        rip_drf = r2.cmdj('pxj 2 @ '+ rip)
        if rip_drf == syscall:
            print("rax:{}, rdi:{}, rsi:{}, rdx:{}, rcx:{}".format(register_data["rax"], register_data["rdi"], register_data["rsi"], register_data["rdx"], register_data["rcx"]))
            if register_data["rax"] == 59:
                print(r2.cmdj('pxj 8 @ '+hex(register_data["rdi"])))
    except Exception as e:
        print(e)
        break



"""

12 0 135168
12 93926044889088 135168
41 2 1
42 3 140723325918660
33 3 2
33 3 1
33 3 0
1 3 140723325918652
[+] SIGNAL 13 errno=0 addr=0x3e800009440 code=0 si_pid=37952 ret=0
0 3 140723325918660

"""