import random
import time

# Generated instructions are stored in these lists to later get written on the appropriate files
#######################################################
now = []
smode_now = []
list_snapshots = []
dict_label_secrets_pair = {}
# Auxiliary Gadgets
#######################################################


def usertokernel(address):
    kerneladdress = address - 0x80000000 - 0x00200000
    kerneladdress = (kerneladdress + 2 ** 64) + 0x80000000
    return kerneladdress


def kerneltouser(address):
    useraddress = address + 0x80000000 + 0x002000000
    useraddress = (useraddress - 2 ** 64)
    return useraddress


def iskerneladdressmapped(address):
    found = False
    physicaladdress = kerneltouser(address)
    lowerbits = physicaladdress & 0xf000
    for entry in list_notmapped_pages:
        if entry == lowerbits:
            found = True
    return found


def loadimmkernel():
    what_address = user_address_pool[random.randrange(len(user_address_pool))]
    what_address = what_address + (random.randrange(1024) * 4)
    kerneladdress = usertokernel(what_address)
    distreg = choosereg("High-Priority", "kerneladdress")
    dict_kernel_address[distreg] = kerneladdress
    line = line_constructor("li", distreg, 0, 0, hex(kerneladdress), 0)
    print(line)
    now.append(line)
    take_snapshot(line)
    return [distreg, kerneladdress]


def bringtomappingwxr(inputreg, address, regdata):
    intaddress = int(address)
    which_store = random.randrange(len(different_stores))
    what_offset = 0
    lowerbits = (intaddress >> 12) << 12
    list_notmapped_pages.remove(lowerbits)
    dict_all_mapped_pages[lowerbits] = "daguxwrv"
    list_dcached_address.append((intaddress >> 6))
    dict_user_address[inputreg] = intaddress
    line = line_constructor("sd", regdata[0], inputreg, 0, 0, what_offset)
    print(line)
    now.append(line)
    take_snapshot(line)


def loadimmuser(from_not_mapped_pages):
    what_address = 0
    if from_not_mapped_pages:
        what_address = list_notmapped_pages[random.randrange(len(list_notmapped_pages))]
    else:
        writable_pages = find_pages_on_permission("daguxwrv")
        reasonable_pages = list_notmapped_pages + writable_pages
        what_address = random.choice(reasonable_pages)
    what_address = what_address + (random.randrange(1024) * 4)
    distreg = choosereg("High-Priority", "useraddress")
    dict_user_address[distreg] = what_address
    line = line_constructor("li", distreg, 0, 0, hex(what_address), 0)
    print(line)
    now.append(line)
    take_snapshot(line)
    return [distreg, what_address]


def loadimmdata():
    what_data = random.randrange(0xffffff)
    distreg = choosereg("High-Priority", "immdata")
    dict_divw_mul_data[distreg] = what_data
    line = line_constructor("li", distreg, 0, 0, hex(what_data), 0)
    print(line)
    now.append(line)
    take_snapshot(line)
    return distreg


def nonsecretdata(page):
    regdata = ["", 0x0]
    output_str = ""
    list_letters = ['a', 'b', 'c', 'd', 'e', 'f']
    list_digits = ['1', '2', '3', '4', '5', '6', '7', '8', '9']
    random_letter = random.choice(list_letters)
    random_digit = random.choice(list_digits)
    rate_repeat = random.randrange(1, 5)
    counter = 16 // (rate_repeat * 2)
    for i in range(counter):
        for j in range(rate_repeat):
            output_str = output_str + random_letter
        for j in range(rate_repeat):
            output_str = output_str + random_digit
    if rate_repeat == 3:
        output_str = output_str + random_letter + random_letter + random_letter + random_digit
    data = int(output_str, base=16)
    distreg = choosereg("Low-Priority", "semi_secret_holder")
    dict_page_secret_pairs[page] = data
    dict_reg_secret_pairs[distreg] = data
    regdata[0] = distreg
    regdata[1] = data
    line = line_constructor("li", distreg, 0, 0, hex(data), 0)
    print(line)
    now.append(line)
    take_snapshot(line)
    return regdata


def bringtoicache(inputreg, address):
    branchlabel = specwindowopen(4)
    list_icached_address.append(address)
    line = line_constructor("jalr", "x1", inputreg, 0, 0, 0)
    print(line)
    now.append(line)
    take_snapshot(line)
    specwindowclose(branchlabel)


def startdummybranch():
    src1 = ""
    src2 = ""
    list_all_used_registers = []
    count = 0
    for key in logical_register_file:
        if logical_register_file[key][2]:
            list_all_used_registers.append(key)
            count = count + 1
    if count == 0:
        src1 = choosereg("Low-Priority", "dummybranch")
        src2 = choosereg("Low-Priority", "dummybranch")
    elif count == 1:
        src1 = list_all_used_registers[random.randrange(len(list_all_used_registers))]
        src2 = choosereg("Low-Priority", "dummybranch")
    else:
        src1 = list_all_used_registers[random.randrange(len(list_all_used_registers))]
        src2 = list_all_used_registers[random.randrange(len(list_all_used_registers))]

    branchlabel = list_branch_labels[random.randrange(len(list_branch_labels))]
    list_branch_labels.remove(branchlabel)
    line = line_constructor("bne", 0, src1, src2, branchlabel, 0)
    print(line)
    now.append(line)
    take_snapshot(line)
    return branchlabel


def finishdummybranch(branchlabel):
    line = branchlabel
    print(line)
    now.append(line)
    take_snapshot(line)


def bringtodcache(inputreg, address):
    distreg = choosereg("Low-Priority", "loadval")
    which_load = random.randrange(len(different_loads))
    what_offset = 0
    list_dcached_address.append((address >> 6))
    load_address.append(address)
    line = line_constructor(different_loads[which_load], distreg, inputreg, 0, 0, what_offset)
    print(line)
    now.append(line)
    take_snapshot(line)


def bringtodcachestore(inputreg, address, data):
    intaddress = int(address)
    which_store = random.randrange(len(different_stores))
    what_offset = 0
    list_dcached_address.append((intaddress >> 6))
    dict_stored_address[inputreg] = intaddress
    line = line_constructor(different_stores[which_store], data, inputreg, 0, 0, what_offset)
    print(line)
    now.append(line)
    take_snapshot(line)

"""
def chooseaddress():
    what_address = user_address_pool[random.randrange(len(user_address_pool))]
    what_address = what_address + random.randrange(0x1000)
    distreg = choosereg("High-Priority", "useraddress")
    stored_address.append(what_address)
    line = line_constructor("li", distreg, 0, 0, hex(what_address), 0)
    print(line)
    now.append(line)
    take_snapshot(line)
    return distreg


def choosedata():
    what_data = list_secrets[random.randrange(len(list_secrets))]
    stored_data.append(what_data)
    distreg = choosereg("High-Priority", "usersecret")
    line = line_constructor("li", distreg, 0, 0, hex(what_data), 0)
    print(line)
    now.append(line)
    take_snapshot(line)
    return distreg
"""

def dummyexception():
    page = random.choice(list_dummy_exception_pages)
    list_dummy_exception_pages.remove(page)
    distreg = choosereg("Low-Priority", "dummy-excp-address")
    line = line_constructor("li", distreg, 0, 0, hex(page), 0)
    print(line)
    now.append(line)
    take_snapshot(line)
    which_load = random.randrange(len(different_loads))
    what_offset = random.randrange(16) * 4
    line = line_constructor(different_loads[which_load], distreg, distreg, 0, 0, 0)
    list_dcached_address.append((page >> 6))
    print(line)
    now.append(line)
    take_snapshot(line)
    return page


def smode_change_pte(input_page, dummy_page, permissions):
    list_chars = list(permissions)
    permission_bits = 0
    for i in range(len(list_chars)):
        if list_chars[i] != '-':
            j = ((-1) * i) + 7
            permission_bits = permission_bits + (2**j)
    line = line_constructor("li", "x4", 0, 0, hex(dummy_page), 0)
    line = smode_line_constructor(line, "first")
    print(line)
    smode_now.append(line)
    pte_address = find_pte_address(input_page)
    line = line_constructor("li", "x6", 0, 0, hex(pte_address), 0)
    line = smode_line_constructor(line, "mid")
    print(line)
    smode_now.append(line)
    line = line_constructor("li", "x5", 0, 0, hex(permission_bits), 0)
    line = smode_line_constructor(line, "mid")
    print(line)
    smode_now.append(line)
    line = line_constructor("ld", "x7", "x6", 0, 0, 0)
    line = smode_line_constructor(line, "mid")
    print(line)
    smode_now.append(line)
    line = line_constructor("srli", "x7", "x7", 0, 2, 0)
    line = smode_line_constructor(line, "mid")
    print(line)
    smode_now.append(line)
    line = line_constructor("slli", "x7", "x7", 0, 2, 0)
    line = smode_line_constructor(line, "mid")
    print(line)
    smode_now.append(line)
    line = line_constructor("add", "x7", "x7", "x5", 0, 0)
    line = smode_line_constructor(line, "mid")
    print(line)
    smode_now.append(line)
    label = random.choice(list_numbered_labels)
    list_numbered_labels.remove(label)
    line = line_constructor("bne", 0, "x4", "x14", label, 0)
    line = smode_line_constructor(line, "mid")
    print(line)
    smode_now.append(line)
    line = line_constructor("sd", "x7", "x6", 0, 0, 0)
    line = smode_line_constructor(line, "mid")
    print(line)
    smode_now.append(line)
    line = line_constructor("li", "x5", 0, 0, hex(input_page + 64), 0)
    line = smode_line_constructor(line, "mid")
    print(line)
    smode_now.append(line)
    line = "sfence.vma " + "x5"
    line = smode_line_constructor(line, "mid")
    print(line)
    smode_now.append(line)
    line = label.replace('f', '') + ":"
    line = smode_line_constructor(line, "last")
    print(line)
    smode_now.append(line)


def find_pte_address(invalid_page):
    diff_base_page = invalid_page - int(0x3000)
    difference = (diff_base_page >> 12) * 8
    pte_address = usertokernel(0x6018) + difference
    return pte_address


def does_it_contain(input_text, input_permission):
    itcontains = False
    list_permission = list(input_permission)
    for i in list_permission:
        if input_text.find(i) != -1:
            itcontains = True
            break
    return itcontains


def get_key(val, diction):
    for key, value in diction.items():
        if val == value:
            return key

    return "key doesn't exist"


def find_pages(off_permissions):
    output_list = []
    for item in dict_all_mapped_pages.values():
        if (does_it_contain(item, off_permissions)) == False:
            output_list.append(get_key(item, dict_all_mapped_pages))
    return output_list


def find_pages_on_permission(on_permissions):
    output_list = []
    itcontains = True
    list_permission = list(on_permissions)
    for key, value in dict_all_mapped_pages.items():
        for i in list_permission:
            if value.find(i) == -1:
                itcontains = False
                break
        #print(itcontains)
        if itcontains:
            output_list.append(key)
        itcontains = True
    return output_list


def free_reg(reg):
    if reg in dict_divw_mul_data.keys():
        del dict_divw_mul_data[reg]
    elif reg in dict_kernel_address.keys():
        del dict_kernel_address[reg]
    elif reg in dict_reg_secret_pairs.keys():
        del dict_reg_secret_pairs[reg]
    elif reg in dict_user_address.keys():
        del dict_user_address[reg]
    elif reg in dict_stored_address.keys():
        del dict_stored_address[reg]


# Analyzer (Beta Version)
#####################################################################

def does_it_contain_analyzer(input_text, permission):
    itcontains = False
    if permission in input_text:
        itcontains = True
    return itcontains


def get_key_analyzer(val, diction):
    for key, value in diction.items():
        if val == value:
            return key

    return "key doesn't exist"


def find_pages_analyzer(off_permissions, diction):
    output_set = set()
    list_permission = list(off_permissions)
    for perm in list_permission:
        for key, value in diction.items():
            if (does_it_contain_analyzer(value, perm)) == False:
                output_set.add(key)
    return output_set

#####################################################################


def take_snapshot(line):
    list_current_secrets = []
    for entry in list_kernel_secrets:
        list_current_secrets.append(entry)
    if line.startswith('Permission'):
        result_set = find_pages_analyzer("avr", snapshot["dict_all_mapped_pages"])
        for i in result_set:
            list_current_secrets.append(dict_page_secret_pairs[i])
        if len(dict_label_secrets_pair) > 0:
            if list(dict_label_secrets_pair.values())[len(dict_label_secrets_pair) - 1] != list_current_secrets:
                line = line.replace(':', '')
                dict_label_secrets_pair[line] = list_current_secrets
        else:
            line = line.replace(':', '')
            dict_label_secrets_pair[line] = list_current_secrets


def choosereg(priority, usage):
    for key in logical_register_file:
        val = logical_register_file[key]
        if (val[2] == False):
            logical_register_file[key] = [priority, usage, True]
            return key
    for key in logical_register_file:
        val = logical_register_file[key]
        if (val[2] == True) and (val[0] == "Low-Priority"):
            logical_register_file[key][2] = False
            free_reg(key)
    for key in logical_register_file:
        if logical_register_file[key][2] == False:
            logical_register_file[key] = [priority, usage, True]
            return key
    for key in logical_register_file:
        logical_register_file[key][2] = False
        free_reg(key)
    for key in logical_register_file:
        if logical_register_file[key][2] == False:
            logical_register_file[key] = [priority, usage, True]
            return key
    return "????"


def find_reg_secret_pair(secret):
    if secret in dict_reg_secret_pairs.values():
        key = get_key(secret, dict_reg_secret_pairs)
        return key
    return "NotFound"


def find_page_secret_pair(address):
    page = address >> 12
    page = page << 12
    regdata = ["", 0]
    if page in dict_page_secret_pairs.keys():
        secret = dict_page_secret_pairs[page]
        reg = find_reg_secret_pair(secret)
        if reg == "NotFound":
            regdata = []
            distreg = choosereg("Low-Priority", "semi_secret_holder")
            dict_reg_secret_pairs[distreg] = secret
            regdata.append(distreg)
            regdata.append(secret)
            line = line_constructor("li", distreg, 0, 0, hex(secret), 0)
            print(line)
            now.append(line)
            take_snapshot(line)
            return regdata
        else:
            regdata[0] = reg
            regdata[1] = secret
            return regdata
    else:
        secret = 0
        regdata = []
        list_all_prefill_pages = list_should_be_filled_user_pages + list_filled_up_user_pages
        if page in list_all_prefill_pages:
            mask = page >> 12
            if mask == 3:
                secret = 0x3a3a3a3a3a3a3a3a
            elif mask == 4:
                secret = 0x4a4a4a4a4a4a4a4a
            elif mask == 5:
                secret = 0x5a5a5a5a5a5a5a5a
            elif mask == 6:
                secret = 0x6a6a6a6a6a6a6a6a
            elif mask == 7:
                secret = 0x7a7a7a7a7a7a7a7a
            distreg = choosereg("Low-Priority", "page_secret_holder")
            dict_reg_secret_pairs[distreg] = secret
            dict_page_secret_pairs[page] = secret
            regdata[0] = distreg
            regdata[1] = secret
            line = line_constructor("li", distreg, 0, 0, hex(secret), 0)
            print(line)
            now.append(line)
            take_snapshot(line)
            return regdata
        else:
            regdata = nonsecretdata(page)
            return regdata



def line_constructor(operand, dist, src1, src2, imm, offset):
    if operand == "fence":
        line = operand + " " + src1 + ", " + src2 + "; \\" + "\n"
    elif operand == "li" or operand == "jal":
        line = operand + " " + str(dist) + ", " + str(imm) + "; \\" + "\n"
    elif operand == "ld" or operand == "lw" or operand == "lh" or operand == "lb" or operand == "lb" or operand == "sd"\
            or operand == "sw" or operand == "sh" or operand == "sb" or operand == "jalr":
        line = operand + " " + str(dist) + ", " + str(offset) + "(" + str(src1) + ")" + "; \\" + "\n"
    elif operand == "add" or operand == "mul" or operand == "divw" or operand == "sub" or operand == "and":
        line = operand + " " + dist + ", " + src1 + "," + src2 + "; \\" + "\n"
    elif operand == "addi" or operand == "muli" or operand == "divwi" or operand == "andi" or operand == "ori" or\
            operand == "xori" or operand == "srli" or operand == "slli":
        line = operand + " " + dist + ", " + src1 + "," + str(imm) + "; \\" + "\n"
    elif operand == "beq" or operand == "bne" or operand == "bge" or operand == "blt" or operand == "bgeu" or operand == "bltu":
        line = operand + " " + src1 + ", " + src2 + ", " + imm + "; \\" + "\n"
    else:
        line = "BlackLivesMatter"
        print(operand)
        now.append(line)
        take_snapshot(line)
    return line


def smode_line_constructor(line, pos):
    line = line.replace("; \\\n", '')
    if pos == "first":
        line = "asm volatile (\"" + line + "\\n\\t" + "\"" + "\n"
    if pos == "mid":
        line = "\"" + line + "\\n\\t" + "\"" + "\n"
    if pos == "last":
        line = "\"" + line + "\"" + ");" + "\n"
    return line

#######################################################

# Initialization (Execution Model)
#######################################################
specexec = False
speclabel = ""
lastspeclabel = ""
logical_register_file = dict(x3=["", "", False], x4=["", "", False], x5=["", "", False], x6=["", "", False],
                             x7=["", "", False], x8=["", "", False], x9=["", "", False], x10=["", "", False],
                             x11=["", "", False], x12=["", "", False], x13=["", "", False], x14=["", "", False],
                             x15=["", "", False], x16=["", "", False], x17=["", "", False], x18=["", "", False],
                             x19=["", "", False], x20=["", "", False], x21=["", "", False], x22=["", "", False],
                             x23=["", "", False], x24=["", "", False], x25=["", "", False], x26=["", "", False],
                             x27=["", "", False],x28=["", "", False], x29=["", "", False], x30=["", "", False],
                             x31=["", "", False])
dict_all_mapped_pages = {}
list_dummy_exception_pages = [0x30000, 0x31000, 0x32000, 0x33000, 0x34000, 0x35000, 0x36000, 0x37000, 0x38000, 0x39000,
                              0x3a000, 0x3b000, 0x3c000, 0x3d000, 0x3e000, 0x3f000, 0x40000, 0x41000, 0x42000, 0x43000]
dict_divw_mul_data = {}
dict_kernel_address = {}
dict_user_address = {}

stored_address = []
stored_address_reg = []
dict_stored_address = {}


load_address = []
list_dcached_address = []
list_icached_address = []
user_address_pool = [0x3000, 0x4000, 0x5000, 0x6000, 0x7000, 0x8000, 0x9000, 0xa000, 0xb000, 0xc000, 0xd000, 0xe000,
                     0xf000]
list_notmapped_pages = [0x3000, 0x4000, 0x5000, 0x6000, 0x7000, 0x8000, 0x9000, 0xa000, 0xb000, 0xc000, 0xd000, 0xe000,
                        0xf000]
list_filled_up_user_pages = []
list_should_be_filled_user_pages = [0x3000, 0x4000, 0x5000, 0x6000, 0x7000]
dict_page_secret_pairs = {0x3000: 0x3a3a3a3a3a3a3a3a, 0x4000: 0x4a4a4a4a4a4a4a4a, 0x5000: 0x5a5a5a5a5a5a5a5a,
                          0x6000: 0x6a6a6a6a6a6a6a6a, 0x7000: 0x7a7a7a7a7a7a7a7a}
dict_reg_secret_pairs = {}
list_kernel_secrets = [0x88888888, 0x99999999, 0xaaaaaaaa, 0xbbbbbbbb, 0xcccccccc, 0xdddddddd, 0xeeeeeeee,
                            0xffffffffffffffff]
list_permission_labels = ["Permission1", "Permission2", "Permission3", "Permission4", "Permission5",
                          "Permission6", "Permission7", "Permission8", "Permission9", "Permission10",
                          "Permission11", "Permission12", "Permission13", "Permission14", "Permission15",
                          "Permission16", "Permission17", "Permission18", "Permission19", "Permission20"]
list_aux_gadgets = ["Dummy Exception", "Delay", "Setup Code", "Stores", "Loads", "ALU/Div/Mul"]
list_main_gadgets = ["Meltdown-US", "RandomInst", "Meltdown-JP", "St/Ld Forwarding", "ShortDelay",
                     "Play-Permission-Bits", "Prime-LFB", "Fill-Up-User-Pages"]
list_delay_insts = ["divw", "mul"]
list_delay_labels = ["Delay", "Delay1", "Delay2", "Delay3", "Delay4", "Delay5"]
list_branch_labels = ["DummyBranch:", "DummyBranch1:", "DummyBranch2:", "DummyBranch3:", "DummyBranch4:",
                      "DummyBranch5:"]
list_fill_up_labels = ["Fill1", "Fill2", "Fill3", "Fill4", "Fill5", "Fill6", "Fill7"]
list_spec_labels = ["Speculated", "Speculated1", "Speculated2", "Speculated3", "Speculated4", "Speculated5",
                    "Speculated6", "Speculated7", "Speculated8", "Speculated9", "Speculated10", "Speculated11",
                    "Speculated12", "Speculated13", "Speculated14", "Speculated15", "Speculated16",
                    "Speculated17", "Speculated18", "Speculated19", "Speculated20", "Speculated21",
                    "Speculated22", "Speculated23", "Speculated24", "Speculated25", "Speculated26",
                    "Speculated27", "Speculated28", "Speculated29", "Speculated30", "Speculated31",
                    "Speculated32", "Speculated33", "Speculated34", "Speculated35", "Speculated36"]
list_numbered_labels = ["20f", "21f", "22f", "23f", "24f", "25f", "26f", "27f", "28f", "29f", "30f", "31f",
                        "32f", "33f", "34f", "35f", "36f", "37f", "38f", "39f", "40f"]
list_secrets = [0xdeadbeefdeadbeef, 0xfadafadafadafada, 0x3333333333333333, 0x4444444444444444, 0x5555555555555555,
                0x6666666666666666, 0x7777777777777777, 0x8888888888888888]
different_loads = {0: "ld", 1: "lw", 2: "lh", 3: "lb"}
different_stores = {0: "sd", 1: "sw", 2: "sh", 3: "sb"}
different_branches = ["beq", "bne", "bge", "blt", "bgeu", "bltu"]
different_instructions = ["add", "sub"]
included_gadgets = []
included_main_gadgets = []
isoutput_valid = False
# Here is the main snapshot of the Execution Model
snapshot = {"list_numbered_labels": list_numbered_labels, "list_spec_labels": list_spec_labels,
            "list_fill_up_labels": list_fill_up_labels, "list_branch_labels": list_branch_labels,
            "list_delay_labels": list_delay_labels, "list_should_be_filled_user_pages": list_should_be_filled_user_pages,
            "list_filled_up_user_pages": list_filled_up_user_pages, "list_notmapped_pages": list_notmapped_pages,
            "dict_page_secret_pairs": dict_page_secret_pairs, "dict_reg_secret_pairs": dict_reg_secret_pairs,
            "user_address_pool": user_address_pool, "list_icached_address": list_icached_address,
            "list_dcached_address": list_dcached_address, "dict_stored_address": dict_stored_address,
            "dict_user_address": dict_user_address, "dict_kernel_address": dict_kernel_address,
            "dict_divw_mul_data": dict_divw_mul_data,
            "list_dummy_exception_pages": list_dummy_exception_pages, "dict_all_mapped_pages": dict_all_mapped_pages,
            "logical_register_file": logical_register_file, "speclabel": speclabel}

list_snapshots.append(snapshot)
#######################################################


# Gadgets
#######################################################
def meltdown_us():
    regdata = ["", 0]
    found = False
    if len(dict_kernel_address) != 0:
        if random.randrange(2) > 0:
            keys_list = list(dict_kernel_address.keys())
            regdata[0] = random.choice(keys_list)
            regdata[1] = dict_kernel_address[regdata[0]]
        else:
            regdata = loadimmkernel()
    else:
        regdata = loadimmkernel()
    for entry in list_dcached_address:
        if entry == (regdata[1] >> 6):
            found = True
            break
    if not found:
        if iskerneladdressmapped(regdata[1]):
            list_dcached_address.append((regdata[1] >> 6))
        else:
            mapped = True
            lowerbits = kerneltouser(regdata[1]) & 0xf000
            for entry in list_notmapped_pages:
                if entry == lowerbits:
                    mapped = False
            if not mapped:
                regdata_nonsecret = find_page_secret_pair(kerneltouser(regdata[1]))
                bringtomappingwxr(regdata[0], kerneltouser(regdata[1]), regdata_nonsecret)
    speclabel = specwindowopen(2)
    output = choosereg("Low-Priority", "kernelval")
    which_load = random.randrange(len(different_loads))
    what_offset = random.randrange(16) * 4
    line = line_constructor(different_loads[which_load], output, regdata[0], 0, 0, what_offset)
    print(line)
    now.append(line)
    take_snapshot(line)
    specwindowclose(speclabel)


def meltdown_jp():
    line = ""
    regdata = []
    storeregdata = ["", 0]
    dict_reasonable_pages = {}
    writable_pages = find_pages_on_permission("daguxwrv")
    for key, value in dict_stored_address.items():
        if ((value >> 12) << 12) in writable_pages:
            dict_reasonable_pages[key] = value
    # Use the previously mapped pages that are mapped with "daguxwrv" permissions
    if len(dict_reasonable_pages) != 0 and random.randrange(2) > 0:
        keys_list = list(dict_reasonable_pages.keys())
        storeregdata[0] = random.choice(keys_list)
        storeregdata[1] = dict_stored_address[storeregdata[0]]
        bringtoicache(storeregdata[0], storeregdata[1])
        which_store = random.randrange(len(different_stores))
        regdata = find_page_secret_pair(storeregdata[1])
        line = line_constructor(different_stores[which_store], regdata[0], storeregdata[0], 0, 0, 0)
        print(line)
        now.append(line)
        take_snapshot(line)
        speclabel = specwindowopen(4)
        line = line_constructor("jalr", "x1", storeregdata[0], 0, 0, 0)
        print(line)
        now.append(line)
        take_snapshot(line)
        specwindowclose(speclabel)
    # Use the previously mapped pages that are mapped with "daguxwrv" permissions
    else:
        storeregdata = loadimmuser(True)
        regdata = find_page_secret_pair(storeregdata[1])
        bringtomappingwxr(storeregdata[0], storeregdata[1], regdata)
        speclabel = specwindowopen(1)
        line = line_constructor("jalr", "x1", storeregdata[0], 0, 0, 0)
        print(line)
        now.append(line)
        take_snapshot(line)
        specwindowclose(speclabel)


def play_with_permission_bits():
    list_pages = []
    notpermission = []
    list_permission_gadgets = ["read_invalid_page", "read_exe_only_page", "read_no_permis_page", "read_acc_off_page",
                               "read_dirt_off_page","read_acc_dirt_off_page", "read_user_off_page",
                               "read_glob_off_page", "read_random_permis_page"]
    what_gadget = random.choice(list_permission_gadgets)
    permissions = "--------"
    if what_gadget == "read_invalid_page":
        permissions = "daguxwr-"
        list_pages = find_pages("v")
    elif what_gadget == "read_exe_only_page":
        permissions = "dagux--v"
        list_pages = find_pages("wr")
    elif what_gadget == "read_no_permis_page":
        permissions = "dagu---v"
        list_pages = find_pages("xwr")
    elif what_gadget == "read_acc_off_page":
        permissions = "d-guxwrv"
        list_pages = find_pages("a")
    elif what_gadget == "read_dirt_off_page":
        permissions = "-aguxwrv"
        list_pages = find_pages("d")
    elif what_gadget == "read_acc_dirt_off_page":
        permissions = "--guxwrv"
        list_pages = find_pages("da")
    elif what_gadget == "read_user_off_page":
        permissions = "dag-xwrv"
        list_pages = find_pages("u")
    elif what_gadget == "read_glob_off_page":
        permissions = "da-uxwrv"
        list_pages = find_pages("g")
    elif what_gadget == "read_random_permis_page":
        permissions = "daguxwrv"
        list_permission = list(permissions)
        for i in range(0, len(permissions)):
            if random.randrange(2) > 0:
                notpermission.append(list_permission[i])
                list_permission[i] = '-'
        list_pages = find_pages("".join(notpermission))
    # Use existing mapped pages to find a page with requested permissions
    if (len(list_pages) != 0) and (random.randrange(2) > 0):
        what_page = list_pages[random.randrange(len(list_pages))]
        what_address = what_page + (random.randrange(1024) * 4)
        distreg = choosereg("Low-Priority", "play-permission-value")
        speclabel = specwindowopen(2)
        line = line_constructor("li", distreg, 0, 0, hex(what_address), 0)
        print(line)
        now.append(line)
        take_snapshot(line)
        which_load = random.randrange(len(different_loads))
        what_offset = random.randrange(16) * 4
        line = line_constructor(different_loads[which_load], distreg, distreg, 0, 0, what_offset)
        list_dcached_address.append((what_address >> 6))
        print(line)
        now.append(line)
        take_snapshot(line)
        specwindowclose(speclabel)
    else:
        # Map a new page with full permissions, then change the permissions.
        if random.randrange(2) > 0 or (not(dict_all_mapped_pages)):
            what_page = random.choice(list_notmapped_pages)
            what_address = what_page + (random.randrange(1024) * 4)
            distreg = choosereg("High-Priority", "play-permission-value")
            line = line_constructor("li", distreg, 0, 0, hex(what_address), 0)
            print(line)
            now.append(line)
            take_snapshot(line)
            what_offset = random.randrange(8) * 8
            semi_secret = find_page_secret_pair(what_page)
            line = line_constructor("sd", semi_secret[0], distreg, 0, 0, what_offset)
            list_dcached_address.append((what_address >> 6))
            print(line)
            now.append(line)
            take_snapshot(line)
            dummy_page = dummyexception()
            line = random.choice(list_permission_labels)
            list_permission_labels.remove(line)
            line = line + ":"
            print(line)
            now.append(line)
            smode_change_pte(what_page, dummy_page, permissions)
            dict_all_mapped_pages[what_page] = permissions
            take_snapshot(line)
            which_load = random.randrange(len(different_loads))
            #what_offset = random.randrange(16) * 4
            line = line_constructor(different_loads[which_load], distreg, distreg, 0, 0, what_offset)
            speclabel= specwindowopen(2)
            print(line)
            now.append(line)
            take_snapshot(line)
            specwindowclose(speclabel)
        else:
            # Use existing mapped pages to change their permission
            temp_mapped_pages_list = list(dict_all_mapped_pages.keys())
            pages_to_choose_list = [page for page in temp_mapped_pages_list if page not in list_pages]
            if not pages_to_choose_list:
                return
            random_page = random.choice(pages_to_choose_list)
            what_address = random_page + (random.randrange(1024) * 4)
            dummy_page = dummyexception()
            line = random.choice(list_permission_labels)
            list_permission_labels.remove(line)
            line = line + ":"
            print(line)
            now.append(line)
            #take_snapshot("*******----Supervisor Code Start----*******")
            smode_change_pte(random_page, dummy_page, permissions)
            dict_all_mapped_pages[random_page] = permissions
            take_snapshot(line)
            #take_snapshot("*******----Supervisor Code End----*******")
            distreg = choosereg("Low-Priority", "play-permission-value")
            line = line_constructor("li", distreg, 0, 0, hex(what_address), 0)
            print(line)
            now.append(line)
            take_snapshot(line)
            which_load = random.randrange(len(different_loads))
            what_offset = random.randrange(16) * 4
            line = line_constructor(different_loads[which_load], distreg, distreg, 0, 0, what_offset)
            list_dcached_address.append((what_address >> 6))
            speclabel = specwindowopen(2)
            print(line)
            now.append(line)
            take_snapshot(line)
            specwindowclose(speclabel)


def st_ld_forwarding():
    regdata = ["", 0x0]
    found = False
    dict_reasonable_adresses = {}
    writable_pages = find_pages_on_permission("daguxwrv")
    for key, value in dict_stored_address.items():
        if ((value >> 12) << 12) in writable_pages:
            dict_reasonable_adresses[key] = value
    if len(dict_reasonable_adresses) != 0:
        if random.randrange(2) > 0:
            keys_list = list(dict_reasonable_adresses.keys())
            regdata[0] = random.choice(keys_list)
            regdata[1] = dict_stored_address[regdata[0]]
        else:
            regdata = loadimmuser(False)
    else:
        regdata = loadimmuser(False)
    for entry in list_dcached_address:
        if entry == (regdata[1] >> 6):
            found = True
            break
    mapped = True
    if not found:
        lowerbits = (regdata[1] >> 12) << 12
        for entry in list_notmapped_pages:
            if entry == lowerbits:
                mapped = False
        if not mapped:
            regdata_semi_secret = find_page_secret_pair(regdata[1])
            bringtomappingwxr(regdata[0], regdata[1], regdata_semi_secret)
            distreg = choosereg("Low-Priority", "stld-forwarding-val")
            which_load = random.randrange(len(different_loads))
            "what_offset = random.randrange(16) * 4"
            line = line_constructor(different_loads[which_load], distreg, regdata[0], 0, 0, 0)
            print(line)
            now.append(line)
            take_snapshot(line)
        else:
            regdata_semi_secret = find_page_secret_pair(regdata[1])
            bringtodcachestore(regdata[0], regdata[1], regdata_semi_secret[0])
            distreg = choosereg("Low-Priority", "stld-forwarding-val")
            which_load = random.randrange(len(different_loads))
            line = line_constructor(different_loads[which_load], distreg, regdata[0], 0, 0, 0)
            print(line)
            now.append(line)
            take_snapshot(line)
    else:
        distreg = choosereg("Low-Priority", "stld-forwarding-val")
        which_store = random.randrange(len(different_stores))
        which_load = random.randrange(len(different_loads))
        what_offset = random.randrange(16) * 4
        regdata_semi_secret = find_page_secret_pair(regdata[1])
        line = line_constructor(different_stores[which_store], regdata_semi_secret[0], regdata[0], 0, 0, what_offset)
        print(line)
        now.append(line)
        take_snapshot(line)
        line = line_constructor(different_loads[which_load], distreg, regdata[0], 0, 0, what_offset)
        print(line)
        now.append(line)
        take_snapshot(line)


def fill_up_user_pages():
    random_page = random.choice(list_should_be_filled_user_pages)
    if random_page in list_notmapped_pages:
        #print("kalle dooghi" + hex(random_page))
        list_notmapped_pages.remove(random_page)
        dict_all_mapped_pages[random_page] = "daguxwrv"
        list_should_be_filled_user_pages.remove(random_page)
        list_filled_up_user_pages.append(random_page)
    else:
        if dict_all_mapped_pages[random_page] == "daguxwrv":
            list_should_be_filled_user_pages.remove(random_page)
            list_filled_up_user_pages.append(random_page)
        else:
            return
    mask = random_page >> 12
    immval = 0
    if mask == 3:
        immval = 0x3a3a3a3a3a3a3a3a
    elif mask == 4:
        immval = 0x4a4a4a4a4a4a4a4a
    elif mask == 5:
        immval = 0x5a5a5a5a5a5a5a5a
    elif mask == 6:
        immval = 0x6a6a6a6a6a6a6a6a
    elif mask == 7:
        immval = 0x7a7a7a7a7a7a7a7a
    distreg_data = choosereg("High-Priority", "fill-up-user-page-data")
    line = line_constructor("li", distreg_data, 0, 0, hex(immval), 0)
    dict_reg_secret_pairs[distreg_data] = immval
    print(line)
    now.append(line)
    take_snapshot(line)
    distreg = choosereg("High-Priority", "fill-up-user-page-address")
    line = line_constructor("li", distreg, 0, 0, hex(random_page), 0)
    print(line)
    now.append(line)
    take_snapshot(line)
    counter_reg = choosereg("High-Priority", "fill-up-user-page-counter")
    line = line_constructor("li", counter_reg, 0, 0, 64, 0)
    print(line)
    now.append(line)
    take_snapshot(line)
    line1 = line_constructor("sd", distreg_data, distreg, 0, 0, 0)
    label = random.choice(list_fill_up_labels)
    list_fill_up_labels.remove(label)
    line1 = label + ":" + line1
    line2 = line_constructor("sd", distreg_data, distreg, 0, 0, 8)
    line3 = line_constructor("sd", distreg_data, distreg, 0, 0, 16)
    line4 = line_constructor("sd", distreg_data, distreg, 0, 0, 24)
    line5 = line_constructor("sd", distreg_data, distreg, 0, 0, 32)
    line6 = line_constructor("sd", distreg_data, distreg, 0, 0, 40)
    line7 = line_constructor("sd", distreg_data, distreg, 0, 0, 48)
    line8 = line_constructor("sd", distreg_data, distreg, 0, 0, 56)
    line9 = line_constructor("addi", counter_reg, counter_reg, 0, -1, 0)
    line10 = line_constructor("addi", distreg, distreg, 0, 64, 0)
    line = line_constructor("bne", 0, counter_reg, "x0", label, 0)
    print(line1)
    now.append(line1)
    take_snapshot(line1)
    print(line2)
    now.append(line2)
    take_snapshot(line2)
    print(line3)
    now.append(line3)
    take_snapshot(line3)
    print(line4)
    now.append(line4)
    take_snapshot(line4)
    print(line5)
    now.append(line5)
    take_snapshot(line5)
    print(line6)
    now.append(line6)
    take_snapshot(line6)
    print(line7)
    now.append(line7)
    take_snapshot(line7)
    print(line8)
    now.append(line8)
    take_snapshot(line8)
    print(line9)
    now.append(line9)
    take_snapshot(line9)
    print(line10)
    now.append(line10)
    take_snapshot(line10)
    print(line)
    now.append(line)
    take_snapshot(line)


def prime_lfb():
    list_secret_mapped_pages = find_pages("v") + find_pages("r") + find_pages("a")
    if not list_secret_mapped_pages:
        return
    random_page = random.choice(list_secret_mapped_pages)
    random_address = random_page + (random.randrange(1024) * 4)
    found = False
    while found == False:
        for entry in list_dcached_address:
            if entry == (random_address >> 6):
                random_address = random_page + (random.randrange(1024) * 4)
                found = True
                break
        if found == True:
            found = False
        elif found == False:
            found = True
    list_dcached_address.append(random_address >> 6)
    speclabel = specwindowopen(1)
    distreg = choosereg("Low-Priority", "prime-lfb-val")
    line = line_constructor("li", distreg, 0, 0, hex(random_address), 0)
    print(line)
    now.append(line)
    take_snapshot(line)
    what_offset = random.randrange(16) * 4
    line = line_constructor("lw", distreg, distreg, 0, 0, what_offset)
    print(line)
    now.append(line)
    take_snapshot(line)
    specwindowclose(speclabel)


def randominst():
    inst = different_instructions[random.randrange(len(different_instructions))]
    list_all_used_registers = []
    count = 0
    for key in logical_register_file:
        if logical_register_file[key][2]:
            list_all_used_registers.append(key)
            count = count + 1
    if count == 0:
        src1 = choosereg("Low-Priority", "random-inst")
        src2 = choosereg("Low-Priority", "random-inst")
    else:
        src1 = list_all_used_registers[random.randrange(len(list_all_used_registers))]
        src2 = list_all_used_registers[random.randrange(len(list_all_used_registers))]
    distreg = choosereg("Low-Priority", "random-inst")
    line = line_constructor(inst, distreg, src1, src2, 0, 0)
    print(line)
    now.append(line)
    take_snapshot(line)


def shortdelay(label):
    keys_list = list(dict_divw_mul_data.keys())
    if len(keys_list) >= 2:
        if random.randrange(2) > 0:
            src1 = random.choice(keys_list)
            src2 = random.choice(keys_list)
        else:
            src1 = loadimmdata()
            src2 = loadimmdata()
    else:
        src1 = loadimmdata()
        src2 = loadimmdata()
    inst = list_delay_insts[random.randrange(len(list_delay_insts))]
    distreg = choosereg("Low-Priority", "shortdelay")
    line = line_constructor(inst, distreg, src1, src2, 0, 0)
    print(line)
    now.append(line)
    take_snapshot(line)
    list_temp = list(dict_user_address.keys()) + list(dict_divw_mul_data.keys()) + list(dict_kernel_address.keys())
    tempreg = random.choice(list_temp)
    while tempreg == distreg:
        tempreg = list_temp[random.randrange(len(list_temp))]
    linelabel = list_delay_labels[random.randrange(len(list_delay_labels))]
    list_delay_labels.remove(linelabel)
    line = line_constructor("bne", 0, distreg, tempreg, linelabel, 0)
    print(line)
    now.append(line)
    take_snapshot(line)
    numberofrandominsts = random.randrange(5)
    for i in range(numberofrandominsts):
        randominst()
    print(linelabel + ":")
    now.append(linelabel + ":")
    take_snapshot(line)


def specwindowopen(intensity):
    list_all_used_registers = []
    count = 0
    for key in logical_register_file:
        if logical_register_file[key][2]:
            list_all_used_registers.append(key)
            count = count + 1
    if count == 0:
        src1 = loadimmdata()
        src2 = loadimmdata()
    elif count == 1:
        src1 = list_all_used_registers[random.randrange(len(list_all_used_registers))]
        src2 = loadimmdata()
    else:
        src1 = list_all_used_registers[random.randrange(len(list_all_used_registers))]
        src2 = list_all_used_registers[random.randrange(len(list_all_used_registers))]
    distreg = choosereg("Low-Priority", "specwindow")
    src0 = loadimmdata()
    line1 = line_constructor("divw", distreg, src1, src2, 0, 0)
    line2 = line_constructor("divw", src2, src1, distreg, 0, 0)
    line3 = line_constructor("divw", src1, src2, distreg, 0, 0)
    line4 = line_constructor("divw", distreg, src2, src1, 0, 0)
    passing_reg = ""

    if intensity == 4:
        print(line1)
        now.append(line1)
        take_snapshot(line1)
        print(line2)
        now.append(line2)
        take_snapshot(line2)
        print(line3)
        now.append(line3)
        take_snapshot(line3)
        print(line4)
        now.append(line4)
        take_snapshot(line4)
        passing_reg = distreg
    elif intensity == 3:
        print(line1)
        now.append(line1)
        take_snapshot(line1)
        print(line2)
        now.append(line2)
        take_snapshot(line2)
        print(line3)
        now.append(line3)
        take_snapshot(line3)
        passing_reg = src1
    elif intensity == 2:
        print(line1)
        now.append(line1)
        take_snapshot(line1)
        print(line2)
        now.append(line2)
        take_snapshot(line2)
        passing_reg = src2
    elif intensity == 1:
        print(line1)
        now.append(line1)
        take_snapshot(line1)
        passing_reg = distreg
    if count == 0:
        logical_register_file[src1][2] = False
        logical_register_file[src2][2] = False
    label = random.choice(list_spec_labels)
    list_spec_labels.remove(label)
    line = line_constructor("bne", 0, passing_reg, src0, label, 0)
    print(line)
    now.append(line)
    take_snapshot(line)
    return label


def specwindowclose(label):
    line = label + ":"
    print(line)
    now.append(line)
    take_snapshot(line)



#######################################################
# Main
#######################################################
main_lengh = len(list_main_gadgets)
# Number of gadgets we are going to use
num_gadgets = 10
for i in range(num_gadgets):
    gadget_selector = random.randrange(main_lengh)
    included_main_gadgets.append(list_main_gadgets[gadget_selector])
# how many of these gadgets are going to be executed speculatively
# (This means there should be branch wrapped around these gadgets)
counter = 0
for entry in included_main_gadgets:
    if entry == "Meltdown-US":
        meltdown_us()
    elif entry == "Meltdown-JP":
        meltdown_jp()
    elif entry == "Fill-Up-User-Pages":
        fill_up_user_pages()
    elif entry == "Prime-LFB":
        prime_lfb()
    elif entry == "RandomInst":
        randominst()
    elif entry == "St/Ld Forwarding":
        numofcalls = random.randrange(4)
        for i in range(numofcalls):
            st_ld_forwarding()
    elif entry == "Play-Permission-Bits":
        numofcalls = random.randrange(10)
        for i in range(numofcalls):
            play_with_permission_bits()
    elif entry == "ShortDelay":
        st_ld_forwarding()
        shortdelay("Delay")
    if entry == included_main_gadgets[len(included_main_gadgets) - 1] and specexec == True:
        specwindowclose(speclabel)
        specexec = False


# Executive Scripts
#####################################################################
print("Preparing vm.c for kernel setup gadgets! ----------------> Started!")
lines = []
index = 0
with open('/home/ghaniyoun/ghan/chipyard/toolchains/riscv-tools/riscv-tests/env/v/vm.c',
          'r') as file:
    lines = file.readlines()
    for line in lines:
        if line.strip("\n") == "//Fuzzer_Added_Code_End":
            index = lines.index(line)
list_before = [lines[i] for i in range(156)]
list_after = [lines[i] for i in range(index, len(lines))]
#now.append("add x5, x5, x5 \\" + "\n" + "\n")
list_final = list_before + smode_now + list_after
with open('/home/ghaniyoun/ghan/chipyard/toolchains/riscv-tools/riscv-tests/env/v/vm.c',
          'w') as file:
    file.writelines(list_final)
print("Preparing vm.c for kernel setup gadgets! ----------------> Successful!")
print()
print("Preparing test_macros.h for main/aux gadgets! ----------------> Started!")
lines = []
index = 0
with open('/home/ghaniyoun/ghan/chipyard/toolchains/riscv-tools/riscv-tests/isa/macros/scalar/test_macros.h',
          'r') as file:
    # read a list of lines into data
    lines = file.readlines()
    for line in lines:
        if line.strip("\n") == "//ThisIsTheEnd":
            index = lines.index(line)
list_before = [lines[i] for i in range(41)]
# print(list_before)
list_after = [lines[i] for i in range(index, len(lines))]
now.append("add x5, x5, x5 \\" + "\n" + "\n")
list_final = list_before + now + list_after
# now change the 2nd line, note that you have to add a newline
with open('/home/ghaniyoun/ghan/chipyard/toolchains/riscv-tools/riscv-tests/isa/macros/scalar/test_macros.h',
          'w') as file:
    file.writelines(list_final)
print("Preparing test_macros.h for main/aux gadgets! ----------------> Successful!")

print()

print("Preparing AddressFooler.S for fuzzing! ----------------> Started!")
inside = []
with open('/home/ghaniyoun/ghan/chipyard/toolchains/riscv-tools/riscv-tests/isa/rv64ui/AddressFooler.S', 'r') as file:
    inside = file.readlines()

    if inside[len(inside) - 1].strip("\n") != "RVTEST_DATA_END":
        inside.pop(len(inside) - 1)
        with open('/home/ghaniyoun/ghan/chipyard/toolchains/riscv-tools/riscv-tests/isa/rv64ui/AddressFooler.S',
                  'w') as file:
            file.writelines(inside)
    else:
        inside.append("\n")
        with open('/home/ghaniyoun/ghan/chipyard/toolchains/riscv-tools/riscv-tests/isa/rv64ui/AddressFooler.S',
                  'w') as file:
            file.writelines(inside)
print("Preparing AddressFooler.S for fuzzing! ----------------> Successful!")

print()

print("Printing out all permission change, secret pairs")
for key, value in dict_label_secrets_pair.items():
    print(key)
    print("[")
    for i in value:
        print(hex(i))
    print("]")



import os

test = os.system("cd /home/ghaniyoun/ghan/chipyard/toolchains/riscv-tools/riscv-tests/ && make && make install")
print("Verilator RTL Simulation! ----------------> Started!")
test1 = os.system(
    "cd /home/ghaniyoun/ghan/chipyard/sims/verilator/ && ./simulator-chipyard-SmallBoomConfig +verbose /home/ghaniyoun/ghan/chipyard/scripts/riscv-tools-install/target/share/riscv-tests/isa/rv64ui-v-AddressFooler 2>log2.txt")
print("Verilator RTL Simulation! ----------------> Successful!")
# print(main_lengh, list_main_gadgets[0], logical_register_file["x3"])
#######################################################







print("Analyzer! ----------------> Started!")








### Check whether we have a user page secret. If not, we should add kernel default secrets to dict_label_secrets
if not dict_label_secrets_pair:
    dict_label_secrets_pair["Kernel Secrets"] = list_kernel_secrets
# Analyzer (Beta Version)
#####################################################################
dict_label_PC = {}
dict_PC_secrets = {}
list_secrets_linenumber = []

print("Creating Label-PC pairs!................")
# Create Label-PC pairs
with open('/home/ghaniyoun/ghan/chipyard/toolchains/riscv-tools/riscv-tests/isa/rv64ui-v-AddressFooler.dump', 'r') as file:
    # read a list of lines into data
    lines = file.readlines()
    for line in lines:
        if "Permission" in line:
            space_separated = line.split(" ")
            label = space_separated[1].strip("<>:\n")
            dict_label_PC[label] = space_separated[0][11:]
print("Extracting User Mode cycles from log file!................")
# Extract User Mode instructions and write them in another file
U_Mode_Merged = []
inside = []
with open('/home/ghaniyoun/ghan/chipyard/sims/verilator/log2.txt', 'r') as file:
    inside = file.readlines()
    length_log = len(inside)
    start_index = 0
    mode_check = ["Mode:U"]
    last_line = False
    while not last_line:
        for i in range(start_index, length_log):
            if i == length_log - 1:
                last_line = True
            if len(mode_check) == 1:
                if mode_check[0] in inside[i]:
                    start_index = i
                    mode_check = ["Mode:S", "Mode:M"]
                    break
            else:
                if mode_check[1] in inside[i] or mode_check[0] in inside[i]:
                    start_index = i
                    mode_check = ["Mode:U"]
                    break
            if len(mode_check) == 2:
                U_Mode_Merged.append(inside[i])

with open('/home/ghaniyoun/ghan/chipyard/sims/verilator/UMode.txt', 'w') as file:
    file.writelines(U_Mode_Merged)
print("Finished creating UMode.txt!")
# Create dictionary of PC, user secret pairs
if dict_label_PC:
    for key, value in dict_label_secrets_pair.items():
        PC = dict_label_PC[key]
        secret_vals = [secret for secret in value if secret not in list_kernel_secrets]
        dict_PC_secrets[PC] = secret_vals


# This dictionary is responsible to hold key, value pairs consisting of 2 permission labels as keys, all lines containing
# secrets as values
dict_post_processing = {}


def search_user_secrets():
    lines = []
    last_label = False
    for key, value in dict_PC_secrets.items():
        list_PC_secrets = list(dict_PC_secrets)
        if list_PC_secrets.index(key) == (len(list_PC_secrets) - 1):
            last_label = True
        if last_label == False:
            nextkey = list_PC_secrets[list_PC_secrets.index(key) + 1]
            #print(key)
            #print(nextkey)
            PC_from = "Slot:0 (PC:0x" + key + " Valid:V "
            PC_to = "Slot:0 (PC:0x" + nextkey + " Valid:V "
            #print(PC_from)
            #print(PC_to)
            index_from = 0
            index_to = 0
            with open('/home/ghaniyoun/ghan/chipyard/sims/verilator/UMode.txt', 'r') as file:
                lines = file.readlines()
                for line in reversed(lines):
                    if PC_to in line:
                        index_to = lines.index(line)
                        break
                for line in lines:
                    if PC_from in line:
                        index_from = lines.index(line)
                        break
                for i in range(index_from, index_to):
                    for entry in value:
                        str_entry = str(hex(entry))[2:]
                        if str_entry in lines[i]:
                            if (key + ":" + nextkey) in dict_post_processing.keys():
                                value_temp_list = dict_post_processing[key + ":" + nextkey]
                                value_temp_list.append(lines[i])
                                dict_post_processing[key + ":" + nextkey] = value_temp_list
                                list_secrets_linenumber.append(str(entry) + ": " + str(i))
                            else:
                                dict_post_processing[key + ":" + nextkey] = [lines[i]]
                                list_secrets_linenumber.append(str(entry) + ": " + str(i))
        else:
            PC_from = "Slot:0 (PC:0x" + key + " Valid:V "
            index_from = 0
            with open('/home/ghaniyoun/ghan/chipyard/sims/verilator/UMode.txt', 'r') as file:
                lines = file.readlines()
                for line in lines:
                    if PC_from in line:
                        index_from = lines.index(line)
                        break
                for i in range(index_from, len(lines) - 1):
                    for entry in value:
                        str_entry = str(hex(entry))[2:]
                        if str_entry in lines[i]:
                            if (key + ":" + "End") in dict_post_processing.keys():
                                value_temp_list = dict_post_processing[key + ":" + "End"]
                                value_temp_list.append(lines[i])
                                dict_post_processing[key + ":" + "End"] = value_temp_list
                                list_secrets_linenumber.append(str(entry) + ": " + str(i))
                            else:
                                dict_post_processing[key + ":" + "End"] = [lines[i]]
                                list_secrets_linenumber.append(str(entry) + ": " + str(i))

list_kernel_post_processing_without8 = []
list_kernel_post_processing_just8 = []

def search_kernel_secrets():
    with open('/home/ghaniyoun/ghan/chipyard/sims/verilator/UMode.txt','r') as file:
        lines = file.readlines()
        for i in range(0, len(lines) - 1):
            for entry in list_kernel_secrets:
                str_entry = str(hex(entry))[2:]
                if str_entry in lines[i]:
                    if str_entry != "88888888":
                        list_kernel_post_processing_without8.append(lines[i])
                        list_secrets_linenumber.append(str(entry) + ": " + str(i))
                    else:
                        list_kernel_post_processing_just8.append(lines[i])
                        list_secrets_linenumber.append(str(entry) + ": " + str(i))


if dict_label_PC:
    print("Looking for Kernel Secrets ------------> Started!")
    search_kernel_secrets()
    print("Looking for Kernel Secrets ------------> Successful!")
    print()
    print("Looking for User Secrets ------------> Started!")
    search_user_secrets()
    print("Looking for User Secrets ------------> Successful!")
else:
    print("Looking for Kernel Secrets ------------> Started!")
    search_kernel_secrets()
    print("Looking for Kernel Secrets ------------> Successful!")
with open('/home/ghaniyoun/ghan/chipyard/sims/verilator/UserSecrets.txt', 'w') as file:
    file.writelines(list(dict_post_processing))
with open('/home/ghaniyoun/ghan/chipyard/sims/verilator/KernelSecrets.txt', 'w') as file:
    file.writelines(list_kernel_post_processing_without8)
with open('/home/ghaniyoun/ghan/chipyard/sims/verilator/KernelSecrets.txt', 'a') as file:
    file.writelines(list_kernel_post_processing_just8)
print("Done!")


