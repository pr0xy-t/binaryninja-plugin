#
#
import binaryninja
from binaryninja import (typelibrary, platform)
from binaryninja.enums import NamedTypeReferenceClass
from binaryninja.types import Type, NamedTypeReferenceType, StructureBuilder, EnumerationBuilder
from binaryninja.interaction import show_plain_text_report, show_message_box
from binaryninja.plugin import BackgroundTaskThread, PluginCommand
from binaryninja.log import log_info
import os
import tempfile
import requests

BINJA_DIR = binaryninja.bundled_plugin_path().replace("/MacOS/plugins","/Resources/").replace("/plugins", "/")

enums = {
        "flags_t": {
            "O_RDONLY":     int("00", 8),
            "O_WRONLY":     int("01", 8),
            "O_RDWR":       int("02", 8),
            "O_ACCMODE":    int("03", 8),
            "O_CREAT":      int("0100", 8),
            "O_EXCL":       int("0200", 8),
            "O_NOCTTY":     int("0400", 8),
            "O_TRUNC":      int("01000", 8),
            "O_APPEND":     int("02000", 8),
            "O_NONBLOCK":   int("04000", 8),
            "O_SYNC":       int("04010000", 8),
            "O_ASYNC":      int("020000", 8),
            "O_PATH":       int("010000000", 8),
            "O_TMPFILE":    int("020000000", 8) | int("0200000", 8),
            },
        "fd_t": {
            "STDIN":    0,
            "STDOUT":   1,
            "STDERR":   2,
            },
        "whence_t": {
            "SEEK_SET": 0,
            "SEEK_CUR": 1,
            "SEEK_END": 2,
            "SEEK_DATA": 3,
            "SEEK_HOLE": 4,
            },
        "mmap_prot_t": {
            "PROT_NONE": 0,
            "PROT_READ": 1,
            "PROT_WRITE": 2,
            "PROT_READ | PROT_WRITE": 3,
            "PROT_EXEC": 4,
            "PROT_READ | PROT_EXEC": 5,
            "PROT_WRITE | PROT_EXEC" : 6,
            "PROT_READ | PROT_WRITE | PROT_EXEC": 7,
            },
        "mmap_flags_t": {
            "MAP_SHARED": 0x1,
            "MAP_PRIVATE": 0x2,
            "MAP_FIXED": 0x10,
            "MAP_ANONYMOUS": 0x20,
            },
        "sig_t": {
            "SIGHUP"     :  1,
            "SIGINT"     :  2,
            "SIGQUIT"    :  3,
            "SIGILL"     :  4,
            "SIGTRAP"    :  5,
            "SIGABRT"    :  6,
            "SIGBUS"     :  7,
            "SIGFPE"     :  8,
            "SIGKILL"    :  9,
            "SIGUSR1"    : 10,
            "SIGSEGV"    : 11,
            "SIGUSR2"    : 12,
            "SIGPIPE"    : 13,
            "SIGALRM"    : 14,
            "SIGTERM"    : 15,
            "SIGSTKFLT"  : 16,
            "SIGCHLD"    : 17,
            "SIGCONT"    : 18,
            "SIGSTOP"    : 19,
            "SIGTSTP"    : 20,
            "SIGTTIN"    : 21,
            "SIGTTOU"    : 22,
            "SIGURG"     : 23,
            "SIGXCPU"    : 24,
            "SIGXFSZ"    : 25,
            "SIGVTALRM"  : 26,
            "SIGPROF"    : 27,
            "SIGWINCH"   : 28,
            "SIGIO"      : 29,
            "SIGPWR"     : 30,
            "SIGSYS"     : 31,
            "SIGRTMIN"   : 34,
            "SIGRTMIN+1" : 35,
            "SIGRTMIN+2" : 36,
            "SIGRTMIN+3" : 37,
            "SIGRTMIN+4" : 38,
            "SIGRTMIN+5" : 39,
            "SIGRTMIN+6" : 40,
            "SIGRTMIN+7" : 41,
            "SIGRTMIN+8" : 42,
            "SIGRTMIN+9" : 43,
            "SIGRTMIN+10": 44,
            "SIGRTMIN+11": 45,
            "SIGRTMIN+12": 46,
            "SIGRTMIN+13": 47,
            "SIGRTMIN+14": 48,
            "SIGRTMIN+15": 49,
            "SIGRTMAX-14": 50,
            "SIGRTMAX-13": 51,
            "SIGRTMAX-12": 52,
            "SIGRTMAX-11": 53,
            "SIGRTMAX-10": 54,
            "SIGRTMAX-9" : 55,
            "SIGRTMAX-8" : 56,
            "SIGRTMAX-7" : 57,
            "SIGRTMAX-6" : 58,
            "SIGRTMAX-5" : 59,
            "SIGRTMAX-4" : 60,
            "SIGRTMAX-3" : 61,
            "SIGRTMAX-2" : 62,
            "SIGRTMAX-1" : 63,
            "SIGRTMAX"   : 64,
            },
        "shutdown_how_t": {
            "SHUT_RD"   : 0,
            "SHUT_WR"   : 1,
            "SHUT_RDWR" : 2,
            },
        "wait_options_t": {
                "WNOHANG"   : 1,
                "WUNTRACED" : 2,
                "WSTOPPED"  : 3,
                "WEXITED"   : 4,
                "WEXITED | WNOHANG"   : 5,
                "WEXITED | WUNTRACED"   : 6,
                "WEXITED | WUNTRACED | WNOHANG"   : 7,
                "WCONTINUED": 8,
                "WCONTINUED | WNOHANG"   : 9,
                "WCONTINUED | WUNTRACED" : 10,
                "WCONTINUED | WSTOPPED"  : 11,
                "WCONTINUED | WEXITED"   : 12,
                "WCONTINUED | WEXITED | WNOHANG"   : 13,
                "WCONTINUED | WEXITED | WUNTRACED"   : 14,
                "WCONTINUED | WEXITED | WUNTRACED | WNOHANG"   : 15,
                },
        }
def create_typelib(fname, name, arch, guid, dependency_name, alternate_names, platform_names, named_objects, named_types):
    typelib = typelibrary.TypeLibrary.new(arch, name)
    typelib.guid = guid

    for an in alternate_names:
        typelib.add_alternate_name(an)
    for pn in platform_names:
        typelib.add_platform(platform.Platform[pn])

    for (name, obj) in named_objects.items():
        typelib.add_named_object(name, obj)

    for (name, type_) in named_types.items():
        typelib.add_named_type(name, type_)
    
    typelib.write_to_file(fname)

def build():
    log_info(f"[Build_Type_Lib(libc.so.6.bntl)] This takes about 2 minutes...")
    tmp_dir =  tempfile.TemporaryDirectory()
    tl_path = os.path.join(tmp_dir.name, "libc.so.6.bntl")
    with open(tl_path, "wb") as f:
        data = requests.get("https://github.com/pr0xy-t/binaryninja-plugin/releases/download/original_libc.so.6.bntl/libc.so.6.bntl").content
        f.write(data)
    log_info(f"[Build_Type_Lib(libc.so.6.bntl)] download {tl_path}")

    tl = typelibrary.TypeLibrary.load_from_file(tl_path)
    arch = tl.arch
    ignore_list = ["open", "lseek", "mmap", "kill", "shutdown", "waitpid"]
    named_objects = {key:tl.named_objects[key] for key in tl.named_objects if not key in ignore_list }
    named_types = tl.named_types
    
    for _type in enums:
        enum_type = EnumerationBuilder.create([], width=4, arch=arch, sign=True)
        for macro in enums[_type]:
            enum_type.append(macro, enums[_type][macro])
        named_types[_type] = enum_type

    # open
    # before: int open(char *pathname, int flags)
    # after:  int open(char *pathname, enum flags_t flags)
    ret = Type.int(4)
    params = [("pathname", Type.pointer(arch, Type.char())), ("flags", named_types["flags_t"])]
    ftype = Type.function(ret, params)
    named_objects["open"] = ftype
    
    # lseek
    # before: off_t lseek(int fd, off_t offset, int whence)
    # after:  off_t lseek(int fd, off_t offset, enum whence_t whence)
    ret = named_types["off64_t"]
    params = [("fd", named_types["fd_t"]), ("offset", named_types["off64_t"]), ("whence", named_types["whence_t"])]
    ftype = Type.function(ret, params)
    named_objects["lseek"] = ftype
    
    # mmap
    # before: void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
    # after : void *mmap(void *addr, size_t length, enum mmap_prot_t prot, enum mmap_flags_t flags, enum fd_t fd, off_t offset);
    ret = Type.pointer(arch, Type.void())
    params = [("addr", Type.pointer(arch, Type.void())), ("length", Type.int(8)), ("prot", named_types["mmap_prot_t"]), ("flags", named_types["mmap_flags_t"]), ("fd", named_types["fd_t"]), ("offset", named_types["off64_t"])]
    ftype = Type.function(ret, params)
    named_objects["mmap"] = ftype
    
    # kill
    # before: int kill(pid_t pid, int sig)
    # after : int kill(pid_t pid, sig_t sig)
    ret = Type.int(4)
    params = [("pid", named_types["pid_t"]), ("sig", named_types["sig_t"])]
    ftype = Type.function(ret, params)
    named_objects["kill"] = ftype


    # shutdown
    # before: int shutdown(int sockfd, int how)
    # after:  int shutdown(int sockfd, enum shutdown_how_t how)
    ret = Type.int(4)
    params = [("sockfd", Type.int(4)), ("how", named_types["shutdown_how_t"])]
    ftype = Type.function(ret, params)
    named_objects["shutdown"] = ftype

    # waitpid
    # before: pid_t waitpid(pid_t pid, int *wstatus, int options)
    # after : pid_t waitpid(pid_t pid, int *wstatus, enum wait_options_t options)
    ret = named_types["pid_t"]
    params = [("pid", named_types["pid_t"]), ("wstatus", Type.pointer(arch, Type.int(4))), ("options", named_types["wait_options_t"])]
    ftype = Type.function(ret, params)
    named_objects["waitpid"] = ftype

    create_typelib(BINJA_DIR + "typelib/x86_64/libc.so.6.bntl", tl.name, arch, tl.guid, tl.dependency_name, tl.alternate_names,tl.platform_names, named_objects, named_types)
    log_info("[Build_Type_Lib(libc.so.6.bntl)] finish")


class Builder(BackgroundTaskThread):
    def __init__(self):
        BackgroundTaskThread.__init__(self, "Build Type Lib ...", True)
    def run(self):
        build()

b = Builder()
b.start()
