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

BINJA_DIR = binaryninja.bundled_plugin_path().replace("/plugins", "/")

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
    ignore_list = ["open", "lseek", "mmap"]
    named_objects = {key:tl.named_objects[key] for key in tl.named_objects if not key in ignore_list }
    named_types = tl.named_types
    
    # open
    # int open(const char *pathname, int flags)
    # int open(char *pathname, enum flags_t)
    enum_type_open_flags = EnumerationBuilder.create([], None, arch=arch)
    enum_type_open_flags.append("O_RDONLY",    int("00", 8))
    enum_type_open_flags.append("O_WRONLY",    int("01", 8))
    enum_type_open_flags.append("O_RDWR",      int("02", 8))
    enum_type_open_flags.append("O_ACCMODE",   int("03", 8))
    enum_type_open_flags.append("O_CREAT",     int("0100", 8))
    enum_type_open_flags.append("O_EXCL",      int("0200", 8))
    enum_type_open_flags.append("O_NOCTTY",    int("0400", 8))
    enum_type_open_flags.append("O_TRUNC",     int("01000", 8))
    enum_type_open_flags.append("O_APPEND",    int("02000", 8))
    enum_type_open_flags.append("O_NONBLOCK",  int("04000", 8))
    enum_type_open_flags.append("O_SYNC",      int("04010000", 8))
    enum_type_open_flags.append("O_ASYNC",     int("020000", 8))
    enum_type_open_flags.append("O_PATH",      int("010000000", 8))
    enum_type_open_flags.append("O_TMPFILE",   int("020000000", 8) | int("0200000", 8))
    named_types["flags_t"] = enum_type_open_flags
    
    ret = Type.int(4)
    params = [("pathname", Type.pointer(arch, Type.char())),("flags", enum_type_open_flags)]
    ftype = Type.function(ret, params)
    named_objects["open"] = ftype
    
    # lseek
    # off_t lseek(int fd, off_t offset, int whence)
    # off64_t lseek(int32_t fd, int64_t __arg2, int32_t whence)
    enum_type_fd = EnumerationBuilder.create([], width=4, arch=arch, sign = True)
    enum_type_fd.append("STDIN", 0)
    enum_type_fd.append("STDOUT", 1)
    enum_type_fd.append("STDERR", 2)
    named_types["fd_t"] = enum_type_fd
    
    enum_type_whence = EnumerationBuilder.create([], width=4, arch=arch)
    enum_type_whence.append("SEEK_SET", 0)
    enum_type_whence.append("SEEK_CUR", 1)
    enum_type_whence.append("SEEK_END", 2)
    enum_type_whence.append("SEEK_DATA", 3)
    enum_type_whence.append("SEEK_HOLE", 4)
    named_types["whence_t"] = enum_type_whence
    
    ret = named_types["off64_t"]
    params = [("fd", enum_type_fd),("offset", named_types["off64_t"]),("whence",enum_type_whence)]
    ftype = Type.function(ret, params)
    named_objects["lseek"] = ftype
    
    # mmap
    # void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
    # void *mmap(void* addr, size_t len, int32_t prot, int32_t flags, int32_t fd, off64_t offset)
    enum_type_mmap_prot = EnumerationBuilder.create([], width=4, arch=arch)
    enum_type_mmap_prot.append("PROT_NONE", 0)
    enum_type_mmap_prot.append("PROT_READ", 1)
    enum_type_mmap_prot.append("PROT_WRITE", 2)
    enum_type_mmap_prot.append("PROT_READ | PROT_WRITE", 3)
    enum_type_mmap_prot.append("PROT_EXEC", 4)
    enum_type_mmap_prot.append("PROT_READ | PROT_EXEC", 5)
    enum_type_mmap_prot.append("PROT_WRITE | PROT_EXEC" , 6)
    enum_type_mmap_prot.append("PROT_READ | PROT_WRITE | PROT_EXEC", 7)
    named_types["mmap_prot_t"] = enum_type_mmap_prot
    
    enum_type_mmap_flags = EnumerationBuilder.create([], width=4, arch=arch)
    enum_type_mmap_flags.append("MAP_SHARED", 0x1)
    enum_type_mmap_flags.append("MAP_PRIVATE", 0x2)
    enum_type_mmap_flags.append("MAP_FIXED", 0x10)
    enum_type_mmap_flags.append("MAP_ANONYMOUS", 0x20)
    named_types["mmap_flags_t"] = enum_type_mmap_flags
    
    ret = Type.pointer(arch, Type.void())
    params = [("addr", Type.pointer(arch, Type.void())),("length", Type.int(8)), ("prot", enum_type_mmap_prot), ("flags",enum_type_mmap_flags), ("fd", enum_type_fd), ("offset", named_types["off64_t"])]
    ftype = Type.function(ret, params)
    named_objects["mmap"] = ftype
    
    
    create_typelib(BINJA_DIR + "typelib/x86_64/libc.so.6.bntl", tl.name, arch, tl.guid, tl.dependency_name, tl.alternate_names,tl.platform_names, named_objects, named_types)

    log_info("[Build_Type_Lib(libc.so.6.bntl)] finish")
class Builder(BackgroundTaskThread):
    def __init__(self):
        BackgroundTaskThread.__init__(self, "Build Type Lib ...", True)
    def run(self):
        build()

b = Builder()
b.start()
