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

def download():
    tl_path = BINJA_DIR + "typelib/x86_64/libc.so.6.bntl"
    with open(tl_path, "wb") as f:
        data = requests.get("https://github.com/pr0xy-t/binaryninja-plugin/releases/download/latest/libc.so.6.bntl").content
        f.write(data)
    log_info("[Download type library(libc.so.6.bntl)] finish")

class Downloader(BackgroundTaskThread):
    def __init__(self):
        BackgroundTaskThread.__init__(self, "Download typelib...", True)
    def run(self):
        download()

d = Downloader()
d.start()
