from typing import List
import logging, io, re, datetime
from volatility3.framework import renderers, interfaces, exceptions, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import pe
from volatility3.framework.symbols.windows.versions import is_windows_7, is_vista_or_later, is_win10
from volatility3.plugins.windows import filescan, dumpfiles
from volatility3.plugins.windows import info

vollog = logging.getLogger(__name__)

# try:
#     from stream_sqlite import stream_sqlite
#     from striprtf.striprtf import rtf_to_text
#     import olefile
# except ImportError:
#     vollog.info(
#         "One of these requirements are not fulfilled in pip:\n- stream-sqlite\n- striprtf\n-olefile\nInstall it first before using this plugin!"
#     )
#     raise

class KUserParse(plugins.PluginInterface):
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            # requirements.TranslationLayerRequirement(name = 'primary',
            #                 description = 'Memory layer for the kernel',
            #                 architectures = ["Intel32", "Intel64"]),
            
            # requirements.SymbolTableRequirement(name = "nt_symbols",
            #                 description = "Windows kernel symbols"),
            requirements.ModuleRequirement(name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="info", plugin=info.Info, version=(1, 0, 0)
            ),
            requirements.PluginRequirement(
                name="dumpfiles", plugin=dumpfiles.DumpFiles, version=(1, 0, 0)
                )
            
            # requirements.BooleanRequirement(name = 'onlywow64',
            #                 description = "Only show WoW64 processes",
            #                 default = False,
            #                 optional = True)
        ]
    ## TODO:
    ## parse .snt file or .db file of sticky notes / done 2 March 2023
    ## parse plum.db file of sticky
    @classmethod
    def ksystemtime_to_100ns(self, ksystemtime):
        assert ksystemtime.High1Time == ksystemtime.High2Time
        first = bin(ksystemtime.High1Time)
        last = bin(ksystemtime.LowPart)
        first32 = "0"*(32-len(first[2:])) + first[2:]
        last32 = "0"*(32-len(last[2:])) + last[2:]
        binary64 = "0b"+ first32 + last32
        return int(binary64, 2)

    def run(self):
        kernel = self.context.modules[self.config["kernel"]]
        kuser = info.Info.get_kuser_structure(self.context, kernel.layer_name, kernel.symbol_table_name)
        return renderers.TreeGrid([("Variable", str), ("Value", float), ("Value Format", str)], self._generator(kuser))

    def _generator(self, kuser):
        interrupt_time = self.ksystemtime_to_100ns(kuser.InterruptTime)/10000000
        system_time = self.ksystemtime_to_100ns(kuser.SystemTime)/10000000
        tick_count = self.ksystemtime_to_100ns(kuser.TickCount)*15.625*100000000/10000/10000000
        yield 0, ("InterruptTime", interrupt_time, "seconds")
        yield 0, ("SystemTime", system_time, "seconds")
        yield 0, ("TickCount", tick_count, "+- seconds")