from typing import List
import logging, io, re, datetime, olefile
from volatility3.framework import renderers, interfaces, exceptions, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import pe
from volatility3.framework.symbols.windows.versions import is_windows_7, is_vista_or_later, is_win10
from volatility3.plugins.windows import filescan, dumpfiles

vollog = logging.getLogger(__name__)

try:
    from stream_sqlite import stream_sqlite
    from striprtf.striprtf import rtf_to_text
    import olefile
except ImportError:
    vollog.info(
        "One of these requirements are not fulfilled in pip:\n- stream-sqlite\n- striprtf\n-olefile\nInstall it first before using this plugin!"
    )
    raise

class MyFirstPlugin(plugins.PluginInterface):
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
                name="filescan", plugin=filescan.FileScan, version=(0, 0, 0)
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
    def parse_sticky_file(cls, file_raw, file_name):
        try:
            if file_name[-4:] == ".snt":    
                ole = olefile.OleFileIO(file_raw)
                for block in ole.listdir():
                    stream = ole.openstream(block)
                    rawstream = stream.read()
                    if b"{\\rtf1" in rawstream:
                        text = repr(rtf_to_text(rawstream.decode()))
                        relative_file_name = file_name[file_name.rfind("\\")+1:]
                        last_modified = "Unknown"
                        if ole.getmtime(stream):
                            last_modified = str(ole.getmtime(stream))
                        yield relative_file_name, last_modified, text
            if file_name[-7:] == ".sqlite":
                sqlite_bytes = io.BytesIO(file_raw)
                for table_name, pragma_table_info, rows in stream_sqlite(sqlite_bytes, max_buffer_size=1_048_576):
                    for row in rows:
                        try:
                            text = repr(row.Text)
                            seconds = int(repr(row.UpdatedAt)) / 10000000
                            posix = seconds - (datetime.date(1970, 1, 1) - datetime.date(1, 1, 1)).total_seconds()
                            last_modified = str(datetime.datetime.fromtimestamp(posix))
                            relative_file_name = file_name[file_name.rfind("\\")+1:]
                            yield relative_file_name, last_modified, text
                        except AttributeError:
                            continue
        except ValueError: 
            relative_file_name = file_name[file_name.rfind("\\")+1:]
            yield relative_file_name, "Unknown", "Unavailable"
            # >File carved
            # >Look inside
            # >Nullbytes only
    
    def run(self):
        kernel = self.context.modules[self.config["kernel"]]
        files = filescan.FileScan.scan_files(self.context,
                                                kernel.layer_name,
                                                kernel.symbol_table_name)
        return renderers.TreeGrid([("Filename", str), ("Last Modified (UTC)", str), ("Parsed Text", str)], self._generator(files))

    def _generator(self, data):
        kernel = self.context.modules[self.config["kernel"]]
        pe_table_name = intermed.IntermediateSymbolTable.create(
            self.context, self.config_path, "windows", "pe", class_types=pe.class_types
        )
    
        for file in data:
            try:
                #check if real Windows 7 (is windows 7 and vista and later is more or less Windows 7), .snt file is from Windows 7-ish or if it's from Windows 10's Sticky Notes
                if (is_windows_7(self.context, kernel.symbol_table_name) and is_vista_or_later(self.context, kernel.symbol_table_name)) or (is_win10(self.context, kernel.symbol_table_name)):
                    if file.FileName.String[-4:] == ".snt" or file.FileName.String[file.FileName.String.rfind("\\")+1:] == "plum.sqlite":
                        file_name = file.FileName.String
                        """If found, try to dump the file (inspired from the "DumpFiles" plugin)"""
                        memory_objects = []
                        memory_layer_name = self.context.layers[kernel.layer_name].config['memory_layer']
                        memory_layer = self.context.layers[memory_layer_name]
                        primary_layer = self.context.layers[kernel.layer_name]
                        for member_name in ["DataSectionObject", "ImageSectionObject"]:
                            try:
                                section_obj = getattr(file.SectionObjectPointer, member_name)
                                control_area = section_obj.dereference().cast("_CONTROL_AREA")
                                if control_area.is_valid():
                                    vollog.info(f"Found : {file.FileName.String}")
                                    memory_objects.append((control_area, memory_layer))
                            except exceptions.InvalidAddressException:
                                vollog.log(constants.LOGLEVEL_VVV,
                                        f"{member_name} is unavailable for file {file.vol.offset:#x}")
                        try:
                            scm_pointer = file.SectionObjectPointer.SharedCacheMap
                            shared_cache_map = scm_pointer.dereference().cast("_SHARED_CACHE_MAP")
                            if shared_cache_map.is_valid():
                                memory_objects.append((shared_cache_map, primary_layer))
                        except exceptions.InvalidAddressException:
                            vollog.info(constants.LOGLEVEL_VVV,
                                        f"SharedCacheMap is unavailable for file {file.vol.offset:#x}")
                        vollog.info(f"memory_objects : {memory_objects}")

                        for memory_object, layer in memory_objects:
                            bytes_read = 0
                            file_raw = b''
                            try:
                                for mem_offset, file_offset, datasize in memory_object.get_available_pages():
                                    file_raw += layer.read(mem_offset, datasize, pad=True)
                                    bytes_read += len(file_raw)
                                    vollog.info(f"Read {bytes_read}")
                                if not bytes_read:
                                    vollog.info(f"{file_name} is empty")
                                else:
                                    """Parsing the trace files"""
                                    #print(file_raw, file_name)
                                    for result in self.parse_sticky_file(file_raw, file_name):
                                        yield 0, result
                            except exceptions.InvalidAddressException:
                                vollog.debug(f"Unable to dump file at {file.vol.offset:#x}")
                                pass
            except exceptions.InvalidAddressException:
                continue
        