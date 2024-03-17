from typing import List

import re, string
from volatility3.framework import renderers, interfaces, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.plugins.windows import pslist
from volatility3.plugins.windows import vadinfo
from volatility3.framework.renderers import format_hints

class Notepad(plugins.PluginInterface):
    """Narrow down probable notepad content from the biggest VAD related to notepad process(es)"""
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.BooleanRequirement(
                name="dump",
                description="Extract probable notepad content to file",
                default=False,
                optional=True,
            ),
            requirements.PluginRequirement(name="vadinfo", description="VadInfo", plugin=vadinfo.VadInfo, version=(2,0,0))
        ]
    def run(self):
        kernel = self.context.modules[self.config["kernel"]]
        tasks = pslist.PsList.list_processes(self.context,
                                                kernel.layer_name,
                                                kernel.symbol_table_name)

        return renderers.TreeGrid([("PID", int), ("Image", str),
                                   ("Probable Strings", str)], self._generator(tasks))
    def _generator(self, data):
        for task in data:
            taskname = task.ImageFileName.cast("string",max_length = task.ImageFileName.vol.count, errors = 'replace')
            task_pid = int(task.UniqueProcessId)
            if taskname.lower() == "notepad.exe":
                try:
                    data_collection = b""
                    vads = vadinfo.VadInfo.list_vads(task)
                    charges = [vad.get_commit_charge() for vad in vadinfo.VadInfo.list_vads(task)]
                    charges = charges[1:]
                    max_charges = max(charges)
                    for vad in vads:
                        vad_start = vad.get_start()
                        vad_end = vad.get_end()
                        proc_id = task.UniqueProcessId
                        proc_layer_name = task.add_process_layer()
                        proc_layer = self.context.layers[proc_layer_name]
                        #print(vad.get_commit_charge())
                        if vad.get_commit_charge() == max_charges:
                            #print(hex(vad_start), hex(vad_end), vad.get_commit_charge(), hex(vad.vol.offset))
                            #print(proc_id)
                            chunk_size = 1024*1024*10
                            offset = vad_start
                            vad_size = vad.get_size()
                            while offset < vad_start + vad_size:
                                to_read = min(chunk_size, vad_start + vad_size - offset)
                                data = proc_layer.read(offset, to_read, pad=True)
                                offset += to_read
                                data_collection += data
                            break            
                    chargen = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{}"
                    s = data_collection
                    n = 2
                    #print(data_collection.rstrip(b"\x00").decode("utf-16le", errors="ignore"))
                    #data_collection_le = b"".join([int.from_bytes(s[i:i+n], "big").to_bytes(2, "little") for i in range(0, len(s), n)])
                    #chargen_index = data_collection_le.find(chargen)
                    data_collection_le = data_collection.rstrip(b"\x00").decode("utf-16le", errors="ignore")
                    final_data_collection = ''.join([i if i in chargen else '\n' for i in data_collection_le]).strip("\n")
                    final_data_collection = re.sub(r"\n+", " ", final_data_collection)
                    if self.config["dump"]:
                        filename = f"pid.{proc_id}.notepad.dmp"
                        with open(filename, "wb") as f:
                            f.write(final_data_collection.encode())
                    yield (0, [task_pid, taskname , final_data_collection])
                except exceptions.InvalidAddressException:
                    continue
