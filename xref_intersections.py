import idaapi
import idc
import sark
import sark.ui as ui
import networkx as nx
from sark import exceptions


class xref_intersections(idaapi.plugin_t):
    flags = 0
    comment = "Gives a list or graph of intersecting xrefs in a list of functions"
    help = ""
    wanted_name = "Xref Intersections"
    wanted_hotkey = ""
    start_points = set()

    def try_get_func_start(self, ea):
        try:
            return sark.Function(ea).startEA

        except exceptions.SarkNoFunction:
            return ea

    def get_xrefs_from(self, function_ea):
        try:
            return sark.Function(function_ea).xrefs_from

        except exceptions.SarkNoFunction:
            return sark.Line(function_ea).xrefs_from

    def scan_xrefs_from_to(self, distance, roots):
        new = set()

        if distance > 0:
            for ea in roots:
                for xref in self.get_xrefs_from(ea):
                    new.add((self.try_get_func_start(xref.frm), self.try_get_func_start(xref.to)))

            new |= self.scan_xrefs_from_to(distance - 1, [x[1] for x in new])

        return new

    def scan_xrefs_to(self, distance, roots):
        new = set()

        if distance > 0:
            for ea in roots:
                for xref in self.get_xrefs_from(ea):
                    new.add(self.try_get_func_start(xref.to))

            new |= self.scan_xrefs_to(distance - 1, new)

        return new

    def show_intersections(self, ea, distance):
        roots = map(self.try_get_func_start, ea)
        tree = [self.scan_xrefs_from_to(distance, [root]) for root in roots]
        call_graph = nx.DiGraph()

        for item in [y for x in tree for y in x]:
            call_graph.add_edge(item[0], item[1])

        for func in set.intersection(*[set([y[1] for y in x]) for x in tree]):
            call_graph.node[func][ui.NXGraph.BG_COLOR] = 0xffe432

        for func in roots:
            call_graph.node[func][ui.NXGraph.BG_COLOR] = 0x80

        view = ui.NXGraph(call_graph, "Intersections", ui.AddressNodeHandler())
        view.Show()

    def print_intersections(self, ea, distance):
        print '----------------------------------------------------------------'

        for func in set.intersection(*[self.scan_xrefs_to(distance, [root]) for root in map(self.try_get_func_start, ea)]):
            try:
                print sark.Function(func).demangled

            except exceptions.SarkNoFunction:
                print idc.Name(func)

    def _get_clear_search_handler(plugin):
        class ClearSearchHandler(ui.ActionHandler):
            TEXT = "Clear intersection list"

            def _activate(self, ctx):
                plugin.start_points.clear()

        return ClearSearchHandler

    def _get_add_to_search_handler(plugin):
        class AddToSearchHandler(ui.ActionHandler):
            TEXT = "Add to intersection list"

            def _activate(self, ctx):
                plugin.start_points.add(idc.here())

        return AddToSearchHandler

    def _get_hooks(plugin):
        class Hooks(idaapi.UI_Hooks):

            def finish_populating_tform_popup(self, form, popup):
                if idaapi.get_tform_type(form) == idaapi.BWN_DISASM:
                    idaapi.attach_action_to_popup(form, popup, plugin.add_to_search_handler.get_name(), '')
                    idaapi.attach_action_to_popup(form, popup, plugin.clear_search_handler.get_name(), '')

        return Hooks

    def _show(self):
        if (len(self.start_points) > 0):
            self.show_intersections(self.start_points, idaapi.asklong(4, 'Scan depth'))
        else:
            idc.Warning("Too few points to perform an intersection.")

    def _print(self):
        if (len(self.start_points) > 0):
            self.print_intersections(self.start_points, idaapi.asklong(4, 'Scan depth'))
        else:
            idc.Warning("Too few points to perform an intersection.")

    def init(self):
        self.clear_search_handler = self._get_clear_search_handler()
        self.add_to_search_handler = self._get_add_to_search_handler()
        self.add_to_search_handler.register()
        self.clear_search_handler.register()

        self.hooks = self._get_hooks()()
        self.hooks.hook()

        self.hotkeys = []
        self.hotkeys.append(idaapi.add_hotkey("Ctrl+Alt+6", self._show))
        self.hotkeys.append(idaapi.add_hotkey("Ctrl+Alt+5", self._print))
        return idaapi.PLUGIN_KEEP

    def term(self):
        self.hooks.unhook()
        self.add_to_search_handler.unregister()
        self.clear_search_handler.unregister()

        for hotkey in self.hotkeys:
            idaapi.del_hotkey(hotkey)

    def run(self, arg):
        result = idc.AskYN(1, "Yes for graph No for console output.")
        if result == 1:
            self._show()
        if result == 0:
            self._print()


def PLUGIN_ENTRY():
    return xref_intersections()
