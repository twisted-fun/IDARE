import idc
import idaapi
import idautils
from PyQt5 import QtGui, QtCore
from PyQt5.QtWidgets import (
    QTreeView,
    QVBoxLayout,
    QLineEdit,
    QMenu,
    QInputDialog,
    QAction,
    QTabWidget,
)


def is_vuln_candidate(function_name, ea):
    if function_name == "system":
        prev_ea = idautils.DecodePreviousInstruction(ea).ea
        disasm = idc.GetDisasm(prev_ea)
        if '; "' not in disasm:
            print(disasm)
            return True

    return False


def get_addr_width():
    return "16" if idaapi.cvar.inf.is_64bit() else "8"


def force_name(ea, new_name):
    if not ea or ea == idaapi.BADADDR:
        return
    if idaapi.IDA_SDK_VERSION >= 700:
        return idaapi.force_name(ea, new_name, idaapi.SN_NOCHECK)
    return idaapi.do_name_anyway(ea, new_name, 0)


class IdaReIDPHooks(idaapi.IDP_Hooks):
    """
    Hooks to keep view updated if some function is updated
    """

    def __init__(self, view, *args):
        super(IdaReIDPHooks, self).__init__(*args)
        self._view = view

    def __on_rename(self, ea, new_name):
        if not self._view:
            return
        items = self._view._model.findItems(
            "0x{:X}".format(ea), QtCore.Qt.MatchRecursive
        )
        if len(items) != 1:
            return

        item = items[0]
        index = self._view._model.indexFromItem(item)
        if not index.isValid():
            return

        name_index = index.sibling(index.row(), 1)
        if not name_index.isValid():
            return

        self._view._model.setData(name_index, new_name)

    def ev_rename(self, ea, new_name):
        """callback for IDA >= 700"""
        self.__on_rename(ea, new_name)
        return super(IdaReIDPHooks, self).ev_rename(ea, new_name)

    def rename(self, ea, new_name):
        """callback for IDA < 700"""
        self.__on_rename(ea, new_name)
        return super(IdaReIDPHooks, self).rename(ea, new_name)


class VulnCandidateFinderView(idaapi.PluginForm):
    ADDR_ROLE = QtCore.Qt.UserRole + 1

    OPT_FORM_PERSIST = (
        idaapi.PluginForm.FORM_PERSIST
        if hasattr(idaapi.PluginForm, "FORM_PERSIST")
        else idaapi.PluginForm.WOPN_PERSIST
    )
    OPT_FORM_NO_CONTEXT = (
        idaapi.PluginForm.FORM_NO_CONTEXT
        if hasattr(idaapi.PluginForm, "FORM_NO_CONTEXT")
        else idaapi.PluginForm.WCLS_NO_CONTEXT
    )

    def __init__(self, data):
        super(VulnCandidateFinderView, self).__init__()
        self._data = data
        self.tv = None
        self._model = None
        self._idp_hooks = None

    def Show(self):
        return idaapi.PluginForm.Show(
            self, "Vuln Candidate Finder", options=self.OPT_FORM_PERSIST
        )

    def _get_parent_widget(self, form):
        return self.FormToPyQtWidget(form)

    def OnCreate(self, form):
        self.parent = self._get_parent_widget(form)

        self._idp_hooks = IdaReIDPHooks(self)
        if not self._idp_hooks.hook():
            print("IDP_Hooks.hook() failed")

        self.tv = QTreeView()
        self.tv.setExpandsOnDoubleClick(False)

        root_layout = QVBoxLayout(self.parent)
        # self.le_filter = QLineEdit(self.parent)

        # root_layout.addWidget(self.le_filter)
        root_layout.addWidget(self.tv)

        self.parent.setLayout(root_layout)

        self._model = QtGui.QStandardItemModel()
        self._init_model()
        self.tv.setModel(self._model)

        self.tv.setColumnWidth(0, 200)
        self.tv.setColumnWidth(1, 300)
        self.tv.header().setStretchLastSection(True)

        self.tv.expandAll()

        self.tv.doubleClicked.connect(self.on_navigate_to_method_requested)
        # self.le_filter.textChanged.connect(self.on_filter_text_changed)
        self.tv.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.tv.customContextMenuRequested.connect(
            self._tree_customContextMenuRequesssted
        )

        rename_action = QAction("Rename...", self.tv)
        rename_action.setShortcut("n")
        rename_action.triggered.connect(self._tv_rename_action_triggered)
        self.tv.addAction(rename_action)

        edit_comment_action = QAction("Edit comment...", self.tv)
        edit_comment_action.setShortcut(";")
        edit_comment_action.triggered.connect(self._tv_edit_comment_action_triggered)
        self.tv.addAction(edit_comment_action)

    def _tree_customContextMenuRequesssted(self, pos):
        idx = self.tv.indexAt(pos)
        if not idx.isValid():
            return

        addr = idx.data(role=self.ADDR_ROLE)
        if not addr:
            return
        caller_func = idaapi.get_func(addr)
        if not caller_func:
            return
        addr = caller_func.start_ea

        name_idx = idx.sibling(idx.row(), 1)
        old_name = name_idx.data()

        comment_idx = idx.sibling(idx.row(), 2)

        menu = QMenu()
        rename_action = menu.addAction("Rename `%s`..." % old_name)
        rename_action.setShortcut("n")
        edit_comment_action = menu.addAction("Edit comment")
        edit_comment_action.setShortcut(";")
        action = menu.exec_(self.tv.mapToGlobal(pos))
        if action == rename_action:
            return self._rename_ea_requested(addr, name_idx)
        elif action == edit_comment_action:
            return self._edit_comment_requested(addr, comment_idx)

    def _tv_edit_comment_action_triggered(self):
        selected = self.tv.selectionModel().selectedIndexes()
        if not selected:
            return

        idx = selected[0]
        if not idx.isValid():
            return

        addr = idx.data(role=self.ADDR_ROLE)
        if not addr:
            return

        comment_idx = idx.sibling(idx.row(), 2)
        if not comment_idx.isValid():
            return

        return self._edit_comment_requested(addr, comment_idx)

    def _edit_comment_requested(self, addr, comment_idx):
        old_comment = comment_idx.data()

        if idaapi.IDA_SDK_VERSION >= 700:
            new_comment = idaapi.ask_str(str(old_comment), 0, "New comment:")
        else:
            new_comment = idaapi.askstr(0, str(old_comment), "New comment:")

        if new_comment is None:
            return

        if not idaapi.set_cmt(addr, new_comment, 1):
            return
        renamed_comment = idaapi.get_cmt(addr, 1)
        comment_idx.model().setData(comment_idx, renamed_comment)

    def _tv_rename_action_triggered(self):
        selected = self.tv.selectionModel().selectedIndexes()
        if not selected:
            return

        idx = selected[0]
        if not idx.isValid():
            return

        addr = idx.data(role=self.ADDR_ROLE)
        if not addr:
            return
        caller_func = idaapi.get_func(addr)
        if not caller_func:
            return
        addr = caller_func.start_ea

        name_idx = idx.sibling(idx.row(), 1)
        if not name_idx.isValid():
            return

        return self._rename_ea_requested(addr, name_idx)

    def _rename_ea_requested(self, addr, name_idx):
        old_name = name_idx.data()

        if idaapi.IDA_SDK_VERSION >= 700:
            new_name = idaapi.ask_str(str(old_name), 0, "New name:")
        else:
            new_name = idaapi.askstr(0, str(old_name), "New name:")

        if new_name is None:
            return

        force_name(addr, new_name)
        renamed_name = idaapi.get_ea_name(addr)
        name_idx.model().setData(name_idx, renamed_name)

    def OnClose(self, form):
        if self._idp_hooks:
            self._idp_hooks.unhook()

    def _tv_init_header(self, model):
        item_header = QtGui.QStandardItem("Address")
        model.setHorizontalHeaderItem(0, item_header)

        item_header = QtGui.QStandardItem("Caller Function")
        model.setHorizontalHeaderItem(1, item_header)

        item_header = QtGui.QStandardItem("Comment")
        model.setHorizontalHeaderItem(2, item_header)

    # noinspection PyMethodMayBeStatic
    def _tv_make_tag_item(self, name):
        rv = QtGui.QStandardItem(name)

        rv.setEditable(False)
        return [rv, QtGui.QStandardItem(), QtGui.QStandardItem()]

    def _tv_make_ref_item(self, tag, ref):
        ea_item = QtGui.QStandardItem("0x{:X}".format(ref["ea"]))
        ea_item.setEditable(False)
        ea_item.setData(ref["ea"], self.ADDR_ROLE)

        name_item = QtGui.QStandardItem(ref["caller"])
        name_item.setEditable(False)
        name_item.setData(ref["ea"], self.ADDR_ROLE)

        api_name = QtGui.QStandardItem(ref["comment"])
        api_name.setEditable(False)
        api_name.setData(ref["ea"], self.ADDR_ROLE)

        return [ea_item, name_item, api_name]

    def _init_model(self):
        self._model.clear()

        root_node = self._model.invisibleRootItem()
        self._tv_init_header(self._model)

        for tag, refs in self._data.items():
            item_tag_list = self._tv_make_tag_item(tag)
            item_tag = item_tag_list[0]

            root_node.appendRow(item_tag_list)

            for ref in refs:
                ref_item_list = self._tv_make_ref_item(tag, ref)

                item_tag.appendRow(ref_item_list)

    def on_navigate_to_method_requested(self, index):
        addr = index.data(role=self.ADDR_ROLE)
        if addr is not None:
            idaapi.jumpto(addr)


DANGEROUS_FUNCTIONS = ["system", "strcpy", "gets", "printf"]


class vuln_candidate_finder_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = ""
    help = ""
    wanted_name = "IDARE: Vuln Candidate Finder"
    wanted_hotkey = ""

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        view_data = {}
        for function_addr in idautils.Functions():
            function_name = idaapi.get_name(function_addr)
            if function_name in DANGEROUS_FUNCTIONS:
                print("{} @ 0x{:x}".format(function_name, function_addr))
                print("CodeRefsTo")
                xrefs = idautils.CodeRefsTo(function_addr, False)
                for xref in xrefs:
                    if is_vuln_candidate(function_name, xref):
                        print("@ 0x{:x}".format(xref))

                        # Get caller function
                        caller_func = idaapi.get_func(xref)
                        if caller_func is not None:
                            caller_func_name = idaapi.get_name(caller_func.start_ea)
                        else:
                            caller_func_name = "?????"

                        # Get repeatable comments on xref
                        comment = idaapi.get_cmt(xref, 1)

                        if function_name not in view_data:
                            view_data[function_name] = []
                        view_data[function_name].append(
                            {"ea": xref, "caller": caller_func_name, "comment": comment}
                        )

        plg = VulnCandidateFinderView(view_data)
        plg.Show()

    def term(self):
        pass


def PLUGIN_ENTRY():
    return vuln_candidate_finder_t()
