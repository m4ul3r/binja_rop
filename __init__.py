from binaryninja import *
from .binja_rop import *

from binaryninja import user_plugin_path, core_version
from binaryninja.plugin import BackgroundTaskThread
from binaryninja.log import (log_error, log_debug, log_alert, log_warn)
from binaryninja.settings import Settings
from binaryninja.interaction import get_directory_name_input
import binaryninjaui
from binaryninjaui import (getMonospaceFont, UIAction, UIActionHandler, Menu, UIContext)
from PySide6.QtWidgets import (QLineEdit, QPushButton, QApplication, QWidget,
     QVBoxLayout, QHBoxLayout, QDialog, QFileSystemModel, QTreeView, QLabel, QSplitter,
     QInputDialog, QMessageBox, QHeaderView, QKeySequenceEdit, QCheckBox, QMenu)
from PySide6.QtCore import (QDir, Qt, QFileInfo, QItemSelectionModel, QSettings, QUrl)
from PySide6.QtGui import (QFontMetrics, QDesktopServices, QKeySequence, QIcon, QColor, QAction)

# https://github.com/Vector35/snippets/blob/a10096727be5bb8d17c88fab33ed43ff12a736e4/__init__.py#L190

class Settings(QDialog):
    def __init__(self, context, parent=None):
        super(Settings, self).__init__(parent)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self.title = QLabel(self.tr("binja_rop"))
        self.saveButton = QPushButton(self.tr("&Save"))
        self.closeButton = QPushButton(self.tr("Close"))
        self.setWindowTitle(self.title.text())
        self.columns = 2
        self.context = context

        font = getMonospaceFont(self)
        font = QFontMetrics(font)

        # create layout and add widgets
        optionsAndButtons = QVBoxLayout()

        buttons = QHBoxLayout()
        buttons.addWidget(self.closeButton)

        optionsAndButtons.addLayout(buttons)

        vlayoutWidget = QWidget()
        vlayout = QVBoxLayout()
        vlayout.addLayout(optionsAndButtons)
        vlayoutWidget.setLayout(vlayout)

        self.showNormal()   # fixes bug that maximized windows are stuck
        self.settings = QSettings("", "binja_rop")

def openSettings(context):
    settings = Settings(context, parent=context.widget)
    settings.open()

def find_rop_gadgets(bv):
    rop_search = ROPSearch(bv)
    rop_search.start()

if __name__ == "__main__":
    print("from main")
else:
    PluginCommand.register(
        "binja_rop\\Find ROP Gadgets",
        "finds rop gadgets in current binary",
        find_rop_gadgets
    )

    UIAction.registerAction("binja_rop\\Settings")
    UIActionHandler.globalActions().bindAction("binja_rop\\Settings", UIAction(openSettings))
    Menu.mainMenu("Plugins").addAction("binja_rop\\Find ROP Gadgets", "binja_rop")
    Menu.mainMenu("Plugins").addAction("binja_rop\\Settings", "binja_rop")

