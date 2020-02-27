# -*- coding: utf-8 -*-

# Copyright (c) 2015-2020 Vector 35 Inc
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

from __future__ import print_function

import sys
import os

from PySide2.QtCore import (Qt, QRect, QItemSelectionModel, QItemSelection, QSize, Signal)
from PySide2.QtGui import (QStandardItemModel, QIcon, QStandardItem, QKeySequence, QFont, QBrush, QTextDocument,
						   QCursor, QFontDatabase, QPalette)
from PySide2.QtWidgets import (QApplication, QTreeView, QVBoxLayout, QWidget, QMenu, QAction, QMainWindow, QFileDialog,
							   QStyledItemDelegate, QStyle, QGroupBox, QHBoxLayout, QPushButton, QAbstractItemView,
							   QInputDialog, QMessageBox, QLabel)

import pickle
import json
import zlib

from . import sig_serialize_json
from . import sig_serialize_fb

class App(QMainWindow):
	def __init__(self):
		super(App, self).__init__()

		self.treeView = None
		self.model = None
		self.pattern_delegate = None
		self.callee_delegate = None
		self.sig_trie = None

		self.searchResults = None
		self.searchIndex = -1
		self.findNextAction = None
		self.findPrevAction = None

		# these two maps are used to make the hyperlinks work
		# mapping from href to FunctionNode
		self.hrefs_to_funcs = {}
		# mapping from FunctionNode to tree view element (QStandardItem)
		self.func_node_items = {}

		self.init_ui()

		# with open('merged_libc.sig', 'rb') as f:
		#     json_trie = zlib.decompress(f.read()).decode('utf-8')
		# sig_trie = trie_ops.deserialize_sig_trie(json.loads(json_trie))
		# self.open_trie(sig_trie, 'merged_libc.sig')

	def init_ui(self):
		self.setWindowTitle('Signature Explorer')
		self.resize(1000, 640)
		app_icon = QIcon()
		app_icon.addFile('icon.ico', QSize(48,48))
		self.setWindowIcon(app_icon)

		self.pattern_delegate = PatternDelegate()
		self.callee_delegate = CalleesDelegate()

		self.treeView = TrieView()
		# self.treeView.setAlternatingRowColors(True)

		self.model = QStandardItemModel(0, 7, self.treeView)
		self.model.setHeaderData(0, Qt.Horizontal, 'Signature')
		self.model.setHeaderData(1, Qt.Horizontal, 'Function')
		self.model.setHeaderData(2, Qt.Horizontal, 'Callees')
		self.model.setHeaderData(3, Qt.Horizontal, 'Offset Extra Pattern')
		self.model.setHeaderData(4, Qt.Horizontal, 'Extra Pattern')
		self.model.setHeaderData(5, Qt.Horizontal, 'Source Binary')
		self.model.setHeaderData(6, Qt.Horizontal, 'ID')
		self.treeView.setModel(self.model)

		self.treeView.setSelectionBehavior(QAbstractItemView.SelectRows)
		self.treeView.setColumnWidth(0, 400)
		self.treeView.setColumnWidth(1, 200)
		self.treeView.setColumnWidth(2, 250)
		self.treeView.setColumnWidth(3, 25)
		self.treeView.setColumnWidth(4, 100)
		self.treeView.setColumnWidth(5, 200)
		self.treeView.setColumnWidth(6, 75)
		self.treeView.setItemDelegateForColumn(0, self.pattern_delegate)
		self.treeView.setItemDelegateForColumn(2, self.callee_delegate)
		self.treeView.setItemDelegateForColumn(4, self.pattern_delegate)
		self.treeView.horizontalScrollBar().setEnabled(True)
		self.treeView.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
		self.treeView.setEditTriggers(QAbstractItemView.NoEditTriggers)
		self.treeView.linkActivated.connect(self.on_func_link_clicked)
		# self.treeView.expanded.connect(lambda x: self.treeView.resizeColumnToContents(1))
		# self.treeView.collapsed.connect(lambda x: self.treeView.resizeColumnToContents(1))

		main_layout = QVBoxLayout()
		main_layout.addWidget(self.treeView)

		panel = QWidget()
		panel.setLayout(main_layout)
		self.setCentralWidget(panel)

		menuBar = self.menuBar()

		fileMenu = QMenu("File")
		openAction = QAction("&Open", self)
		openAction.setShortcuts(QKeySequence.Open)
		openAction.triggered.connect(self.open_file)
		fileMenu.addAction(openAction)

		closeAction = QAction("&Close", self)
		closeAction.setShortcuts(QKeySequence.Close)
		closeAction.triggered.connect(self.close_file)
		fileMenu.addAction(closeAction)

		saveAsAction = QAction("Save As...", self)
		saveAsAction.setShortcuts(QKeySequence.Save)
		saveAsAction.triggered.connect(self.save_as)
		fileMenu.addAction(saveAsAction)

		menuBar.addMenu(fileMenu)

		editMenu = QMenu("Edit")

		findAction = QAction("&Find", self)
		findAction.setShortcuts(QKeySequence.Find)
		findAction.triggered.connect(self.search)
		editMenu.addAction(findAction)

		self.findNextAction = QAction("&Find Next", self)
		self.findNextAction.setShortcuts(QKeySequence.FindNext)
		self.findNextAction.triggered.connect(self.select_next)
		self.findNextAction.setEnabled(False)
		editMenu.addAction(self.findNextAction)

		self.findPrevAction = QAction("&Find Prev", self)
		self.findPrevAction.setShortcuts(QKeySequence.FindPrevious)
		self.findPrevAction.triggered.connect(self.select_prev)
		self.findPrevAction.setEnabled(False)
		editMenu.addAction(self.findPrevAction)

		menuBar.addMenu(editMenu)

		viewMenu = QMenu("View")

		expandAction = QAction("&Expand All", self)
		expandAction.triggered.connect(self.treeView.expandAll)
		viewMenu.addAction(expandAction)

		collapseAction = QAction("&Collapse All", self)
		collapseAction.triggered.connect(self.treeView.collapseAll)
		viewMenu.addAction(collapseAction)

		menuBar.addMenu(viewMenu)

	def search(self):
		query_string, ok = QInputDialog.getText(self, 'Find in Trie', 'Function name')
		if not ok or not query_string:
			return

		self.searchResults = self.model.findItems(query_string, Qt.MatchContains | Qt.MatchRecursive, 1)

		if self.searchResults:
			self.findNextAction.setEnabled(True)
			self.findPrevAction.setEnabled(True)
			self.searchIndex = 0
			self.select_next()
		else:
			self.findNextAction.setEnabled(False)
			self.findPrevAction.setEnabled(False)
			self.searchIndex = -1
			QMessageBox.warning(self, 'Find in Trie', 'No results found')

	def select_next(self):
		next_item = self.searchResults[self.searchIndex]
		self.searchIndex = (self.searchIndex + 1) % len(self.searchResults)
		self.select_tree_item(next_item)

	def select_prev(self):
		prev_item = self.searchResults[self.searchIndex]
		self.searchIndex = (self.searchIndex - 1) % len(self.searchResults)
		self.select_tree_item(prev_item)

	def select_tree_item(self, item):
		path = []
		while item:
			path.insert(0, self.model.indexFromItem(item))
			item = item.parent()
		# print(path)
		for index in path:
			self.treeView.setExpanded(index, True)
		self.treeView.selectionModel().select(path[-1], QItemSelectionModel.ClearAndSelect | QItemSelectionModel.Rows)
		self.treeView.scrollTo(path[-1])

	def close_file(self):
		self.model.removeRows(0, self.model.rowCount())
		self.sig_trie = None
		self.hrefs_to_funcs = {}
		self.func_node_items = {}

	def open_file(self):
		sig_filter = 'Signature library (*.sig)'
		json_zlib_filter = 'Compressed JSON signature library (*.json.zlib)'
		json_filter = 'JSON signature library (*.json)'
		pkl_filter = 'Pickled signature library (*.pkl)'
		fname, filter = QFileDialog.getOpenFileName(self, 'Open file', filter=';;'.join([sig_filter, json_zlib_filter, json_filter, pkl_filter]))
		if filter and fname:
			print('Opening signature library %s' % (fname,))

		if filter == json_zlib_filter:
			with open(fname, 'rb') as f:
				json_trie = zlib.decompress(f.read()).decode('utf-8')
			sig_trie = sig_serialize_json.deserialize_sig_trie(json.loads(json_trie))
		elif filter == json_filter:
			with open(fname, 'r') as f:
				json_trie = f.read()
			sig_trie = sig_serialize_json.deserialize_sig_trie(json.loads(json_trie))
		elif filter == sig_filter:
			with open(fname, 'rb') as f:
				fb_trie = f.read()
			sig_trie = sig_serialize_fb.SignatureLibraryReader().deserialize(fb_trie)
		elif filter == pkl_filter:
			with open(fname, 'rb') as f:
				sig_trie = pickle.load(f)
		else:
			return

		self.open_trie(sig_trie, os.path.basename(fname))

	def save_as(self):
		sig_filter = 'Signature library (*.sig)'
		json_zlib_filter = 'Compressed JSON signature library (*.json.zlib)'
		json_filter = 'JSON signature library (*.json)'
		pkl_filter = 'Pickled signature library (*.pkl)'
		fname, filter = QFileDialog.getSaveFileName(self, 'Open file', filter=';;'.join([sig_filter, json_zlib_filter, json_filter, pkl_filter]))

		if filter == json_zlib_filter:
			with open(fname, 'wb') as f:
				f.write(zlib.compress(sig_serialize_json.serialize_sig_trie(self.sig_trie).encode('utf-8')))
		elif filter == json_filter:
			with open(fname, 'w') as f:
				json.dump(sig_serialize_json.serialize_sig_trie(self.sig_trie), f, indent=4)
		elif filter == sig_filter:
			with open(fname, 'wb') as f:
				f.write(sig_serialize_fb.SignatureLibraryWriter().serialize(self.sig_trie))
		elif filter == pkl_filter:
			with open(fname, 'wb') as f:
				pickle.dump(self.sig_trie, f)
		else:
			return
		print('Saved as ' + fname)

	@staticmethod
	def generate_href(func):
		return str(id(func))

	def get_func_name(self, func_node):
		if func_node is None:
			return '<missing>'
		else:
			return '<a href="' + self.generate_href(func_node) + '">' + func_node.name + '</a>'

	# handles when the user clicks on a hyperlink to a function node
	def on_func_link_clicked(self, link):
		print('Hyperlink clicked: ' + link)
		self.select_tree_item(self.func_node_items[self.hrefs_to_funcs[link]])

	# Generate treeview row for function (leaf) node in the trie
	def add_func_node(self, parent, pattern_col_item, func):
		self.hrefs_to_funcs[self.generate_href(func)] = func
		self.func_node_items[func] = pattern_col_item

		if not func.callees: func.callees = {}
		callees_text = '<br />'.join([str(k) + ': ' + self.get_func_name(v) for k,v in func.callees.items()])
		callees_item = QStandardItem(callees_text)
		cols = [pattern_col_item,
				QStandardItem(func.name),
				callees_item,
				QStandardItem(str(func.pattern_offset) if func.pattern else ''),
				QStandardItem(str(func.pattern) if func.pattern else ''),
				QStandardItem(func.source_binary),
				QStandardItem(self.generate_href(func))]
		boldface = cols[1].font()
		boldface.setBold(True)
		cols[1].setFont(boldface)
		parent.appendRow(cols)

	# Recursively add rows for this trie node and its children
	def add_trie_node(self, parent, pattern_text, node):
		left_item = QStandardItem(pattern_text)

		if not node.value: # Stem node
			parent.appendRow([left_item, QStandardItem('')])
		else: # Leaf node
			self.add_func_node(parent, left_item, node.value[0])
			for func in node.value[1:]:
				self.add_func_node(parent, QStandardItem(''), func)

		pairs = map(lambda node: (str(node.pattern), node), node.children.values())
		pairs = sorted(pairs, key=lambda kv: kv[0].replace('?', '\xff'))
		for text, child in pairs:
			self.add_trie_node(left_item, text, child)
		return left_item

	# Add bridge nodes to a special node at the root
	def add_bridge_nodes(self, parent, sig_trie):
		bridge_item = QStandardItem('(bridge)')
		parent.appendRow([bridge_item, QStandardItem('')])
		def visit(func, visited):
			if func is None or func in visited: return
			visited.add(func)
			if func.is_bridge:
				self.add_func_node(bridge_item, QStandardItem(''), func)
			for callee in func.callees.values():
				visit(callee, visited)
		visited = set()
		for func in sig_trie.all_values():
			visit(func, visited)

	def open_trie(self, sig_trie, filename):
		self.close_file()
		self.sig_trie = sig_trie
		root_node = self.add_trie_node(self.model, filename, sig_trie)
		self.add_bridge_nodes(root_node, sig_trie)


# copy-pasted off https://stackoverflow.com/questions/55923137/ lol
class PatternDelegate(QStyledItemDelegate):
	def __init__(self):
		super(PatternDelegate, self).__init__()
		self.font = QFontDatabase.systemFont(QFontDatabase.FixedFont)

	def paint(self, painter, option, index):
		if index.data() is None:
			return
		painter.save()

		painter.setFont(self.font)
		defaultPen = painter.pen()
		self.initStyleOption(option, index)
		style = option.widget.style()
		option.text = '' # wipe out the text passed to the original renderer, so just have it render the background
		style.drawControl(QStyle.CE_ItemViewItem, option, painter, option.widget)

		offset = 3
		ellipsis = '…'
		ellipsisWidth = painter.fontMetrics().width(ellipsis)
		rightBorder = option.rect.left() + option.rect.width() - offset

		option.rect.moveRight(option.rect.right() + offset)

		textRole = QPalette.NoRole
		if option.state & QStyle.State_Selected:
			textRole = QPalette.HighlightedText

		color = 0
		painter.setPen(defaultPen)
		for c in index.data():
			if color == 0 and c == '?': # little fsm
				color = 1
				painter.setPen(Qt.red)
			elif color == 1 and c != '?':
				color = 0
				painter.setPen(defaultPen)

			charWidth = painter.fontMetrics().width(c)
			drawRect = option.rect
			if drawRect.left() + charWidth + ellipsisWidth > rightBorder:
				style.drawItemText(painter, drawRect, option.displayAlignment, option.palette, True, ellipsis, textRole)
				break

			style.drawItemText(painter, drawRect, option.displayAlignment, option.palette, True, c, textRole)

			option.rect.moveRight(option.rect.right() + charWidth)


		painter.restore()


# https://stackoverflow.com/questions/35397943/how-to-make-a-fast-qtableview-with-html-formatted-and-clickable-cells
class CalleesDelegate(QStyledItemDelegate):
	def __init__(self):
		super(CalleesDelegate, self).__init__()

	def anchorAt(self, html, point):
		doc = QTextDocument()
		doc.setHtml(html)

		textLayout = doc.documentLayout()
		assert textLayout != None
		return textLayout.anchorAt(point)

	def paint(self, painter, option, index):
		options = option
		self.initStyleOption(options, index)

		painter.save()

		doc = QTextDocument()
		doc.setHtml(options.text)

		options.text = ""
		options.widget.style().drawControl(QStyle.CE_ItemViewItem, option, painter, option.widget)

		painter.translate(options.rect.left(), options.rect.top())
		clip = QRect(0, 0, options.rect.width(), options.rect.height())
		doc.drawContents(painter, clip)

		painter.restore()

	def sizeHint(self, option, index):
		options = option
		self.initStyleOption(options, index)

		doc = QTextDocument()
		doc.setHtml(options.text)
		doc.setTextWidth(options.rect.width())
		return QSize(doc.idealWidth(), doc.size().height())


class TrieView(QTreeView):
	linkUnhovered = Signal()
	linkHovered = Signal(str)
	linkActivated = Signal(str)

	def __init__(self, *args, **kwargs):
		super(TrieView, self).__init__(*args, **kwargs)
		self.setMouseTracking(True)
		self._mousePressAnchor = ''
		self._lastHoveredAnchor = ''

	def mousePressEvent(self, event):
		super(TrieView, self).mousePressEvent(event)
		anchor = self.anchorAt(event.pos())
		self._mousePressAnchor = anchor

	def mouseMoveEvent(self, event):
		anchor = self.anchorAt(event.pos())

		if self._mousePressAnchor != anchor:
			self._mousePressAnchor = ''

		if self._lastHoveredAnchor != anchor:
			self._lastHoveredAnchor = anchor
			if self._lastHoveredAnchor:
				QApplication.setOverrideCursor(QCursor(Qt.PointingHandCursor))
				self.linkHovered.emit(self._lastHoveredAnchor)
			else:
				QApplication.restoreOverrideCursor()
				self.linkUnhovered.emit()

	def mouseReleaseEvent(self, event):
		if self._mousePressAnchor:
			anchor = self.anchorAt(event.pos())

			if anchor == self._mousePressAnchor:
				self.linkActivated.emit(self._mousePressAnchor)

			self._mousePressAnchor = ''

		super(TrieView, self).mouseReleaseEvent(event)

	def anchorAt(self, pos):
		index = self.indexAt(pos)
		if index.isValid():
			delegate = self.itemDelegate(index)
			wordDelegate = delegate
			if isinstance(wordDelegate, CalleesDelegate):
				itemRect = self.visualRect(index)
				relativeClickPosition = pos - itemRect.topLeft()

				html = index.data()
				if html is not None:
					return wordDelegate.anchorAt(html, relativeClickPosition)

		return ''

def show_signature_library(sig_trie):
	if not QApplication.instance():
		app = QApplication(sys.argv)
	else:
		app = None
	widget = App()
	widget.show()
	widget.open_trie(sig_trie, '(memory)')
	if app:
		app.exec_()

if __name__ == "__main__":
	app = QApplication(sys.argv)

	widget = App()
	widget.show()

	sys.exit(app.exec_())
