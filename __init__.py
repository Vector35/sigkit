# coding=utf-8

# Copyright (c) 2019-2020 Vector 35 Inc
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

import binaryninjaui
from binaryninja import *

# exports
from . import trie_ops
from . import sig_serialize_fb
from . import sig_serialize_json

from .signaturelibrary import TrieNode, FunctionNode, Pattern, MaskedByte, new_trie
from .sig_serialize_fb import SignatureLibraryReader, SignatureLibraryWriter
from .compute_sig import process_function as generate_function_signature
from .sigexplorer import explore_signature_library

def load_signature_library(filename):
	"""
	Load a signature library from a .sig file.
	:param filename: input filename
	:return: instance of `TrieNode`, the root of the signature trie.
	"""
	with open(filename, 'rb') as f:
		buf = f.read()
	return SignatureLibraryReader().deserialize(buf)

def save_signature_library(sig_lib, filename):
	"""
	Save the given signature library to a file.
	:param sig_lib: instance of `TrieNode`, the root of the signature trie.
	:param filename: destination filename
	"""
	buf = SignatureLibraryWriter().serialize(sig_lib)
	with open(filename, 'wb') as f:
		f.write(buf)

def signature_explorer(prompt=True):
	"""
	Open the signature explorer UI.
	:param prompt: if True, prompt the user to open a file immediately.
	:return: `App`, a QT window
	"""
	if "qt_major_version" in binaryninjaui.__dict__ and binaryninjaui.qt_major_version == 6:
		from PySide6.QtWidgets import QApplication
	else:
		from PySide2.QtWidgets import QApplication
	app = QApplication.instance()
	global widget # avoid lifetime issues from it falling out of scope
	widget = sigexplorer.App()
	if prompt:
		widget.open_file()
	widget.show()
	if app: # VERY IMPORTANT to avoiding lifetime issues???
		app.exec_()
	return widget


# UI plugin code
def _generate_signature_library(bv):
	guess_relocs = len(bv.relocation_ranges) == 0
	if guess_relocs:
		log.log_debug('Relocation information unavailable; choosing pattern masks heuristically')
	else:
		log.log_debug('Generating pattern masks based on relocation ranges')

	func_count = sum(map(lambda func: int(bool(bv.get_symbol_at(func.start))), bv.functions))
	log.log_info('Generating signatures for %d functions' % (func_count,))
	# Warning for usability purposes. Someone will be confused why it's skipping auto-named functions
	if func_count / float(len(bv.functions)) < 0.5:
		num_skipped = len(bv.functions) - func_count
		log.log_warn("%d functions that don't have a name or symbol will be skipped" % (num_skipped,))

	funcs = {}
	for func in bv.functions:
		if bv.get_symbol_at(func.start) is None: continue
		func_node, info = generate_function_signature(func, guess_relocs)
		funcs[func_node] = info
		log.log_debug('Processed ' + func.name)

	log.log_debug('Constructing signature trie')
	trie = signaturelibrary.new_trie()
	trie_ops.trie_insert_funcs(trie, funcs)
	log.log_debug('Finalizing trie')
	trie_ops.finalize_trie(trie, funcs)

	output_filename = get_save_filename_input("Filename:", "*.sig", bv.file.filename + '.sig')
	if not output_filename:
		log.log_debug('Save cancelled')
		return
	output_filename = output_filename.decode('utf-8')
	buf = sig_serialize_fb.SignatureLibraryWriter().serialize(trie)
	with open(output_filename, 'wb') as f:
		f.write(buf)
	log.log_info('Saved to ' + output_filename)

PluginCommand.register(
	"Signature Library\\Generate Signature Library",
	"Create a Signature Library that the Signature Matcher can use to locate functions.",
	_generate_signature_library
)

PluginCommand.register(
	"Signature Library\\Explore Signature Library",
	"View a Signature Library's contents in a graphical interface.",
	lambda bv: signature_explorer()
)
