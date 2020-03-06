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

from binaryninja import *

from . import signaturelibrary
from . import compute_sig
from . import trie_ops
from . import sig_serialize_fb
from . import sigexplorer

# exports and utility functions
SignatureLibraryReader = sig_serialize_fb.SignatureLibraryReader
SignatureLibraryWriter = sig_serialize_fb.SignatureLibraryWriter

def load_signature_library(filename):
	with open(filename, 'rb') as f:
		buf = f.read()
	return SignatureLibraryReader().deserialize(buf)

def save_signature_library(sig_lib, filename):
	buf = SignatureLibraryWriter().serialize(sig_lib)
	with open(filename, 'wb') as f:
		f.write(buf)


def generate_signature_library(bv):
	guess_relocs = len(bv.relocation_ranges) == 0
	if guess_relocs:
		log.log_debug('Relocation information unavailable; choosing pattern masks heuristically')
	else:
		log.log_debug('Generating pattern masks based on relocation ranges')

	func_count = sum(map(lambda func: int(bool(bv.get_symbol_at(func.start))), bv.functions))
	log.log_info('Generating signatures for %d functions' % (func_count,))
	# Warning for usability purposes. Someone will be confused why it's skipping auto-named functions
	if func_count / float(len(bv.functions)) < 0.5:
		log.log_warn("Functions that don't have a name or symbol will be skipped")

	funcs = {}
	for func in bv.functions:
		if bv.get_symbol_at(func.start) is None: continue
		func_node, info = compute_sig.process_function(func, guess_relocs)
		funcs[func_node] = info
		log.log_debug('Processed ' + func.name)

	log.log_info('Constructing signature trie')
	trie = signaturelibrary.new_trie()
	trie_ops.trie_insert_funcs(trie, funcs)
	log.log_debug('Finalizing trie')
	trie_ops.finalize_trie(trie, funcs)

	output_filename = get_save_filename_input("Filename:", "*.sig", bv.file.filename + '.sig').decode('utf-8')
	if not output_filename:
		log.log_info('Cancelled')
		return
	buf = sig_serialize_fb.SignatureLibraryWriter().serialize(trie)
	with open(output_filename, 'wb') as f:
		f.write(buf)
	log.log_info('Saved to ' + output_filename)


def explore_signature_library(bv):
	app = sigexplorer.App()
	app.open_file()
	app.show()

PluginCommand.register(
	"Signature Library\\Generate Signature Library",
	"Create a Signature Library that the Signature Matcher can use to locate functions.",
	generate_signature_library
)

PluginCommand.register(
	"Signature Library\\Explore Signature Library",
	"View a Signature Library's contents in a graphical interface.",
	explore_signature_library
)
