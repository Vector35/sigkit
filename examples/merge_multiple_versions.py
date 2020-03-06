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

"""
This script shows how you can merge the signature libraries generated for
different versions of the same library. We would want to do this because
there's like a lot of overlap between the two and duplicated functions.
We want to avoid creating huge signatures that are bloated with these
duplicated functions, so we will deduplicate them using the trie_ops package.

This script loads pickled dicts of {FunctionNode: FunctionInfo} generated
by batch_process.py.
"""

import pickle, json
import gc
from pathlib import Path

import sigkit.signaturelibrary, sigkit.trie_ops, sigkit.sig_serialize_json


def func_count(trie):
	return len(set(trie.all_functions()))

# Clean up the functions list, exclude some garbage functions, etc.
def preprocess_funcs_list(func_info):
	import re
	to_delete = set()
	for f in func_info:
		if re.match(r'\.L\d+', f.name):
			to_delete.add(f)
			continue
		f.name = f.name[:40] # trim long names
	for f in to_delete:
		del func_info[f]

def load_pkls(path, glob):
	pkls = list(map(str, Path(path).glob(glob)))
	trie, func_info = sigkit.signaturelibrary.new_trie(), {}
	for pkl in pkls:
		with open(pkl, 'rb') as f:
			pkl_funcs = pickle.load(f)
			preprocess_funcs_list(pkl_funcs)
			sigkit.trie_ops.trie_insert_funcs(trie, pkl_funcs)
			func_info.update(pkl_funcs)
	sigkit.trie_ops.finalize_trie(trie, func_info)
	return trie, func_info

gc.disable() # I AM SPEED - Lightning McQueen
dst_trie, dst_info = load_pkls('.', 'libc_version1/*.pkl')
src_trie, src_info = load_pkls('.', 'libc_version2/*.pkl')
gc.disable() # i am no longer speed.

size1, size2 = func_count(dst_trie), func_count(src_trie)
print("Pre-merge sizes: %d + %d = %d funcs" % (size1, size2, size1+size2))

sigkit.trie_ops.combine_signature_libraries(dst_trie, dst_info, src_trie, src_info)
print("Post-merge size: %d funcs" % (func_count(dst_trie),))

sigkit.trie_ops.finalize_trie(dst_trie, dst_info)
print("Finalized size: %d funcs" % (func_count(dst_trie),))

print(json.dumps(sigkit.sig_serialize_json.serialize(dst_trie)))
import sigexplorer
sigexplorer.show_signature_library(dst_trie)
