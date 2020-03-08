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
This utility shows how to load and save signature libraries using the sigkit API.
Although many file formats are supported, Binary Ninja will only support signatures
in the .sig (flatbuffer) format. The other formats are provided for debugging
purposes.
"""

import pickle
import zlib

from sigkit import *

if __name__ == '__main__':
	import sys

	if len(sys.argv) < 2:
		print('Usage: convert_siglib.py <signature library>')
		sys.exit(1)

	# Load a signature library.
	filename = sys.argv[1]
	basename, ext = filename[:filename.index('.')], filename[filename.index('.'):]
	if ext == '.sig':
		with open(filename, 'rb') as f:
			sig_trie = sig_serialize_fb.load(f)
	elif ext == '.json':
		with open(filename, 'r') as f:
			sig_trie = sig_serialize_json.load(f)
	elif ext == '.json.zlib':
		with open(filename, 'rb') as f:
			sig_trie =  sig_serialize_json.deserialize(json.loads(zlib.decompress(f.read()).decode('utf-8')))
	elif ext == '.pkl':
		with open(filename, 'rb') as f:
			sig_trie = pickle.load(f)
	else:
		print('Unsupported file extension ' + ext)
		sys.exit(1)

	# Save the signature library to a binary format and write it to a file.
	buf = sig_serialize_fb.dumps(sig_trie)
	with open(basename + '.sig', 'wb') as f:
		f.write(buf)

	# This is a pretty stringent assertion, but I want to be sure this implementation is correct.
	# having the exact same round-trip depends on having a consistent iteration order through the trie as well
	# as the ordering of the functions per node. That's enforced by iterating the trie (DFS) in a sorted fashion.
	assert buf == sig_serialize_fb.SignatureLibraryWriter().serialize(sig_serialize_fb.SignatureLibraryReader().deserialize(buf))
