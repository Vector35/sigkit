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
"""

from sigkit.sig_serialize_fb import *
import sigkit.sig_serialize_json

if __name__ == '__main__':
	import sys

	if len(sys.argv) < 2:
		print('Usage: convert_siglib.py <signature library>')
		sys.exit(1)

	filename = sys.argv[1]
	basename, ext = filename[:filename.index('.')], filename[filename.index('.'):]
	if ext == '.pkl':
		import pickle
		with open(filename, 'rb') as f:
			sig_trie = pickle.load(f)
	elif ext == '.json.zlib':
		import json, zlib
		with open(filename, 'rb') as f:
			sig_trie =  sigkit.sig_serialize_json.deserialize(json.loads(zlib.decompress(f.read()).decode('utf-8')))
	else:
		print('Unsupported file extension ' + ext)
		sys.exit(1)

	buf = SignatureLibraryWriter().serialize(sig_trie)
	with open(basename + '.sig', 'wb') as f:
		f.write(buf)

	# This is a pretty stringent assertion, but I want to be sure this implementation is correct.
	# having the exact same round-trip depends on having a consistent iteration order through the trie as well
	# as the ordering of the functions per node. That's enforced by iterating the trie (DFS) in a sorted fashion.
	assert buf == SignatureLibraryWriter().serialize(SignatureLibraryReader().deserialize(buf))
