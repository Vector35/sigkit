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

from .sigkit.sig_serialize_fb import SignatureLibraryReader, SignatureLibraryWriter
from .sigkit.compute_sig import process_function as generate_function_signature

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
