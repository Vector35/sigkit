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
JSON serialization / deserialization
"""

import json

from . import signaturelibrary

def _serialize_func_node(func_node, func_node_ids):
	return {
		'name': func_node.name,
		'source_binary': func_node.source_binary,
		'pattern': str(func_node.pattern),
		'pattern_offset': func_node.pattern_offset,
		'callees': {str(call_site): func_node_ids[callee] for call_site, callee in func_node.callees.items()},
		'is_bridge': func_node.is_bridge
	}

def _serialize_trie_node(trie_node, func_node_ids):
	children = {str(k) : _serialize_trie_node(v, func_node_ids) for k, v in trie_node.children.items()}
	if trie_node.value:
		functions = [func_node_ids[f] for f in trie_node.value]
	else:
		functions = []
	return {
		'pattern': str(trie_node.pattern),
		'children': children,
		'functions': functions,
	}

def serialize(sig_trie):
	"""
	Serialize a signature trie to a JSON-compatible format.
	:param sig_trie: `TrieNode` object
	:return: a python dictionary ready for serialization as JSON
	"""
	func_nodes = []
	func_node_ids = {None: -1}
	def visit(func_node):
		if func_node in func_node_ids: return
		func_node_ids[func_node] = len(func_nodes)
		func_nodes.append(func_node)
		for f in func_node.callees.values(): visit(f)
	for f in sig_trie.all_values(): visit(f)

	return {
		'functions': [_serialize_func_node(f, func_node_ids, ) for f in func_nodes],
		'trie': _serialize_trie_node(sig_trie, func_node_ids)
	}

def _deserialize_pattern(serialized):
	return signaturelibrary.Pattern.from_str(serialized)


def _deserialize_func_node(serialized):
	func_node = signaturelibrary.FunctionNode(serialized['name'])
	func_node.source_binary = serialized['source_binary']
	func_node.pattern = _deserialize_pattern(serialized['pattern'])
	func_node.pattern_offset = serialized['pattern_offset']
	# func_node.is_bridge = serialized['is_bridge']
	return func_node

def _deserialize_trie_node(serialized, funcs_arr):
	return signaturelibrary.TrieNode(
		_deserialize_pattern(serialized['pattern']),
		{signaturelibrary.MaskedByte.from_str(k): _deserialize_trie_node(v, funcs_arr) for k, v in serialized['children'].items()},
		[funcs_arr[i] for i in serialized['functions']] if serialized['functions'] else []
	)

def deserialize(serialized):
	"""
	Deserialize a signature trie from JSON data.
	:param serialized: a dict containing JSON-format data to signature trie objects.
	:return: the root `TrieNode`
	"""
	funcs_serialized = serialized['functions']
	funcs = [_deserialize_func_node(f) for f in funcs_serialized]
	for i in range(len(funcs)): # link callgraph
		funcs[i].callees = {int(call_site): None if callee_id == -1 else funcs[callee_id]
							for call_site, callee_id in funcs_serialized[i]['callees'].items()}

	return _deserialize_trie_node(serialized['trie'], funcs)

def dumps(sig_trie, *args, **kwargs):
	return json.dumps(serialize(sig_trie), *args, **kwargs)

def dump(sig_trie, fp, *args, **kwargs):
	return json.dump(serialize(sig_trie), fp, *args, **kwargs)

def loads(serialized, *args, **kwargs):
	return deserialize(json.loads(serialized, *args, **kwargs))

def load(fp, *args, **kwargs):
	return deserialize(json.load(fp, *args, **kwargs))
