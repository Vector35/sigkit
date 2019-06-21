# coding=utf-8

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
This package contains code for advanced manipulation of signature library
data structures and operations like signature trie merging and finalization.
This package is intended for users who are creating their own signature
libraries.

The most useful functions are `trie_insert_funcs`, `combine_signature_libraries`,
`update_signature_library`, and `finalize_trie`.
"""

# You know the old joke, right?
# When I wrote this code, only God and I understood it.
# now only God understands it

import sys
from collections import defaultdict
from functools import reduce
import operator

from binaryninja import SymbolType

from . import signaturelibrary

class FunctionInfo(object):
	"""
	Stores additional information about functions that are useful while generating and manipulating
	signature libraries, but excluded from the finalized signature library to save space.
	This information is also used to simulate linking when generating the call-graph.
	"""
	def __init__(self):
		self.patterns = None
		self.callees = None
		self.aliases = None


def are_names_compatible(a, b):
	if a == b:
		return True
	if a.name == b.name:
		return True
	if a.name.startswith(b.name) or b.name.startswith(a.name):
		return True
	if len(a.name) > 12 and len(b.name) > 12:
		return a.name in b.name or b.name in a.name
	return False


# mathematically speaking, this is defines a less-than-or-equal-to operation over the
# set of function signatures and therefore a partial ordering over that set.
# Let A, B both be signatures. we say that that A <= B if all functions that A matches
# are also matched by B. In other words, for a signature library containing B, it would be
# redundant to add A, since B already already matches all of the functions that A would.
#
# Let A ⨅ B denote a signature that would match all functions matched by both A and B.
# ⨅ defines a "meet" relationship on the lattice of signatures.
# in other words, A <= B iff A ⨅ B = B (and commutatively, B ⨅ A = A).
# concretely, A ⨅ B is equivalent to the signature with pattern and callees that is the
# intersection those of A and B. thus, we can check if A = (A ⨅ B), and likewise A <= B,
# by matching A's pattern directly against B's pattern.
#
# the greatest element of this lattice is None, a signature that matches all functions.
#
# during optimization during trie finalization, we delete all non-maximal signatures
# in the signature trie; i.e., all signatures which are less than another one (and therefore
# redundant) are eliminated. the downside to this approach is that we will lose a degree
# of specificity: consider a function which matches B but doesn't match A (where A <= B).
# we could choose to keep both A and B in the signature library, but if we encountered such
# a function, what should we do with it? how do we distinguish between functions which match
# both A and B as opposed to ones which only match B? more importantly, what name should
# be assigned to such a function? therefore, it's meaningless to include both A and B, and
# eliminating the redundancy also reduces the ambiguity of matches.
#
# this function returns whether A <= B, for two function signatures A and B.
#
# sometimes, we don't have function info (e.g., function bytes) for both nodes. this is typically
# when we're trying to merge additional nodes into a trie that we don't have FunctionInfo for.
# in this case, we only need function info for the nodes we're trying to merge in by exploiting
# the signature trie. We know A <= B if searching for A's data in the trie matches B.
def is_signature_subset(a, func_info, b, sig_trie, visited):
	"""
	:param a: FunctionNode to check whether is a subset of B
	:param func_info: dict containing the function info for A's trie
	:param b: FunctionNode to check whether it contains A
	:param sig_trie: the trie B belongs to.
	:param visited: visited set, should be initialized to {}
	:return: whether A matches a subset of what B matches
	"""
	if a == b:
		return True
	if int(a is None) < int(b is None):
		return True
	if int(a is None) > int(b is None):
		return False
	assert isinstance(a, signaturelibrary.FunctionNode)
	assert isinstance(b, signaturelibrary.FunctionNode)
	assert a in func_info

	# this is essentially a dfs on the callgraph. if we encounter a backedge,
	# treat it optimistically, implying that the callers match if the callees match.
	# however, we track our previous assumptions, meaning that if we previously
	# optimistically assumed b == a, then later on if we compare b and c, we say
	# that b != c since we already assumed b == a (and we already checked above that c != a).
	if b in visited:
		return visited[b] == a
	visited[b] = a

	# if A is bridge, but B isn't, A is obviously more ambiguous than B. (and vice versa)
	if int(a.is_bridge) < int(b.is_bridge):
		return True
	if int(a.is_bridge) > int(b.is_bridge):
		return False

	if not b.is_bridge:
		for a_pattern in func_info[a].patterns:
			# if A is a subset of B, then B >= A; i.e., searching the trie for A's data should match B.
			# A <= B --> A ⨅ B = B
			if b not in sig_trie.find(a_pattern):
				return False

	# return false if B's additional pattern doesn't match A (B ⨅ A != B)
	for a_pattern in func_info[a].patterns:
		if b.pattern_offset >= 0 and b.pattern_offset + len(b.pattern) < len(a_pattern):
			if not b.pattern.matches(a_pattern[b.pattern_offset:]):
				return False

	# check that all callees required by B are also required by A
	for call_site, callee in b.callees.items():
		if callee is not None and call_site not in a.callees:
			return False
	if not all(map(lambda k: is_signature_subset(a.callees[k] if k in a.callees else None, func_info,
												 b.callees[k], sig_trie, visited), b.callees)):
		return False

	return True


def rewrite_callgraph(funcs, to_delete):
	# complete the DFS first, avoid simultaneous modification and traversal
	inverse_callgraph = defaultdict(set)
	for func in funcs:
		if func in to_delete: continue
		for callee in func.callees.values():
			if callee in to_delete:
				inverse_callgraph[callee].add(func)

	def follow(k):
		while k in to_delete:
			k = to_delete[k]
		return k

	# rewrite callgraph
	for k in to_delete:
		v = follow(k)
		for func in inverse_callgraph[k]:
			for call_site in func.callees:
				if func.callees[call_site] == k:
					func.callees[call_site] = v
					assert k != v
					# print('replace', k.name, id(k), '=>', v.name, id(v),'in', func.name)


def rewrite_trie(sig_trie, to_delete, update=False):
	def follow(k):
		while k in to_delete:
			k = to_delete[k]
		return k

	# rewrite trie values
	for node in sig_trie.all_nodes():
		if not node.value: continue
		new_value = []
		for func in node.value:
			func.ref_count -= 1
			if func in to_delete:
				if update:
					v = follow(func)
					if v not in new_value:
						v.ref_count += 1
						new_value.append(v)
			else:
				if func not in new_value:
					func.ref_count += 1
					new_value.append(func)
		node.value = new_value

	# dfs; delete functionless subtries
	def prune(node):
		if not node.children:
			should_delete = not node.value
			return should_delete
		new_children = {}
		for b, c in node.children.items():
			should_delete = prune(c)
			if not should_delete:
				new_children[b] = c
		node.children = new_children
		should_delete = not node.children and not node.value
		return should_delete
	prune(sig_trie)


# one-way deduplication (trie1 to trie2)
def find_redundant(trie1, info1, trie2):
	cache = {}
	def cached_is_signature_subset(a, func_info, b, sig_trie, visited):
		if (a, b) in cache:
			return cache[(a, b)]
		result = is_signature_subset(a, func_info, b, sig_trie, visited)
		cache[(a, b)] = result
		return result


	# search trie2 for funcs from trie1. if `A` is matched by `B`, then `A` matches a subset of `B`
	# and should be discarded. references to `A` should be replaced by references to `B`.
	# algebraically if A ⨅ B = A, then A <= B, so A is redundant.
	to_delete = {}

	def check_if_redundant(func_a, func_b):
		while func_b in to_delete:  # avoid cycles
			func_b = to_delete[func_b]
		if func_a == func_b: # avoid infinite loop
			return False
		if not are_names_compatible(func_a, func_b):
			return False
		if cached_is_signature_subset(func_a, info1, func_b, trie2, {}):  # func <= cand. func is redundant
			to_delete[func_a] = func_b
			return True
		return False

	for func in info1: # func is our `A`
		for pattern in info1[func].patterns:
			candidates = trie1.find(pattern)
			for cand in candidates: # cand is our `B`
				check_if_redundant(func, cand)

	# also clean up useless bridge nodes
	bridges1 = list(filter(lambda f: f.is_bridge, info1))
	bridges2 = list(filter(lambda f: f.is_bridge, trie2.all_functions()))
	for func in bridges1:
		for cand in bridges2:
			check_if_redundant(func, cand)

	return to_delete


# Would it be ok substitute A with B if they have the same name? In that case, trie position is irrelevant as
# we can just have multiple leaf nodes pointing to the same function node
def can_substitute(a, b):
	if a == b: return True
	if (b is None) != (a is None): return False
	assert isinstance(a, signaturelibrary.FunctionNode)
	assert isinstance(b, signaturelibrary.FunctionNode)

	if not are_names_compatible(a, b):
		return False

	# if A is bridge, but B isn't, A is obviously more ambiguous than B.
	if int(a.is_bridge) < int(b.is_bridge):
		return False

	# check that all callees required by B are also required by A
	for call_site, callee in b.callees.items():
		if callee is not None and call_site not in a.callees:
			return False

	return True

# deal with signatures with the same name at different parts in the signature trie that can be merged
def collapse_by_name(func_info):
	by_name = defaultdict(set)
	for f in func_info:
		by_name[f.name].add(f)
	to_delete = {}
	for family in by_name.values():
		for func in family:
			for cand in family:
				while cand in to_delete: # avoid cycles
					cand = to_delete[cand]
				if func == cand: # avoid infinite loop
					continue
				if can_substitute(func, cand):
					to_delete[func] = cand
					# transfer patterns and aliases from deleted functioninfo to cand's
					cand_info = func_info[cand]
					deleted_info = func_info[func]
					cand_info.patterns.extend(deleted_info.patterns)
					cand_info.aliases.extend(deleted_info.aliases)
					deleted_info.patterns = [] # free memory (!)
					deleted_info.aliases = []
	return to_delete


def sanity_check(sig_trie):
	if not sig_trie.children:
		sys.stderr.write('Warning: no functions in trie\n')
		return

	count = defaultdict(lambda: 0)
	for func in sig_trie.all_values():
		count[func] += 1
	for func in sig_trie.all_functions():
		assert func.ref_count == count[func]


# we avoid linking across library boundaries ... they're discrete compilation units and we shouldn't assume
# anything about inter-module calls. who knows which version will be linked with what!
# if we can't resolve the reference, exclude that from the signature! if an optional library isn't linked,
# the call will turn into a stub (like jump 0x0), and will not be a call in the real binary.
# so, we give that a wildcard. in our matching algorithm, we allow calls to wildcard callee to be optional.
def resolve_reference(name, sym_type, source_binary, source_to_node):
	if sym_type == SymbolType.FunctionSymbol:
		# look for callee from the same object file
		if source_binary in source_to_node:
			result = source_to_node[source_binary]
			# print('resolved static reference', name, '=', result.name, 'from', source_binary)
			return result
		else:
			# sys.stderr.write('Warning: missing static reference ' + name + ' from ' + source_binary + '\n')
			return None
	else:
		# look for callee in a different object file
		possible_callees = []
		for source in source_to_node:
			if source != source_binary:
				possible_callees.append(source_to_node[source])
		if not possible_callees:
			# sys.stderr.write('Warning: missing extern reference ' + name + ' from ' + source_binary + '\n')
			return None
		elif len(possible_callees) > 1:
			# sys.stderr.write('Warning: multiple definitions for external reference ' + name + ' from ' + source_binary + ': '+ ', '.join(map(lambda n: n.name, possible_callees)) + '\n')
			return None
		else:
			# print('resolved extern reference', name, '=', possible_callees[0].name)
			return possible_callees[0]


def link_callgraph(func_info):
	"""
	Construct the callgraph based on `FunctionInfo` and link all the `FunctionNode`s together.
	:param func_info:
	:return:
	"""
	name_to_source_to_node = defaultdict(dict)
	for node, info in func_info.items():
		for name in [node.name] + info.aliases:
			name_to_source_to_node[name][node.source_binary] = node

	for node, info in func_info.items():
		node.callees = {call_site: resolve_reference(name, sym_type, node.source_binary, name_to_source_to_node[name])
						for call_site, (name, sym_type) in info.callees.items()}
		# Wildcard out callees that are masked out.
		def is_valid_call_site(i):
			if i < 0: return False
			for pattern in info.patterns:
				if i >= len(pattern): return False
				if not pattern[i]: return False
			return True
		node.callees = {call_site: callee if is_valid_call_site(call_site) else None
						for call_site, callee in node.callees.items()}


def choose_disambiguation_bytes(sig_trie, func_info, min_offset=32, maxlen=5):
	for node in sig_trie.all_nodes():
		if not node.value: continue
		for f in node.value: assert f in func_info
		for f in node.value: # reset patterns
			f.pattern = signaturelibrary.Pattern(b'', [])
			f.pattern_offset = 0
		if len(node.value) <= 1: continue

		# since a FunctionNode can have multiple patterns in its FunctionInfo, we say that the set of functions
		# it matches is based on the *join* ⨆ of all of these patterns. our goal here is to find some substring
		# in all of these patterns that share no intersection.
		#
		# let P(f) denote the patterns belonging to FunctionNode f's FunctionInfo.
		# then let PU(f) = ⨆ P(f) ; i.e. the join of all patterns, a pattern that would match the union of functions matched by those patterns.
		# given some functions f1,f2,... at this trie node, we want to find some substring (i,j) in PU(f1),PU(f2),...
		# such that PU(fx)[i:j] ⨅ PU(fy)[i:j] = 0 for all pairs fx,fy in f1,f2,...
		# then we will choose PU(f)[i:j] as f's disambiguation pattern for each FunctionNode f in f1,f2,...

		pu = {func: reduce(signaturelibrary.Pattern.union, func_info[func].patterns) for func in node.value}
		min_len = min(map(len, pu.values()))
		if min_len <= min_offset: # this is hopeless. all those bytes are already in the trie
			# print('Warn: no possible disambiguation (length) for', repr(node))
			continue
		if reduce(operator.eq, pu.values()):
			# print('Warn: no possible disambiguation (content) for', repr(node))
			continue

		def ok(i, j):
			for fx in node.value:
				for fy in node.value:
					if fx == fy: continue
					if pu[fx][i:j].intersect(pu[fy][i:j]) is not None:
						return False
			return True

		for i in range(min_offset, min_len-1): # unfortunately, this is O(min_len*maxlen).
			j = i+1
			while not ok(i, j) and j < min_len and j-i < maxlen:
				j += 1
			while ok(i+1, j) and i+1 < j:
				i += 1
			if ok(i, j):
				for f in node.value:
					f.pattern = pu[f][i:j]
					f.pattern_offset = i
				break
		# else:
		#     print('Warn: failed to choose disambiguation for', repr(node))


# finalizing a trie links the call graph and removes any redundant nodes, and adds disambiguation bytes
def finalize_trie(sig_trie, func_info):
	link_callgraph(func_info)
	sanity_check(sig_trie)

	to_delete = find_redundant(sig_trie, func_info, sig_trie)
	rewrite_callgraph(func_info, to_delete)
	rewrite_trie(sig_trie, to_delete)
	for k in to_delete: assert k.ref_count == 0
	for k in to_delete: del func_info[k]
	to_delete = collapse_by_name(func_info)

	rewrite_callgraph(func_info, to_delete)
	rewrite_trie(sig_trie, to_delete)
	for k in to_delete: assert k.ref_count == 0
	for k in to_delete: del func_info[k]
	sanity_check(sig_trie)

	choose_disambiguation_bytes(sig_trie, func_info)


# inserts functions from FunctionInfo dict `src_info` into trie `dst_trie`.
def trie_insert_funcs(dst_trie, src_info, maxlen=32):
	for to_add in src_info:
		to_add.ref_count = 0 # we are repatriating this function node. reset refcount
		for pattern in src_info[to_add].patterns:
			pattern = pattern[:maxlen]
			inserted = dst_trie.insert(pattern, to_add)


# merges a signature trie `src_trie` into another signature trie dst_trie`, with FunctionInfo only available for `src_trie`.
# `dst_trie` is modified.
def update_signature_library(dst_trie, src_trie, src_info):
	link_callgraph(src_info) # build callgraph

	# identify redundant signatures
	to_delete = find_redundant(src_trie, src_info, dst_trie)

	# merge
	trie_insert_funcs(dst_trie, src_info)
	rewrite_callgraph(dst_trie.all_functions(), to_delete)
	rewrite_trie(dst_trie, to_delete)

	sanity_check(dst_trie)


# combines two signature tries, `src_trie` into `dst_trie` where FunctionInfo is available for both tries.
# both `dst_trie` and `dst_info` are mutated: functions from `src_trie`  and `src_info` are added `dst_trie` and `dst_info`.
def combine_signature_libraries(dst_trie, dst_info, src_trie, src_info):
	# merge
	trie_insert_funcs(dst_trie, src_info)
	dst_info.update(src_info)

	# identify redundant signatures
	to_delete = find_redundant(dst_trie, dst_info, src_trie)
	rewrite_callgraph(dst_info, to_delete)
	rewrite_trie(dst_trie, to_delete)
	for k in to_delete: assert k.ref_count == 0
	for k in to_delete: del dst_info[k]

	sanity_check(dst_trie)
