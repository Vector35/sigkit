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
This file contains a signature matcher implementation in Python. This
implementation is only an illustrative example and should be used for testing
purposes only. It is extremely slow compared to the native implementation
found in Binary Ninja. Furthermore, the algorithm shown here is outdated
compared to the native implementation, so matcher results will be of inferior
quality.
"""

from __future__ import print_function

from binaryninja import *

import sigkit.compute_sig

class SignatureMatcher(object):
	def __init__(self, sig_trie, bv):
		self.sig_trie = sig_trie
		self.bv = bv

		self._matches = {}
		self._matches_inv = {}
		self.results = {}

		self._cur_match_debug = ""

	def resolve_thunk(self, func, level=0):
		if sigkit.compute_sig.get_func_len(func) >= 8:
			return func

		first_insn = func.mlil[0]
		if first_insn.operation == MediumLevelILOperation.MLIL_TAILCALL:
			thunk_dest = self.bv.get_function_at(first_insn.dest.value.value)
		elif first_insn.operation == MediumLevelILOperation.MLIL_JUMP and first_insn.dest.operation == MediumLevelILOperation.MLIL_LOAD and first_insn.dest.src.operation == MediumLevelILOperation.MLIL_CONST_PTR:
			data_var = self.bv.get_data_var_at(first_insn.dest.src.value.value)
			if not data_var or not data_var.data_refs_from: return None
			thunk_dest = self.bv.get_function_at(data_var.data_refs_from[0])
		else:
			return func

		if thunk_dest is None:
			return None

		if level >= 100:
			# something is wrong here. there's a weird infinite loop of thunks.
			sys.stderr.write('Warning: reached recursion limit while trying to resolve thunk %s!\n' % (func.name,))
			return None

		print('* following thunk %s -> %s' % (func.name, thunk_dest.name))
		return self.resolve_thunk(thunk_dest, level + 1)

	def on_match(self, func, func_node, level=0):
		if func in self._matches:
			if self._matches[func] != func_node:
				sys.stderr.write('Warning: CONFLICT on %s: %s vs %s' % (func.name, self._matches[func], func_node) + '\n')
				if func in self.results:
					del self.results[func]
			return

		self.results[func] = func_node

		if func_node in self._matches_inv:
			if self._matches_inv[func_node] != func:
				sys.stderr.write('Warning: INVERSE CONFLICT (%s) on %s: %s vs %s' % (self._cur_match_debug, func_node, self._matches_inv[func_node].name, func.name) + '\n')
			return

		print((' ' * level) + func.name, '=>', func_node.name, 'from', func_node.source_binary, '(' + self._cur_match_debug + ')')
		self._matches[func] = func_node
		self._matches_inv[func_node] = func

	def compute_func_callees(self, func):
		"""
		Return a list of the names of symbols the function calls.
		"""
		callees = {}
		for ref in func.call_sites:
			callee_addrs = self.bv.get_callees(ref.address, ref.function, ref.arch)
			if len(callee_addrs) != 1: continue
			callees[ref.address - func.start] = self.bv.get_function_at(callee_addrs[0])
		return callees

	def does_func_match(self, func, func_node, visited, level=0):
		print((' '*level) + 'compare', 'None' if not func else func.name, 'vs', '*' if not func_node else func_node.name, 'from ' + func_node.source_binary if func_node else '')
		# no information about this function. assume wildcard.
		if func_node is None:
			return 999

		# we expect a function to be here but there isn't one. no match.
		if func is None:
			return 0

		# fix for msvc thunks -.-
		thunk_dest = self.resolve_thunk(func)
		if not thunk_dest:
			sys.stderr.write('Warning: encountered a weird thunk %s, giving up\n' % (func.name,))
			return 0
		func = thunk_dest

		# this is essentially a dfs on the callgraph. if we encounter a backedge,
		# treat it optimistically, implying that the callers match if the callees match.
		# however, we track our previous assumptions, meaning that if we previously
		# optimistically assumed b == a, then later on if we compare b and c, we say
		# that b != c since we already assumed b == a (and c != a)
		if func in visited:
			print("we've already seen visited one before")
			return 999 if visited[func] == func_node else 0
		visited[func] = func_node

		# if we've already figured out what this function is, don't waste our time doing it again.
		if func in self._matches:
			return 999 if self._matches[func] == func_node else 0

		func_len = sigkit.compute_sig.get_func_len(func)
		func_data = self.bv.read(func.start, func_len)
		if not func_node.is_bridge:
			trie_matches = self.sig_trie.find(func_data)
			if func_node not in trie_matches:
				print((' ' * level) + 'trie mismatch!')
				return 0
		else:
			print((' ' * level) + 'this is a bridge node.')

		disambiguation_data = func_data[func_node.pattern_offset:func_node.pattern_offset + len(func_node.pattern)]
		if not func_node.pattern.matches(disambiguation_data):
			print((' ' * level) + 'disambiguation mismatch!')
			return 1

		callees = self.compute_func_callees(func)
		for call_site in callees:
			if call_site not in func_node:
				print((' ' * level) + 'call sites mismatch!')
				return 2
		for call_site, callee in func_node.callees.items():
			if callee is not None and call_site not in callees:
				print((' ' * level) + 'call sites mismatch!')
				return 2

		for call_site in callees:
			if self.does_func_match(callees[call_site], func_node.callees[call_site], visited, level + 1) != 999:
				print((' '*level) + 'callee ' + func_node.callees[call_site].name + ' mismatch!')
				return 3

		self._cur_match_debug = 'full match'
		self.on_match(func, func_node, level)
		return 999


	def process_func(self, func):
		"""
		Try to sig the given function.
		Return the list of signatures the function matched against
		"""
		func_len = sigkit.compute_sig.get_func_len(func)
		func_data = self.bv.read(func.start, func_len)
		trie_matches = self.sig_trie.find(func_data)
		best_score, results = 0, []
		for candidate_func in trie_matches:
			score = self.does_func_match(func, candidate_func, {})
			if score > best_score:
				results = [candidate_func]
				best_score = score
			elif score == best_score:
				results.append(candidate_func)
		if len(results) == 0:
			print(func.name, '=>', 'no match', end=", ")
			for x in self.sig_trie.all_values():
				if x.name == func.name:
					print('but there was a signature from', x.source_binary)
					break
			else:
				print('but this is OK.')
			assert best_score == 0
			return results
		elif len(results) > 1:
			print(func.name, '=>', 'deferred at level', best_score, results)
			return results

		match = results[0]
		if best_score == 1:
			self._cur_match_debug = 'bytes match (but disambiguation mismatch?)'
			self.on_match(func, match)
			return results
		elif best_score == 2:
			self._cur_match_debug = 'bytes + disambiguation match (but callee count mismatch)'
			self.on_match(func, match)
			return results
		elif best_score == 3:
			self._cur_match_debug = 'bytes + disambiguation match (but callees mismatch)'
			self.on_match(func, match)
			return results
		else:
			self._cur_match_debug = 'full match'
			self.on_match(func, match)
			return results

	def run(self):
		queue = self.bv.functions
		while True: # silly fixedpoint worklist algorithm
			deferred = []
			print('Start of pass %d functions remaining' % (len(queue)))

			for func in queue:
				if func in self._matches:
					continue
				if sigkit.compute_sig.get_func_len(func) < 8:
					continue
				matches = self.process_func(func)
				if len(matches) > 1:
					deferred.append(func)

			print('Pass complete, %d functions deferred' % (len(deferred),))
			if len(queue) == len(deferred):
				print('No changes. Quit.')
				break
			queue = deferred
