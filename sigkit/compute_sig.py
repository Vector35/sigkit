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
This package contains code to compute functions signatures using Binary
Ninja's python API. The most useful function is `process_function`, which
generates a function signature for the specified function.
"""

from binaryninja import *

from . import signaturelibrary
from . import trie_ops

def is_llil_relocatable(llil):
	"""
	Guesses whether a LLIL instruction is likely to contain operands that have been or would be relocated by a linker.
	:param llil: the llil instruction
	:return: true if the LLIL instruction contains LLIL_CONST_PTR or LLIL_EXTERN_PTR.
	"""
	if not isinstance(llil, LowLevelILInstruction):
		return False
	if llil.operation in [LowLevelILOperation.LLIL_CONST_PTR, LowLevelILOperation.LLIL_EXTERN_PTR]:
		return True
	for operand in llil.operands:
		if is_llil_relocatable(operand):
			return True
	return False

def guess_relocations_mask(func, sig_length):
	"""
	Compute the relocations mask on a best-efforts basis using a heuristic based on the LLIL.
	:param func: BinaryNinja api function
	:param sig_length: how long the mask should be
	:return: an array of booleans, signifying whether the byte at each index is significant or not for matching
	"""

	mask = [False] * sig_length
	i = 0
	while i < sig_length:
		bb = func.get_basic_block_at(func.start + i)
		if not bb: # not in a basicblock; wildcard
			mask[i] = False
			i += 1
			continue

		bb._buildStartCache()
		if not bb._instLengths:
			i += 1
			continue
		for insn_len in bb._instLengths:
			# This throws an exception for large functions where you need to manually force analysis
			try:
				llil = func.get_low_level_il_at(func.start + i, bb.arch)
			except exceptions.ILException:
				log_warn(f"Skipping function at {hex(func.start)}. You need to force the analysis of this function.")
				return None

			insn_mask = not is_llil_relocatable(llil)
			# if not insn_mask:
			#     func.set_auto_instr_highlight(func.start + i, HighlightStandardColor.BlueHighlightColor)
			mask[i:min(i + insn_len, sig_length)] = [insn_mask] * min(insn_len, sig_length - i)
			i += insn_len
			if i >= sig_length: break
	return mask

def find_relocation(func, start, end):
	"""
	Finds a relocation from `start` to `end`. If `start`==`end`, then they will be expanded to the closest instruction boundary
	:param func: function start and end are contained in
	:param start: start address
	:param end: end address
	:return: corrected start and end addresses for the relocation
	"""

	if end != start: # relocation isn't stupid
		return start, end - start
	# relocation is stupid (start==end), so just expand to the whole instruction
	bb = func.get_basic_block_at(start)
	if not bb: # not in a basicblock, don't care.
		return None, None
	bb._buildStartCache()
	for i, insn_start in enumerate(bb._instStarts):
		insn_end = insn_start + bb._instLengths[i]
		if (insn_start < end and start < insn_end) or (start == end and insn_start <= start < insn_end):
			return insn_start, bb._instLengths[i]

def relocations_mask(func, sig_length):
	"""
	Compute the relocations mask based on the relocation metadata contained within the binary.
	:param func: BinaryNinja api function
	:param sig_length: how long the mask should be
	:return: an array of booleans, signifying whether the byte at each index is significant or not for matching
	"""

	mask = [True] * sig_length
	for start, end in func.view.relocation_ranges:
		if start > func.start + sig_length or end < func.start: continue
		reloc_start, reloc_len = find_relocation(func, start, end)
		if reloc_start is None: continue # not in a basicblock, don't care.
		reloc_start -= func.start
		if reloc_start < 0:
			reloc_len = reloc_len + reloc_start
			reloc_start = 0
		if reloc_len <= 0: continue
		mask[reloc_start:reloc_start + reloc_len] = [False] * reloc_len

	in_block = [False] * sig_length
	for bb in func.basic_blocks:
		bb_start_offset = bb.start - func.start
		bb_end_offset = bb_start_offset + get_bb_len(bb)
		if bb_start_offset > sig_length or bb.start < func.start: continue
		in_block[bb_start_offset:min(bb_end_offset, sig_length)] = [True] * min(get_bb_len(bb), sig_length - bb_start_offset)

	mask = [a and b for a,b in zip(mask, in_block)]
	return mask

def get_bb_len(bb):
	"""
	Calculate the length of the basicblock, taking into account weird cases like the block ending with an illegal instruction
	:param bb: BinaryNinja api basic block
	:return: length of the basic block in bytes
	"""
	if bb.has_invalid_instructions:
		log.log_warn("Basic block with illegal instructions in " + bb.function.name)
		# stupid ugly HACK to deal with illegal instructions after noreturns that aren't marked noreturn
		bb._buildStartCache()
		if not bb._instLengths: return 0
		return bb._instLengths[-1] + bb._instStarts[-1]
	else:
		return bb.end - bb.start

def get_func_len(func):
	"""
	Calculates the length of the function based on the linear addresses of basic blocks.
	The length is truncated so that it never lies outside of the underlying binaryview.
	:param func: BinaryNinja api function
	:return: the distance to the end of the farthest instruction contained within this function
	"""
	return min(max(map(lambda bb: bb.start + get_bb_len(bb) - func.start, func.basic_blocks)), func.view.end - func.start)

def compute_callees(func):
	"""
	Callees are a map of {offset: dest}, where func+offset is a MLIL_CALL instruction or similar.
	But sometimes, our version has MORE calls than the signature! This is because sometimes libraries
	are optionally linked in, and when they aren't, those calls turn into stubs (e.g., jump 0x0)
	so we make those callees wildcard (when we finalize the trie and resolve references).
	in our matching algorithm, we allow calls to wildcard callee to be optional.
	:param func: BinaryNinja api function
	:return: dictionary of {offset: (destination name, `ReferenceType`)}
	"""
	bv = func.view
	callees = {}
	for ref in func.call_sites:
		callee_addrs = bv.get_callees(ref.address, ref.function, ref.arch)
		if len(callee_addrs) != 1: continue
		sym = bv.get_symbol_at(callee_addrs[0])
		if sym is None: continue
		callees[ref.address - func.start] = (sym.name, sym.type)
	return callees

def function_pattern(func, guess_relocs, sig_length=None):
	"""
	Computes a data and mask for the specified function `func` that can be used to identify this function.
	For example, a function may look like:

	0: 53             push rbx
	1: 83 77 05       lea esi, [rdi+5]
	4: bf a0 07 40 00 mov edi,0x4007a0
	9: 31 c0          xor    eax,eax

	In this case, because they constitute a pointer, bytes 5-8 are liable to change when this binary is recompiled or linked.
	Thus, we would like to wildcard those bytes out and ignore them while matching.
	An appropriate function pattern may look like: 53 83 77 05 bf ?? ?? ?? ?? 31 c0
	The pattern data is a the sequence of bytes in the pattern and the mask is an array which specifies which bytes are not wildcards.
	For example, the data would be b'\x55\x83\x77\x05\xbf\x00\x00\x00\x00\x31\xc0' and the mask would be [1,1,1,1,1,0,0,0,0,1,1].

	This function is responsible for computing that data and that mask based on the information available in the binaryview.

	:param func: BinaryNinja api function
	:param guess_relocs: if False, assume relocation information is available for calculating the mask. otherwise,
	guess the relocation mask based on the IL.
	:param sig_length: the maximum length of the signature. If None, try to calculate it based on basic block addresses.
	:return: list of MaskedByte
	"""

	if sig_length is None:
		sig_length = min(get_func_len(func), 1000)

	if guess_relocs:
		mask = guess_relocations_mask(func, sig_length)
	else:
		mask = relocations_mask(func, sig_length)
	if not mask:
		return None
	mask = list(map(int, mask)) # bool to int
	data = b''
	i = 0
	while i < len(mask) and func.start + i < func.view.end:
		if mask[i]:
			next_byte = func.view.read(func.start + i, 1)
			if len(next_byte) != 1: break # end of bv
			data += next_byte
		else:
			data += b'\x00'
		i += 1
	if len(data) < len(mask):
		mask = mask[:len(data)]
	assert len(data) == len(mask)
	while len(mask) and not mask[-1]:
		data = data[:len(data) - 1]
		mask = mask[:len(mask) - 1]
	return signaturelibrary.Pattern(data,mask)

def process_function(func, guess_relocs):
	"""
	Generates a signature for a given function.
	This signature can be thought of as a semi-unique fingerprint that is able to match copies of this function
	found in other binaries.

	:param func: BinaryNinja api function
	:param guess_relocs: if False, assume relocation information is available for calculating the mask. otherwise,
	guess the relocation mask based on the IL.
	:return: tuple of (FunctionNode, FunctionInfo)
	"""

	func_node = signaturelibrary.FunctionNode(func.name)
	func_node.source_binary = func.view.file.filename

	info = signaturelibrary.FunctionInfo()
	function_pattern_val = function_pattern(func, guess_relocs)
	if not function_pattern_val:
		return None, None
	info.patterns = [function_pattern_val]
	info.callees = compute_callees(func)
	if hasattr(func.symbol, 'aliases'):
		info.aliases = list(map(lambda s: s.decode('utf-8'), func.symbol.aliases))
	else:
		info.aliases = []
	return func_node, info
