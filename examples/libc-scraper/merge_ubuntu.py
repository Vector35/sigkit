#!/usr/bin/env python3

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
This script generates libc signature libraries after precomputing function
signatures using batch_process.py, using all cpus available on the machine.
"""

import os, sys
import gc
import pickle
from pathlib import Path
import tqdm
import asyncio
import concurrent.futures
import math

import sigkit.signaturelibrary
import sigkit.trie_ops
import sigkit.sig_serialize_fb

cpu_factor = int(math.ceil(math.sqrt(os.cpu_count())))

# delete weird, useless funcs and truncate names
def cleanup_info(func_info, maxlen=40):
	import re
	to_delete = set()
	for f in func_info:
		if re.match(r'\.L\d+', f.name):
			to_delete.add(f)
			continue
		f.name = f.name[:maxlen]
	for f in to_delete:
		del func_info[f]

# load all pickles into a single signature library
def load_pkls(pkls):
	# rarely-used libgcc stuff
	pkl_blacklist = {'libcilkrts.pkl', 'libubsan.pkl', 'libitm.pkl', 'libgcov.pkl', 'libmpx.pkl', 'libmpxwrappers.pkl', 'libquadmath.pkl', 'libgomp.pkl'}
	trie, func_info = sigkit.signaturelibrary.new_trie(), {}
	for pkl in pkls:
		if os.path.basename(pkl) in pkl_blacklist: continue
		with open(pkl, 'rb') as f:
			pkl_funcs = pickle.load(f)
			cleanup_info(pkl_funcs)
			sigkit.trie_ops.trie_insert_funcs(trie, pkl_funcs)
			func_info.update(pkl_funcs)
	sigkit.trie_ops.finalize_trie(trie, func_info)
	return trie, func_info

def combine_sig_libs(sig_lib1, sig_lib2):
	sigkit.trie_ops.combine_signature_libraries(*sig_lib1, *sig_lib2)
	return sig_lib1

def finalize_sig_lib(sig_lib):
	sigkit.trie_ops.finalize_trie(*sig_lib)
	return sig_lib

def do_package(package):
	loop = asyncio.get_event_loop()
	pool = concurrent.futures.ProcessPoolExecutor(cpu_factor)

	async def inner():
		print('Processing', package)
		result_filename = os.path.join('sigs', package.replace('/', '-') + '.sig')
		if os.path.exists(result_filename):
			print(result_filename + ' exists')
			return

		pkl_groups = []
		for pkg_version in os.listdir(package):
			pkg_version = os.path.join(package, pkg_version)
			pkls = Path(pkg_version).glob('**/*.pkl')
			pkls = list(map(str, pkls))
			if not pkls: continue
			# print('  ' + pkg_version, len(pkls))
			pkl_groups.append(pkls)
		if not pkl_groups:
			print(package, 'has no versions available')
			return

		with tqdm.tqdm(total=len(pkl_groups), desc='generating tries') as pbar:
			async def async_load(to_load):
				result = await loop.run_in_executor(pool, load_pkls, to_load)
				pbar.update(1)
				pbar.refresh()
				return result
			lib_versions = await asyncio.gather(*map(async_load, pkl_groups))

		# linear merge
		# dst_trie, dst_funcs = sigkit.signaturelibrary.new_trie(), {}
		# for trie, funcs in tqdm.tqdm(lib_versions):
		#     sigkit.trie_ops.combine_signature_libraries(dst_trie, dst_funcs, trie, funcs)

		# big brain parallel async binary merge
		with tqdm.tqdm(total=len(lib_versions)-1, desc='merging') as pbar:
			async def merge(sig_libs):
				assert len(sig_libs)
				if len(sig_libs) == 1:
					return sig_libs[0]
				else:
					half = len(sig_libs) // 2
					sig_lib1, sig_lib2 = await asyncio.gather(merge(sig_libs[:half]), merge(sig_libs[half:]))
					sig_libs[:] = [None] * len(sig_libs) # free memory
					merged_lib = await loop.run_in_executor(pool, combine_sig_libs, sig_lib1, sig_lib2)
					pbar.update(1)
					pbar.refresh()
					gc.collect()
					return merged_lib
			sig_lib = await merge(lib_versions)

		dst_trie, dst_funcs = await loop.run_in_executor(pool, finalize_sig_lib, sig_lib)
		if not dst_funcs:
			print(package, 'has no functions')
			return

		buf = sigkit.sig_serialize_fb.SignatureLibraryWriter().serialize(dst_trie)
		with open(result_filename, 'wb') as f:
			f.write(buf)
		print('  saved to', result_filename, ' | size:', len(buf))

	loop.run_until_complete(inner())

def main():
	if not os.path.exists('sigs'):
		os.mkdir('sigs')
	elif not os.path.isdir('sigs'):
		print('Please delete "sigs" before starting')
		sys.exit(1)

	tasks = []
	distr = 'ubuntu'
	# for version in os.listdir(distr):
	for version in ['bionic']:
		version = os.path.join(distr, version)
		for arch in os.listdir(version):
			arch = os.path.join(version, arch)
			for package in os.listdir(arch):
				package = os.path.join(arch, package)
				tasks.append(package)

	# we are going to do some heirarchical multiprocessing because there is a very high pickle message-passing overhead
	# so a lot of cpu time gets burned pickling in the main process simply passing work to worker processes
	import subprocess
	import multiprocessing.pool
	pool = multiprocessing.pool.ThreadPool(cpu_factor)
	def do_package_in_worker(package):
		subprocess.call(['python3', __file__, '-c', package])
	for _ in pool.imap_unordered(do_package_in_worker, tasks):
		pass

if __name__ == '__main__':
	if len(sys.argv) <= 1:
		main()
	elif len(sys.argv) >= 3 and sys.argv[1] == '-c':
		# child
		do_package(sys.argv[2])
