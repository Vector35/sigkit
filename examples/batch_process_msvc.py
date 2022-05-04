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
This script processes many object files using headless mode and generate
function signatures for functions in them in a highly parallelized fashion.
The result is a dictionary of {FunctionNode: FunctionInfo} that is then pickled
and saved to disk. These pickles can be processed with a merging script, i.e.
merge_multiple_versions.py or libc-scraper's merge_ubuntu.py.
"""

import time

from binaryninja import *

import sigkit

def process_bv(bv):
    global results
    # print(bv.file.filename, ': processing')
    guess_relocs = len(bv.relocation_ranges) == 0

    for func in bv.functions:
        try:
            if bv.get_symbol_at(func.start) is None: continue
            node, info = sigkit.generate_function_signature(func, guess_relocs)
            results.put((node, info, bv.platform.name))
            # print("Processed", func.name)
        except:
            import traceback
            traceback.print_exc()
    # print(bv.file.filename, ': done')

def on_analysis_complete(self):
    global wg
    process_bv(self.view)
    with wg.get_lock():
        wg.value -= 1
    self.view.file.close()

def process_binary(info):
    global wg
    input_binary, i, total = info
    input_binary = str(input_binary)
    log_to_stdout(LogLevel.AlertLog)
    log_to_stderr(LogLevel.AlertLog)

    bv = binaryninja.BinaryViewType["Raw"].open(input_binary)
    coff = binaryninja.BinaryViewType["COFF"]
    if not coff.is_valid_for_data(bv):
        return
    print(f"{i/total:.2}% - {i}/{total} - {input_binary}")
    bv = coff.open(input_binary)
    if not bv:
        print('Failed to load', input_binary)
        return
    AnalysisCompletionEvent(bv, on_analysis_complete)
    bv.update_analysis()
    with wg.get_lock():
        wg.value += 1

def async_process(input_queue):
    for input_binary in input_queue:
        process_binary(input_binary)
        yield

def init_child(wg_, results_):
    global wg, results
    wg, results = wg_, results_

def get_paths():
    for path in enumerate():
        p = str(path)
        if not p.endswith(".obj"):
            continue
        yield p

if __name__ == '__main__':
    import sys
    from pathlib import Path
    if len(sys.argv) < 2:
        print('Usage: %s <output func info pickle>' % (sys.argv[0]))
        print('The pickle designates the filename of a pickle file that the computed function metadata will be saved to.')
        sys.exit(1)

    import multiprocessing as mp
    wg = mp.Value('i', 0)
    results = mp.Queue()
    from collections import defaultdict
    func_info = defaultdict(dict)
    with mp.Pool(mp.cpu_count(), initializer=init_child, initargs=(wg, results)) as pool:
        print("Collecting paths...")
        paths = []
        path_list = list(Path.rglob(Path("libs"), "*.obj"))
        total = len(path_list)
        for i, path in enumerate(path_list):
            paths.append((path, i, total))
        pool.map(process_binary, paths)

        while True:
            time.sleep(0.1)
            with wg.get_lock():
                if wg.value == 0: break

        while not results.empty():
            node, info, platform = results.get()
            func_info[platform][node] = info

    import pickle
    for platform in func_info.keys():
        with open(f"msvcrt_{platform}.pkl", 'wb') as f:
            pickle.dump(func_info, f)
