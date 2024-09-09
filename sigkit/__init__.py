from binaryninja import *

# exports
from . import trie_ops
from . import sig_serialize_fb
from . import sig_serialize_json

from .signaturelibrary import TrieNode, FunctionNode, Pattern, MaskedByte, new_trie
from .compute_sig import process_function as generate_function_signature

if core_ui_enabled():
	from .sigexplorer import explore_signature_library
	import binaryninjaui

	def signature_explorer(prompt=True):
		"""
		Open the signature explorer UI.
		:param prompt: if True, prompt the user to open a file immediately.
		:return: `App`, a QT window
		"""
		if "qt_major_version" in binaryninjaui.__dict__ and binaryninjaui.qt_major_version == 6:
			from PySide6.QtWidgets import QApplication
		else:
			from PySide2.QtWidgets import QApplication
		app = QApplication.instance()
		global widget # avoid lifetime issues from it falling out of scope
		widget = sigexplorer.App()
		if prompt:
			widget.open_file()
		widget.show()
		if app: # VERY IMPORTANT to avoiding lifetime issues???
			app.exec_()
		return widget


	# UI plugin code
	def _generate_signature_library(bv):
		guess_relocs = len(bv.relocation_ranges) == 0
		if guess_relocs:
			log.log_debug('Relocation information unavailable; choosing pattern masks heuristically')
		else:
			log.log_debug('Generating pattern masks based on relocation ranges')

		func_count = sum(map(lambda func: int(bool(bv.get_symbol_at(func.start))), bv.functions))
		log.log_info('Generating signatures for %d functions' % (func_count,))
		# Warning for usability purposes. Someone will be confused why it's skipping auto-named functions
		if func_count / float(len(bv.functions)) < 0.5:
			num_skipped = len(bv.functions) - func_count
			log.log_warn("%d functions that don't have a name or symbol will be skipped" % (num_skipped,))

		funcs = {}
		for func in bv.functions:
			if bv.get_symbol_at(func.start) is None: continue
			func_node, info = generate_function_signature(func, guess_relocs)
			funcs[func_node] = info
			log.log_debug('Processed ' + func.name)

		log.log_debug('Constructing signature trie')
		trie = signaturelibrary.new_trie()
		trie_ops.trie_insert_funcs(trie, funcs)
		log.log_debug('Finalizing trie')
		trie_ops.finalize_trie(trie, funcs)


		if 'SIGNATURE_FILE_NAME' in bv.session_data:
			output_filename = bv.session_data['SIGNATURE_FILE_NAME']
		else:
			output_filename = get_save_filename_input("Filename:", "*.sig", bv.file.filename + '.sig')
			if not output_filename:
				log.log_debug('Save cancelled')
				return
		if isinstance(output_filename, bytes):
			output_filename = output_filename.decode('utf-8')
		buf = sig_serialize_fb.SignatureLibraryWriter().serialize(trie)
		with open(output_filename, 'wb') as f:
			f.write(buf)
		log.log_info('Saved to ' + output_filename)

	PluginCommand.register(
		"Signature Library\\Generate Signature Library",
		"Create a Signature Library that the Signature Matcher can use to locate functions.",
		_generate_signature_library
	)

	PluginCommand.register(
		"Signature Library\\Explore Signature Library",
		"View a Signature Library's contents in a graphical interface.",
		lambda bv: signature_explorer()
	)
