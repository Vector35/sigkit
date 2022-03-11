import flatbuffers

if hasattr(flatbuffers, "__version__"):
    saved_EndVector = flatbuffers.Builder.EndVector
    flatbuffers.Builder.EndVector = lambda self, *args: saved_EndVector(self)