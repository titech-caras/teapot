import capstone

# Teapot's analyses are written against Capstone 6's instruction details (see teapot.arch.decoders).
if capstone.CS_API_MAJOR < 6:
    raise ImportError(f"Teapot requires Capstone 6.0.0-Alpha11 (capstone==6.0.0a11), found {capstone.__version__}")
