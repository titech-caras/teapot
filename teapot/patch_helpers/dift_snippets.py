from gtirb_rewriting import Register

from teapot.utils.dift import reg_to_dift_reg_id


def dift_add_reg_tag_snippet(tag_reg: Register, *, reg_add: Register):
    return f"or {tag_reg:8l}, dift_reg_tags+{reg_to_dift_reg_id(reg_add)}\n"
