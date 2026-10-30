/* The linker owns the adaptive copy's end, including erratum/range thunks.
   Isolate the final executable extent on all Linux A64 page sizes. */
SECTIONS
{
  .teapot_transient ALIGN(65536) :
  {
    KEEP(*(.teapot_transient))
    . = ALIGN(65536);
  }
  HIDDEN(.__transient_end__teapot__ = ADDR(.teapot_transient) + SIZEOF(.teapot_transient));
}
INSERT BEFORE .plt;
