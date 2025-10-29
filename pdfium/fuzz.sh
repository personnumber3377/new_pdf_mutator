#!/bin/sh

cp /home/oof/new_pdf_mutator/pdfium/newmutator.py ./mutator.py
cp /home/oof/new_pdf_mutator/pdfium/*.py .
cp /home/oof/new_pdf_mutator/resources.pkl .
export ASAN_OPTIONS=alloc_dealloc_mismatch=0:allocator_may_return_null=1:halt_on_error=0
# pdf_corpus
ASAN_OPTIONS=alloc_dealloc_mismatch=0:allocator_may_return_null=1:halt_on_error=1:abort_on_error=1 LIBFUZZER_PYTHON_MODULE=daemon PYTHONPATH=. ./pdfium_fuzzer -fork=1 -ignore_crashes=1 -dict=pdfium_fuzzer.dict -timeout=10 -rss_limit_mb=0 ./pdf_corpus/


