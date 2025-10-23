#!/bin/sh

cp /home/oof/new_pdf_mutator/mutator.py .
cp /home/oof/new_pdf_mutator/resources.pkl .

LIBFUZZER_PYTHON_MODULE=mutator PYTHONPATH=. ./pdfium_fuzzer -dict=pdfium_fuzzer.dict -timeout=3 ./pdf_corpus/


