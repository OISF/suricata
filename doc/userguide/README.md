# Suricata User Guide

This directory contains the Suricata Guide. The
[Sphinx Document Generate](http://sphinx-doc.org) is used to build the
documentation. For a primer os reStructuredText see the
[reStructuredText Primer](http://sphinx-doc.org/rest.html).

## Verifying Changes

There are a number of output formats to choose from when making the source documentation locally (e.g. html, pdf, man).

The documentation source can be built with `make -f Makefile.sphinx html`. Substitute the 'html' word for desired output format.

There are different application dependencies based on the output desired.
