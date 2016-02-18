# Suricata User Guide

This directory contains the Suricata Guide. The
[Sphinx Document Generate](http://sphinx-doc.org) is used to build the
documentation. For a primer os reStructuredText see the
[reStructuredText Primer](http://sphinx-doc.org/rest.html).

## Development Server

To help with writing documentation there is a development web server
with live reload. To get run the live server you will first need npm
installed then run the following:

	npm install
	gulp serve

Then point your browser at http://localhost:8000/_build/html/index.html

Any edits to .rst files should trigger a "make html" and cause your
browser to refresh.
