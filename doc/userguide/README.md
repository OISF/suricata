# Suricata User Guide

This directory contains the Suricata Guide. The
[Sphinx Document Generate](http://sphinx-doc.org) is used to build the
documentation. For a primer os reStructuredText see the
[reStructuredText Primer](http://sphinx-doc.org/rest.html).

## Development Server

To help with writing documentation there is a development web server
with live reload. To get run the live server you will first need `npm`
and `sphinx-build` installed then run the following:

`npm install gulp gulp-shell gulp-webserver gulp-cli`
        
Create a gulpfile.js file:

```
var gulp = require('gulp')
var shell = require('gulp-shell')
var serve = require('gulp-webserver')

gulp.task('build-docs', shell.task('make --file Makefile.sphinx html', {cwd: 'pathtouserguidedirectory'}))

gulp.task('docs', ['build-docs'], function() {
gulp.watch(['pathtouserguidedirectory/*.rst'], ['build-docs'])
gulp.watch(['pathtouserguidedirectory/rules/*.rst'], ['build-docs'])
})

gulp.task('serve', function() {
  gulp.src('pathtouserguidedirectory')
    .pipe(serve({
      livereload: true,
      open: true,
      directoryListing: {
          enable:true,
          path: 'pathtouserguidedirectory'
      }
    }));
});

gulp.task('default', ['build-docs', 'docs', 'serve']);
```

- Run `gulp` from the directory where the gulpfile.js was created
- In a browser navigate to http://localhost:8000/_build

Any edits to .rst files should trigger a "make html" and cause your
browser to refresh.
