var gulp = require("gulp");
var watch = require("gulp-watch");
var spawn = require("child_process").spawn;
var server = require("gulp-webserver")

gulp.task("watch", function(cb) {
    watch(["*.rst", "*/*.rst"], function() {
	console.log("Changed.");
	spawn("make", ["-f", "Makefile.sphinx", "html"], {
	    stdio: "inherit",
	    stderr: "inherit"
	});
    });
});

gulp.task("server", function(cb) {
    gulp.src(".")
	.pipe(server({
	    livereload: {
		enable: true,
		filter: function(filename) {
		    if (filename.match(/^_build/)) {
			return true;
		    }
		    return false;
		}
	    },
	    directoryListing: true
	}));
});

gulp.task("serve", ["watch", "server"])
