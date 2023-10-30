plugindir = ${libdir}/suricata/plugins

if BUILD_SHARED_LIBRARY
plugin_LTLIBRARIES = json-filetype.la
json_filetype_la_LDFLAGS = -module -shared
json_filetype_la_SOURCES = filetype.c

json_filetype_la_CPPFLAGS = -I$(abs_top_srcdir)/rust/gen -I$(abs_top_srcdir)/rust/dist

else

all-local:
	@echo
	@echo "Shared library support must be enabled to build plugins."
	@echo

endif
