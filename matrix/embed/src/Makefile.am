## Process this file with automake to produce Makefile.in

## Created by Anjuta

AM_CPPFLAGS = \
	$(WX_CXXFLAGS) \
	-DPACKAGE_LOCALE_DIR=\""$(localedir)"\" \
	-DPACKAGE_SRC_DIR=\""$(srcdir)"\" \
	-DPACKAGE_DATA_DIR=\""$(pkgdatadir)"\"

AM_CFLAGS =\
	 -Wall \
	 -g \
	 $(WX_CPPFLAGS)

bin_PROGRAMS = embed

embed_SOURCES = \
	main.cc \
	embed

embed_LDFLAGS = 

embed_LDADD = \
	 \
	$(WX_LIBS)

