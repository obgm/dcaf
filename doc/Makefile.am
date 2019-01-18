# doc/Makefile.am
#
# Copyright (C) 2019 Olaf Bergmann <bergmann@tzi.org>
#
# This file is part of the library dcaf. Please see README and
# COPYING for terms of use.

# We can only perfom the targets in this directory if doxygen is present.

if BUILD_DOCUMENTATION

CLEANFILES = \
  doxygen_sqlite3.db

# This target has no check for automated install data! It's simply assumed that
# that the 'all' target is running before, in short: the user has to run first
# 'make' before running 'make install'!
install-data-am:
	@if [ ! -d $(top_builddir)/doc/html ]; then \
		echo ;\
		echo "     No install data in '$(top_builddir)/doc/html'found! Please run 'make all' first." ;\
		echo ;\
		exit 1 ;\
	fi
	$(MKDIR_P) $(DESTDIR)$(htmldir)/html || exit 1
	cp -a -f $(top_builddir)/doc/html $(DESTDIR)$(htmldir)
	find $(DESTDIR)$(htmldir) -type f -name "*.md5" -delete

uninstall-am:
	-$(RM) -rf $(DESTDIR)$(htmldir)/html

all: Doxyfile layout.xml
	$(DOXYGEN) $<

layout.xml:
	$(DOXYGEN) -l $@

distclean-local:
	-$(RM) -rf $(top_builddir)/doc/html $(top_builddir)/doc/layout.xml

endif
