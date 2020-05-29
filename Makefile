
PLUGIN=inject.so
SOURCES=\
        inject.cc \
		rules.cc \
		$(END)

INSTALLDIR=/usr

CC=$(INSTALLDIR)/bin/gcc
CXX=$(INSTALLDIR)/bin/g++
PLUGINDIR=$(shell $(CC) -print-file-name=plugin)

CXXFLAGS=-std=gnu++11 -fPIC -Wall -g -fno-rtti -I$(PLUGINDIR)/include 
# This is a side effect of using C++11
CXXFLAGS+=-Wno-literal-suffix

CFLAGS=-c -I/usr/include/libiberty/ 

LDFLAGS=
LDADD=

END=
OBJECTS=$(patsubst %.cc,%.o,$(SOURCES))

all: $(PLUGIN)

$(PLUGIN): $(OBJECTS)
	$(CXX) $(LDFLAGS) -o $@ -shared $+ $(LDADD) -liberty -lyaml


%.o: %.cc
	$(CXX) -c -o $@ $(CXXFLAGS) $<



PLUGINFLAG=-fplugin=./$(PLUGIN)

CCPLUGIN=$(CC) $(PLUGINFLAG)
CXXPLUGIN=$(CXX)  $(PLUGINFLAG)

.PHONY: all clean test asm
clean:
	rm -f $(OBJECTS) $(PLUGIN)


.PHONY: test
test: $(PLUGIN)
	$(CCPLUGIN) -fplugin-arg-inject-rules=rules.yml -fdump-tree-gimple-raw -lpthread -lyaml -O2 test_plugin.c -g -o test_plugin


.PHONY: asm
asm: $(PLUGIN)
	$(CCPLUGIN) -fplugin-arg-inject-rules=rules.yml -lpthread -lyaml -O2 test_plugin.c -g -v -S -o test_plugin.s
