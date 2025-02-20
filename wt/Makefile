PROJECT = wt
MELANGE_CONTEXTDIR ?= /tmp/melange-context/$(PROJECT)
MELANGE_INSTALL_PATH = $(MELANGE_CONTEXTDIR)/usr

.PHONY: build melange-install

build:
	mkdir -p bin
	go test -c -o bin/wt
	$(eval MULTICALLS := $(shell bin/wt list-multicalls))
	$(foreach cmd,$(MULTICALLS),\
		ln -sf wt bin/$(cmd) && echo "Created symlink for $(cmd)";\
	)

melange-install: build
	echo $@
	mkdir -p $(MELANGE_INSTALL_PATH)
	cp -r bin $(MELANGE_INSTALL_PATH)
