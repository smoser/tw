PROJECT = tw
MELANGE_CONTEXTDIR ?= /tmp/melange-context/$(PROJECT)
MELANGE_INSTALL_PATH = $(MELANGE_CONTEXTDIR)/usr

.PHONY: build melange-install

build:
	mkdir -p bin
	go test -c -o bin/tw
	$(eval MULTICALLS := $(shell bin/tw list-multicalls))
	$(foreach cmd,$(MULTICALLS),\
		ln -sf tw bin/$(cmd) && echo "Created symlink for $(cmd)";\
	)

melange-install: build
	echo $@
	mkdir -p $(MELANGE_INSTALL_PATH)
	cp -r bin $(MELANGE_INSTALL_PATH)
