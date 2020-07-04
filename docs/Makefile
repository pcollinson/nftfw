# Makefile
# Take ile source in .md and make html files
# requires pandoc to run
HTML = html/How_do_I.html  html/Installation.html  html/Users_Guide.html html/Installing-GeoLocation.html html/Updating-nftfw.html html/Installation-Instructions.html html/Getting-cidr-lists.html

.PHONY: make makeclean

all: $(HTML) make

html/%.html : %.md
	pandoc --standalone --to html5 --css pandoc.css --css nftfw-doc.css $< -o $@

make:
	$(MAKE) -C man

clean: makeclean
	rm $(HTML)

makeclean:
	$(MAKE) -C man clean
