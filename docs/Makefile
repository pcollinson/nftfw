# Makefile
# Take file source in .md and make html files
# Take file source and make .pdf files using groff
# requires pandoc, groff and iconv to run

HTML = html/How_do_I.html  html/Users_Guide.html html/Installing-GeoLocation.html html/Updating-nftfw.html html/Getting-cidr-lists.html html/index.html html/README.html html/Debian_package_install.html html/Using-fail2ban-with-nftfw.html
PDF = pdf/How_do_I.pdf  pdf/Users_Guide.pdf pdf/Installing-GeoLocation.pdf pdf/Updating-nftfw.pdf pdf/Getting-cidr-lists.pdf pdf/index.pdf pdf/README.pdf pdf/Debian_package_install.pdf pdf/Using-fail2ban-with-nftfw.pdf

.PHONY: make makeclean

all: $(HTML) $(PDF) make

# change .md links to .html, remove any #links which don't work on files
html/%.html : %.md
	sed -e 's/md)/html)/' -e 's/md#[^)]*)/html)/' $< | pandoc --standalone --wrap=auto --to html5 --css pandoc.css --css nftfw-doc.css -o $@

pdf/%.pdf: %.md
	sed -e 's/md)/pdf)/' -e 's/md#[^)]*)/pdf)/' $< | pandoc --standalone --to ms -V fontfamily=H -V indent=0  | iconv -f UTF-8 -t ISO-8859-1//TRANSLIT | groff -dpaper=a4 -Tpdf -ms > $@ 2> /dev/null

make:
	$(MAKE) -C man

clean: makeclean
	rm $(HTML)

makeclean:
	$(MAKE) -C man clean
