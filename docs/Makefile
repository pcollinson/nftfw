# Makefile
# Take file source in .md and make html files
# Take file source and make .pdf files using groff
# requires pandoc, groff and iconv to run

HTML = html/How_do_I.html  html/Installation.html  html/Users_Guide.html html/Installing-GeoLocation.html html/Updating-nftfw.html html/Installation-Instructions.html html/Getting-cidr-lists.html html/index.html html/README.html
PDF = pdf/How_do_I.pdf  pdf/Installation.pdf  pdf/Users_Guide.pdf pdf/Installing-GeoLocation.pdf pdf/Updating-nftfw.pdf pdf/Installation-Instructions.pdf pdf/Getting-cidr-lists.pdf pdf/index.pdf pdf/README.pdf

.PHONY: make makeclean

all: $(HTML) $(PDF) make

html/%.html : %.md
	sed -e 's/md)/html)/' $< | pandoc --standalone --to html5 --css pandoc.css --css nftfw-doc.css -o $@

pdf/%.pdf: %.md
	sed -e 's/md)/pdf)/' $< | pandoc --standalone --to ms -V fontfamily=H -V indent=0  | iconv -f utf8 -t ISO-8859-1//TRANSLIT | groff -dpaper=a4 -Tpdf -ms > $@ 2> /dev/null

make:
	$(MAKE) -C man

clean: makeclean
	rm $(HTML)

makeclean:
	$(MAKE) -C man clean
