# Makefile
# Take man file source in .md and create various versions
# of the files
# requires pandoc to run

# you shouldn't have to use shell to make these targets
HTML := $(shell ls *.md | sed -e 's,^,manhtml/,g' -e 's/\.md/.html/g' -e '/man-template/d')
MAN1 := $(shell ls *.1.md | sed -e 's,^,man/man1/,g' -e 's/.md//g')
MAN5 := $(shell ls *.5.md | sed -e 's,^,man/man5/,g' -e 's/\.md//g')
CSS  := manhtml/pandoc.css manhtml/nftfw.css

all: $(HTML) $(MAN1) $(MAN5) $(CSS)

%.man : %.md
	pandoc --standalone --to man $< -o $@

man/man1/%.1: %.1.md
	pandoc --standalone --to man $< -o $@

man/man5/%.5: %.5.md
	pandoc --standalone --to man $< -o $@

%.txt : %.man
	groff -Tutf8 -man $< > $@

manhtml/%.css: %.css
	cp $< $@

manhtml/%.html : %.md
	pandoc --standalone --wrap=auto --to html5 --css pandoc.css --css nftfw.css $< -o $@

manhtml/index.html: index.md
	sed -e 's/md)/html)/' $< | pandoc --standalone --to html5 --css pandoc.css --css nftfw.css -o $@

clean:
	rm -f *.man *.html manhtml/* man/man1/* man/man5/*
