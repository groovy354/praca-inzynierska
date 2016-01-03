# Heavily inspired by https://github.com/rootkovska/state_harmful/blob/master/Makefile

filename := praca-inzynierska
title := "Odniesienie się do kwestii bezpieczeństwa i zależności pomiędzy dokumentami w Sealiousie"

ifdef format
else
	format=pdf
endif

all: $(filename).$(format)
	make $(filename).$(format)

$(filename).$(format): $(filename).md references.json
	pandoc $(filename).md \
		--standalone \
		--smart \
		-V documentclass=report \
		-f markdown+footnotes+backtick_code_blocks+inline_notes \
		--toc \
		--bibliography references.json \
		-V papersize=a4paper \
		-V fontsize=12pt \
		-V lang=pl-PL \
		-V filename=kupa \
		-o $(filename).$(format) && \
	xdg-open $(filename).$(format)

clean:
	rm -f $(filename).pdf $(filename).odt $(filename).html $(filename).docx