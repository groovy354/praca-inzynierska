# Heavily inspired by https://github.com/rootkovska/state_harmful/blob/master/Makefile

filename := praca-inzynierska
title := "Odniesienie się do kwestii bezpieczeństwa i zależności pomiędzy dokumentami w Sealiousie"

ifdef format
else
	format=pdf
endif

all: $(filename).$(format)
	make $(filename).$(format)

$(filename).temp.md: $(filename).md
	./twarde-spacje.sh $(filename).md $(filename).temp.md

$(filename).$(format): references.json $(filename).temp.md
	pandoc $(filename).temp.md \
		--standalone \
		--smart \
		-V documentclass=report \
		-f markdown+footnotes+backtick_code_blocks+inline_notes \
		--toc \
		--bibliography references.json \
		-V papersize=a4paper \
		-V fontsize=12pt \
		-V lang=pl-PL \
		-V title=$(title) \
		-o $(filename).$(format) && \
	xdg-open $(filename).$(format)

clean:
	rm -f $(filename).temp.md $(filename).pdf $(filename).odt $(filename).html $(filename).docx 