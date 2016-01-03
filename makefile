# Heavily inspired by https://github.com/rootkovska/state_harmful/blob/master/Makefile

# If a need to change the font to Times arisises, add this line to the `wmi.sty` file:
# \usepackage{times}

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

# export LC_ALL=pl_PL && 
# export LANG=pl_PL.UTF-8 && 
# export LANGUAGE=pl_PL && 
$(filename).$(format): references.json $(filename).temp.md citation-style.xml wmi.sty
	pandoc $(filename).temp.md \
		--csl=citation-style.xml \
		-H wmi.sty \
		-V geometry:"inner=3cm, outer=2cm, top=2.5cm, bottom=2.5cm" \
		--standalone \
		--smart \
		-V documentclass=report \
		-f markdown+footnotes+backtick_code_blocks+inline_notes+raw_html \
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