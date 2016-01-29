# Heavily inspired by https://github.com/rootkovska/state_harmful/blob/master/Makefile

# If a need to change the font to Times arisises, add this line to the `wmi.sty` file:
# \usepackage{times}

filenames := 0-wstep.md 1-cel-i-zakres.md 2-nomenklatura.md 3-bezpieczenstwo.md
result_filename := sealious-cz-2-jan-orlik
title := "Rozwój open-source’owego frameworka do tworzenia aplikacji - \"Sealious\"\ (cz.\ 2)"
title_eng := "Extending capabilities of Sealious - an open-source application-development framework (part 2)"
year := "2016"
promotor := "prof. Marek Nawrocki"
type := "Praca inżynierska"
author := "Jan Orlik"
# author_is_female := true
author_numer_albumu := "384018"

ifdef format
else
	format=pdf
endif

all: $(result_filename).$(format)
	make $(result_filename).$(format)

concatenated.temp: $(filenames)
	cat $(filenames) > concatenated.temp

$(result_filename).temp: concatenated.temp
	./twarde-spacje.sh concatenated.temp $(result_filename).temp

# export LC_ALL=pl_PL && 
# export LANG=pl_PL.UTF-8 && 
# export LANGUAGE=pl_PL && 
# --highlight-style monochrome \
$(result_filename).$(format): references.json concatenated.temp citation-style.xml wmi.sty makefile template_wmi/template.latex
	pandoc concatenated.temp \
		--csl=citation-style.xml \
		-H wmi.sty \
		-V geometry:"inner=3cm, outer=2cm, top=2.5cm, bottom=2.5cm" \
		--latex-engine=xelatex \
		--standalone \
		--smart \
		--toc-depth=2 \
		--template=template_wmi/template \
		-V documentclass=report \
		-f markdown+footnotes+backtick_code_blocks+inline_notes+raw_html \
		--toc \
		--bibliography references.json \
		-V papersize=a4paper \
		-V fontsize=12pt \
		-V lang=pl-PL \
		--metadata lang=pl-PL \
		-V title=$(title) \
		-V title_eng=$(title_eng) \
		-V author=$(author) \
		-V year=$(year) \
		-V promotor=$(promotor) \
		-V author_is_female=$(author_is_female) \
		-V author_numer_albumu=$(author_numer_albumu) \
		-V type=$(type) \
		-o $(result_filename).$(format) && \
	xdg-open $(result_filename).$(format)

clean:
	rm -f $(result_filename).temp $(result_filename).pdf $(result_filename).odt $(result_filename).html $(result_filename).docx concatenated.temp