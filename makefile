# Heavily inspired by https://github.com/rootkovska/state_harmful/blob/master/Makefile

# If a need to change the font to Times arisises, add this line to the `wmi.sty` file:
# \usepackage{times}

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

ifdef filenames
else
	filenames := 0-abstrakt.md 1-wstep.md 2-cel-i-zakres.md 3-nomenklatura.md 4-bezpieczenstwo.md
endif

ifdef result_filename
else
	result_filename := sealious-cz-2-jan-orlik
endif

ifdef paper_mode
	result_filename := $(result_filename).paper
	code_color_scheme := monochrome
	paper_mode_var := true
else
	result_filename := $(result_filename).digital
	code_color_scheme := pygments
	paper_mode_var := ""
endif


all: $(result_filename).$(format)
	make $(result_filename).$(format)

# export LC_ALL=pl_PL && 
# export LANG=pl_PL.UTF-8 && 
# export LANGUAGE=pl_PL && 

$(result_filename).$(format): references.json citation-style.xml wmi.sty makefile template_wmi/template.latex $(filenames)
	cat $(filenames) > concatenated.temp
	./twarde-spacje.sh concatenated.temp $(result_filename).temp	
	pandoc $(result_filename).temp \
		--csl=citation-style.xml \
		-H wmi.sty \
		-V geometry:"inner=3cm, outer=2cm, top=2.5cm, bottom=2.5cm" \
		--latex-engine=xelatex \
		--standalone \
		--smart \
		--toc-depth=2 \
		--template=template_wmi/template.latex \
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
		-V paper_mode=$(paper_mode_var) \
		--highlight-style $(code_color_scheme) \
		-V author_numer_albumu=$(author_numer_albumu) \
		-V type=$(type) \
		-o $(result_filename).$(format) && \
	xdg-open $(result_filename).$(format)

clean:
	rm -f $(result_filename).temp $(result_filename).pdf $(result_filename).odt $(result_filename).html $(result_filename).docx concatenated.temp