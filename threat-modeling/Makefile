demo:
	cd pytm && mkdir -p sample	
	cd pytm && python3 ./tm.py --dfd | dot -Tpng -o ../sample/dfd.png
	cd pytm && python3 ./tm.py --seq | java -Djava.awt.headless=true -jar ../plantuml.jar -tpng -pipe > sample/seq.png
	cd pytm && python3 ./tm.py --report ../docs/template.md | pandoc -f markdown -t html > ../sample/report.html 2>/dev/null
	cd pytm && open sample/report.html

h1:
	mkdir -p h1_model
	python ./h1_model_tm.py --dfd | dot -Tpng -o h1_model/dfd.png
	python ./h1_model_tm.py --seq | java -Djava.awt.headless=true -jar plantuml.jar -tpng -pipe > h1_model/seq.png
	python ./h1_model_tm.py --report docs/template.md | pandoc -f markdown -t html > h1_model/report.html
	open h1_model/report.html
h2:
	mkdir -p h2_model
	python ./h2_model_tm.py --dfd | dot -Tpng -o h2_model/dfd.png
	python ./h2_model_tm.py --seq | java -Djava.awt.headless=true -jar plantuml.jar -tpng -pipe > h2_model/seq.png
	python ./h2_model_tm.py --report docs/template.md | pandoc -f markdown -t html > h2_model/report.html
	open h2_model/report.html
h3:
	mkdir -p h3_model
	python ./h3_model_tm.py --dfd | dot -Tpng -o h3_model/dfd.png
	python ./h3_model_tm.py --seq | java -Djava.awt.headless=true -jar plantuml.jar -tpng -pipe > h3_model/seq.png
	python ./h3_model_tm.py --report docs/template.md | pandoc -f markdown -t html > h3_model/report.html
	open h3_model/report.html

stride:
	python

default: h1 h2 h3