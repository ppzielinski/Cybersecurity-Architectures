# Define the ports and file locations
PORT = 8000
OUTPUT_PDF = combined.pdf

# List of HTML files in the current directory
HTML_FILES = $(wildcard *.html)

# Start a Python HTTP server to serve HTML files
start_server:
	@echo "Starting Python HTTP server on port $(PORT)..."
	python -m http.server $(PORT) &

# Generate PDF from each HTML file using DeckTape
generate_pdfs: $(HTML_FILES)
	@echo "Generating PDFs..."
	@for file in $(HTML_FILES); do \
		echo "Generating PDF for $$file..."; \
		decktape reveal --size 1600x1200 http://localhost:$(PORT)/$$file $$file.pdf; \
	done

# Merge all generated PDFs into one combined PDF
merge_pdfs: generate_pdfs
	@echo "Merging PDFs into $(OUTPUT_PDF)..."
	pdftk $(wildcard *.pdf) cat output $(OUTPUT_PDF)

# Clean up any temporary PDF files generated
clean:
	@echo "Cleaning up..."
	rm -f *.pdf

# Default target: start server, generate PDFs, merge them, and clean up
all: start_server generate_pdfs merge_pdfs clean
