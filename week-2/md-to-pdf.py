import os
import re
import subprocess
import shlex

# Paths
input_md = 'Net-Sec-Arch.md'
output_md = 'output.md'
output_img_dir = 'diagrams'
output_pdf = 'Net-Sec-Arch.pdf'

# Ensure diagram output directory exists
os.makedirs(output_img_dir, exist_ok=True)

# Load Markdown
try:
    with open(input_md, 'r', encoding='utf-8') as f:
        content = f.read()
    print(f"Loaded Markdown from {input_md}")
except FileNotFoundError:
    print(f"ERROR: Input file not found at '{input_md}'")
    exit(1)
except Exception as e:
    print(f"ERROR: Failed to read input file '{input_md}': {e}")
    exit(1)

# Add CSS for black text in Mermaid diagrams
css_content = """
<style>
text, .label text, .node text, .edgeLabel text, .cluster-label text, .edgeLabel span p {
    fill: #000000 !important;
    color: #000000 !important;
    stroke: none !important;
}
</style>
"""

css_path = os.path.join(output_img_dir, 'mermaid_blacktext.css')
try:
    with open(css_path, 'w', encoding='utf-8') as f:
        f.write(css_content)
    print(f"Created CSS file at {css_path}")
except Exception as e:
    print(f"ERROR: Failed to create CSS file: {e}")
    exit(1)

# Extract Mermaid diagrams
mermaid_blocks_found = re.findall(r'(```mermaid\s*\n(.*?)\n\s*```)', content, re.DOTALL)
print(f"Found {len(mermaid_blocks_found)} Mermaid blocks")

# Process each diagram
for idx, (full_block, diagram_code) in enumerate(mermaid_blocks_found, start=1):
    diagram_svg = os.path.join(output_img_dir, f'diagram_{idx}.svg')
    diagram_png = os.path.join(output_img_dir, f'diagram_{idx}.png')
    temp_mmd = os.path.join(output_img_dir, f'temp_{idx}.mmd')
    raw_diagram_code = diagram_code.strip()

    if not raw_diagram_code:
        print(f"Warning: Skipping empty Mermaid block {idx}")
        content = content.replace(full_block, f'\n\n[Empty Mermaid Diagram {idx}]\n\n')
        continue

    # Handle subgraph style bug
    lines = raw_diagram_code.splitlines()
    processed_lines = []
    style_pattern = re.compile(r'^\s*style\s+\".*\"')
    for line in lines:
        if style_pattern.match(line):
            print(f"Info: Removing style line in diagram {idx}: {line.strip()}")
            processed_lines.append(f"%% Removed style line: {line.strip()}")
        else:
            processed_lines.append(line)

    processed_diagram_code = "\n".join(processed_lines)

    try:
        # Write diagram code to temp file
        with open(temp_mmd, 'w', encoding='utf-8') as f:
            f.write(processed_diagram_code)
        print(f"Wrote diagram {idx} code to {temp_mmd}")

        # Render SVG with Mermaid CLI
        print(f"Rendering diagram {idx} to {diagram_svg}...")
        mmdc_cmd = [
            'mmdc', '-i', temp_mmd, '-o', diagram_svg,
            '-t', 'forest',
            '-w', '1024',
            '-C', css_path,
            '-b', 'transparent'
        ]
        result = subprocess.run(mmdc_cmd, check=True, capture_output=True, text=True)
        print(f"Diagram {idx} rendered to SVG: {result.stdout.strip()}")

        # Convert SVG to PNG with rsvg-convert
        print(f"Converting {diagram_svg} to {diagram_png}...")
        convert_cmd = ['rsvg-convert', '-f', 'png', '-o', diagram_png, diagram_svg]
        result = subprocess.run(convert_cmd, check=True, capture_output=True, text=True)
        print(f"Diagram {idx} converted to PNG: {result.stdout.strip() if result.stdout else 'Success'}")

        # Use relative path for embedding
        img_rel_path = os.path.join('.', output_img_dir, f'diagram_{idx}.png').replace('\\', '/')
        img_embed = f'\n\n![Diagram {idx}]({img_rel_path})\n\n'
        content = content.replace(full_block, img_embed)
        print(f"Embedded diagram {idx} as PNG at {img_rel_path}")

    except subprocess.CalledProcessError as e:
        print(f"ERROR: Failed for diagram {idx}. Return Code: {e.returncode}")
        stderr_output = e.stderr if e.stderr else "(No stderr)"
        print(f"STDERR:\n{stderr_output[:1000]}{'...' if len(stderr_output) > 1000 else ''}")
        content = content.replace(full_block, f'\n\n[Rendering Error for Diagram {idx}]\n\n')
    except FileNotFoundError as e:
        print(f"ERROR: Tool not found for diagram {idx}: {e}")
        content = content.replace(full_block, f'\n\n[Mermaid Error: Tool not found for diagram {idx}]\n\n')
    except Exception as e:
        print(f"ERROR: Unexpected error processing diagram {idx}: {e}")
        content = content.replace(full_block, f'\n\n[Processing Error for Diagram {idx}]\n\n')
    finally:
        if os.path.exists(temp_mmd):
            os.remove(temp_mmd)
            print(f"Cleaned up temp file {temp_mmd}")

# Save updated Markdown with embedded images
try:
    with open(output_md, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"Markdown with embedded images saved to {output_md}")
except Exception as e:
    print(f"ERROR: Failed to save output Markdown: {e}")
    exit(1)

# Convert Markdown directly to PDF with Pandoc, including clickable TOC
try:
    pandoc_cmd = (
        f"pandoc {output_md} -o {output_pdf} "
        f"--pdf-engine=xelatex "
        f"--toc "
        f"--toc-depth=3 "
        f"-V geometry:margin=1in "
        f"--resource-path={output_img_dir}"
    )
    result = subprocess.run(shlex.split(pandoc_cmd), check=True, capture_output=True, text=True)
    print(f"PDF with clickable TOC generated as {output_pdf}: {result.stdout.strip() if result.stdout else 'Success'}")
except subprocess.CalledProcessError as e:
    print(f"ERROR: Pandoc failed with return code {e.returncode}")
    stderr_output = e.stderr if e.stderr else "(No stderr)"
    print(f"STDERR: {stderr_output}")
    exit(1)

# Cleanup
try:
    os.remove(css_path)
    print(f"Cleaned up CSS file at {css_path}")
except Exception as e:
    print(f"Warning: Failed to clean up CSS file: {e}")