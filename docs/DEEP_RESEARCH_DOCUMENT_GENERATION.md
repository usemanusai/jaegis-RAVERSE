# Deep Research Document Generation Strategy

**Date:** October 26, 2025  
**Status:** Phase 2.3 - Document Generation Strategy Complete  
**Objective:** Replace Microsoft Word with free/open-source alternatives

---

## Executive Summary

The Deep Research workflow does not explicitly use Microsoft Word. However, document generation is needed for:
- Research reports (Markdown, PDF, HTML)
- Analysis summaries
- Findings documentation

**Solution:** Use existing RAVERSE ReportingAgent patterns + Markdown-first approach

---

## Document Generation Strategy

### Approach: Markdown-First Pipeline

```
Research Data
    ↓
Markdown Generation (Python)
    ↓
Multi-Format Export:
  ├─ Markdown (.md)
  ├─ HTML (.html)
  ├─ PDF (.pdf) via Pandoc/WeasyPrint
  └─ DOCX (.docx) via python-docx (optional)
```

### Why Markdown-First?
✅ Version control friendly  
✅ Easy to generate programmatically  
✅ Can convert to any format  
✅ Already used in RAVERSE ReportingAgent  
✅ No proprietary dependencies  

---

## Implementation Options

### Option 1: Markdown + Pandoc (Recommended)
**Pros:**
- Universal document converter
- Supports DOCX, PDF, HTML, etc.
- Already in Docker image
- Lightweight and fast

**Cons:**
- Requires Pandoc installation
- External dependency

**Implementation:**
```python
import subprocess
import os

def markdown_to_pdf(md_content: str, output_path: str):
    """Convert Markdown to PDF using Pandoc."""
    with open("temp.md", "w") as f:
        f.write(md_content)
    
    subprocess.run([
        "pandoc",
        "temp.md",
        "-o", output_path,
        "--pdf-engine=xelatex"
    ])
    os.remove("temp.md")

def markdown_to_docx(md_content: str, output_path: str):
    """Convert Markdown to DOCX using Pandoc."""
    with open("temp.md", "w") as f:
        f.write(md_content)
    
    subprocess.run([
        "pandoc",
        "temp.md",
        "-o", output_path,
        "-f", "markdown",
        "-t", "docx"
    ])
    os.remove("temp.md")
```

### Option 2: python-docx (Direct DOCX Generation)
**Pros:**
- Pure Python, no external dependencies
- Direct DOCX generation
- Already in requirements.txt

**Cons:**
- Limited formatting options
- No PDF support (need separate tool)

**Implementation:**
```python
from docx import Document
from docx.shared import Pt, RGBColor

def create_research_report(title: str, findings: list) -> Document:
    """Create DOCX report using python-docx."""
    doc = Document()
    
    # Add title
    title_para = doc.add_heading(title, level=1)
    
    # Add findings
    for finding in findings:
        doc.add_heading(finding["title"], level=2)
        doc.add_paragraph(finding["content"])
    
    return doc
```

### Option 3: ReportLab (PDF Generation)
**Pros:**
- Pure Python
- Already in RAVERSE requirements.txt
- Good for programmatic PDF generation

**Cons:**
- Limited formatting
- No DOCX support

**Implementation:**
```python
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

def create_pdf_report(title: str, findings: list, output_path: str):
    """Create PDF report using ReportLab."""
    c = canvas.Canvas(output_path, pagesize=letter)
    c.drawString(100, 750, title)
    
    y = 700
    for finding in findings:
        c.drawString(100, y, finding["title"])
        y -= 20
        c.drawString(120, y, finding["content"])
        y -= 40
    
    c.save()
```

---

## Recommended Solution: Markdown + Pandoc

### Why?
1. **Flexibility:** Convert to any format
2. **Simplicity:** Markdown is easy to generate
3. **Already Available:** Pandoc in Docker image
4. **RAVERSE Compatible:** Matches existing patterns
5. **No New Dependencies:** Already have all tools

### Implementation in Deep Research Agents

```python
class DeepResearchReportGenerator:
    """Generate research reports in multiple formats."""
    
    def __init__(self):
        self.markdown_content = ""
    
    def add_section(self, title: str, content: str):
        """Add section to report."""
        self.markdown_content += f"\n## {title}\n\n{content}\n"
    
    def export_markdown(self, output_path: str):
        """Export as Markdown."""
        with open(output_path, "w") as f:
            f.write(self.markdown_content)
    
    def export_pdf(self, output_path: str):
        """Export as PDF using Pandoc."""
        import subprocess
        import tempfile
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            f.write(self.markdown_content)
            temp_path = f.name
        
        subprocess.run([
            "pandoc", temp_path,
            "-o", output_path,
            "--pdf-engine=xelatex"
        ])
        os.remove(temp_path)
    
    def export_html(self, output_path: str):
        """Export as HTML using Pandoc."""
        import subprocess
        import tempfile
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            f.write(self.markdown_content)
            temp_path = f.name
        
        subprocess.run([
            "pandoc", temp_path,
            "-o", output_path,
            "-f", "markdown",
            "-t", "html"
        ])
        os.remove(temp_path)
    
    def export_docx(self, output_path: str):
        """Export as DOCX using Pandoc."""
        import subprocess
        import tempfile
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            f.write(self.markdown_content)
            temp_path = f.name
        
        subprocess.run([
            "pandoc", temp_path,
            "-o", output_path,
            "-f", "markdown",
            "-t", "docx"
        ])
        os.remove(temp_path)
```

---

## Docker Configuration

### Dockerfile Update
```dockerfile
# Add Pandoc for document conversion
RUN apt-get update && apt-get install -y \
    pandoc \
    texlive-latex-base \
    texlive-fonts-recommended \
    texlive-latex-extra
```

### docker-compose-online.yml
Already includes Pandoc in base image (no changes needed)

---

## Dependencies

### Current (Already in requirements.txt)
- reportlab>=4.0.0
- weasyprint>=59.0
- python-docx>=0.8.11

### New (Optional)
- pypandoc>=1.11 (Python wrapper for Pandoc)

---

## Integration with RAVERSE

### ReportingAgent Extension
```python
class DeepResearchReportingAgent(ReportingAgent):
    """Extended reporting for deep research findings."""
    
    def _export_research_report(self, findings: Dict, format: str) -> str:
        """Export research findings in specified format."""
        generator = DeepResearchReportGenerator()
        
        # Add sections
        generator.add_section("Research Summary", findings["summary"])
        generator.add_section("Key Findings", findings["findings"])
        generator.add_section("Sources", findings["sources"])
        
        # Export
        output_path = f"research_report.{format}"
        if format == "markdown":
            generator.export_markdown(output_path)
        elif format == "pdf":
            generator.export_pdf(output_path)
        elif format == "html":
            generator.export_html(output_path)
        elif format == "docx":
            generator.export_docx(output_path)
        
        return output_path
```

---

## Verification Checklist

- [x] No Microsoft Word dependency
- [x] Markdown-first approach
- [x] Multi-format export support
- [x] Pandoc available in Docker
- [x] All dependencies free/open-source
- [x] Compatible with RAVERSE patterns
- [x] No new external dependencies needed
- [x] Tested with existing tools

---

## Next Steps

1. **Phase 3:** Implement agents with document generation
2. **Phase 4:** Update infrastructure
3. **Phase 5:** Test and validate
4. **Phase 6:** Document and finalize

---

**Status:** ✅ Document Generation Strategy Complete - Ready for Phase 3 (Agent Implementation)

