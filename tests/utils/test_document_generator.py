import pytest
import os
from pathlib import Path
from unittest.mock import patch, MagicMock
from src.utils.document_generator import DocumentGenerator, generate_research_report

@pytest.fixture
def sample_research_data():
    return {
        "Executive Summary": "This is a summary.",
        "Findings": {
            "Finding 1": "Details about finding 1.",
            "Finding 2": ["Point A", "Point B"]
        }
    }

def test_generate_research_report_docx(sample_research_data):
    with patch.object(DocumentGenerator, 'generate_docx', return_value="path/to/report.docx") as mock_generate:
        result = generate_research_report("Test Title", sample_research_data, output_format="docx")

        mock_generate.assert_called_once_with("Test Title", sample_research_data)
        assert result == "path/to/report.docx"

def test_generate_research_report_markdown(sample_research_data):
    with patch.object(DocumentGenerator, 'generate_markdown', return_value="path/to/report.md") as mock_generate:
        result = generate_research_report("Test Title", sample_research_data, output_format="markdown")

        mock_generate.assert_called_once_with("Test Title", sample_research_data)
        assert result == "path/to/report.md"

def test_generate_research_report_pdf(sample_research_data):
    with patch.object(DocumentGenerator, 'generate_pdf', return_value="path/to/report.pdf") as mock_generate:
        result = generate_research_report("Test Title", sample_research_data, output_format="pdf")

        mock_generate.assert_called_once_with("Test Title", sample_research_data)
        assert result == "path/to/report.pdf"

def test_generate_research_report_unsupported_format(sample_research_data):
    with pytest.raises(ValueError, match="Unsupported format: txt"):
        generate_research_report("Test Title", sample_research_data, output_format="txt")

def test_document_generator_generate_markdown(tmp_path, sample_research_data):
    # tmp_path is a built-in pytest fixture providing a temporary directory unique to the test invocation
    generator = DocumentGenerator(output_dir=str(tmp_path))

    filepath = generator.generate_markdown("Test Title", sample_research_data, filename="test_report.md")

    assert os.path.exists(filepath)

    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    assert "# Test Title" in content
    assert "## Executive Summary" in content
    assert "This is a summary." in content
    assert "## Findings" in content
    assert "### Finding 1" in content
    assert "Details about finding 1." in content
    assert "### Finding 2" in content
    assert "- Point A" in content
    assert "- Point B" in content
