import pdfplumber
import os
import extract_intelligence  # Import the extract_threat_intelligence function

# Path to the directory containing the PDF files
pdf_folder = 'C:/Users/gupta/threat-intelligence/C3i_HACKATHON_FINAL_ROUND_Q1_DATA'

# List all files in the directory
pdf_files = [file for file in os.listdir(pdf_folder) if file.endswith('.pdf')]

# Loop through each PDF file and extract text
for pdf_file in pdf_files:
    with pdfplumber.open(os.path.join(pdf_folder, pdf_file)) as pdf:
        full_text = ""
        for page in pdf.pages:
            full_text += page.extract_text()

        # Print extracted text (or save it to a file if needed)
        print(f"Extracting from {pdf_file}:")
        print(full_text[:1000])  # Print the first 1000 characters of the extracted text

        # Extract threat intelligence from the text
        threat_intelligence = extract_intelligence.extract_threat_intelligence(full_text)

        # Print the extracted threat intelligence
        print("\nExtracted Threat Intelligence:")
        print(threat_intelligence)
        print("\n--- End of file ---\n")
