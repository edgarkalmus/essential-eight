import jsPDF from 'jspdf';

export const exportToPdf = async () => {
  const results = document.getElementById('assessment-results');
  
  if (!results) {
    console.error('Results element not found');
    return;
  }

  try {
    const pdf = new jsPDF('p', 'mm', 'a4');
    const pageWidth = pdf.internal.pageSize.getWidth();
    const margin = 20;
    const contentWidth = pageWidth - (margin * 2);
    let yPos = margin;

    // Set fonts
    pdf.setFont('helvetica', 'bold');
    
    // Title
    pdf.setFontSize(20);
    pdf.text('Essential Eight Assessment Results', pageWidth / 2, yPos, { align: 'center' });
    yPos += 15;

    // Date
    pdf.setFontSize(12);
    pdf.setFont('helvetica', 'normal');
    const date = new Date().toLocaleDateString('en-AU', {
      day: 'numeric',
      month: 'long',
      year: 'numeric'
    });
    pdf.text(`Assessment Date: ${date}`, pageWidth / 2, yPos, { align: 'center' });
    yPos += 20;

    // Overall metrics
    const metricsContainer = results.querySelector('div:first-of-type');
    if (metricsContainer) {
      const metrics = metricsContainer.querySelectorAll(':scope > div');
      
      metrics.forEach((metric) => {
        const titleElement = metric.querySelector('h3');
        const valueElement = metric.querySelector('div:not(h3)');
        
        if (titleElement && valueElement) {
          const title = titleElement.textContent?.trim();
          const value = valueElement.textContent?.trim();
          
          if (title && value) {
            pdf.setFont('helvetica', 'bold');
            pdf.setFontSize(14);
            pdf.text(title, margin, yPos);
            
            pdf.setFont('helvetica', 'normal');
            pdf.text(value, pageWidth - margin, yPos, { align: 'right' });
            yPos += 10;
          }
        }
      });
      yPos += 10;
    }

    // Strategy Summary
    pdf.setFontSize(16);
    pdf.setFont('helvetica', 'bold');
    pdf.text('Strategy-Level Maturity Summary', margin, yPos);
    yPos += 10;

    // Table headers
    const headers = ['Strategy', 'Level', 'Description'];
    pdf.setFontSize(12);
    pdf.setFont('helvetica', 'bold');
    
    const colWidths = [
      contentWidth * 0.2,  // Strategy
      contentWidth * 0.15, // Level
      contentWidth * 0.65  // Description
    ];
    
    let xPos = margin;
    headers.forEach((header, i) => {
      pdf.text(header, xPos, yPos);
      xPos += colWidths[i];
    });
    yPos += 5;

    // Draw header line
    pdf.setLineWidth(0.2);
    pdf.line(margin, yPos, pageWidth - margin, yPos);
    yPos += 5;

    // Table content
    pdf.setFont('helvetica', 'normal');
    const tableContainer = document.getElementById('pdf-table-container');
    if (tableContainer) {
      const rows = tableContainer.querySelectorAll('table tbody tr');

      rows.forEach((row) => {
        const cells = row.querySelectorAll('td');
        const lineHeight = 5;
        let rowLines = [];
        let maxHeight = 0;

        cells.forEach((cell, i) => {
          const text = cell?.textContent?.trim() || '';
          let lines;

          if (i === 2) {
            const bulletPoints = text.split(/[.•]/).filter(p => p.trim());
            lines = bulletPoints.map(p => `• ${p.trim()}`).flatMap(b =>
              pdf.splitTextToSize(b, colWidths[i] - 5)
            );
          } else {
            lines = pdf.splitTextToSize(text, colWidths[i] - 5);
          }

          rowLines[i] = lines;
          maxHeight = Math.max(maxHeight, lines.length * lineHeight);
        });

        if (yPos + maxHeight > pdf.internal.pageSize.getHeight() - margin) {
          pdf.addPage();
          yPos = margin;
        }

        xPos = margin;
        rowLines.forEach((cellLines, i) => {
          pdf.text(cellLines, xPos, yPos);
          xPos += colWidths[i];
        });

        yPos += maxHeight + 5;
      });
    }

    // Recommendations
    if (yPos + 40 > pdf.internal.pageSize.getHeight() - margin) {
      pdf.addPage();
      yPos = margin;
    }

    yPos += 10;
    pdf.setFont('helvetica', 'bold');
    pdf.setFontSize(16);
    pdf.text('Key Recommendations', margin, yPos);
    yPos += 10;

    pdf.setFont('helvetica', 'normal');
    pdf.setFontSize(12);

    const recommendations = results.querySelectorAll('.bg-gray-50');
    
    recommendations.forEach((rec) => {
      const titleElement = rec.querySelector('h4');
      const descriptionElement = rec.querySelector('p');
      const fullItemsData = rec.getAttribute('data-full-items');
      let items = [];
      
      try {
        items = JSON.parse(fullItemsData || '[]');
      } catch (e) {
        console.error('Error parsing recommendation items:', e);
      }

      if (!titleElement || !descriptionElement) return;

      const title = titleElement.textContent?.trim();
      const description = descriptionElement.textContent?.trim();

      if (yPos + 20 > pdf.internal.pageSize.getHeight() - margin) {
        pdf.addPage();
        yPos = margin;
      }

      pdf.setFont('helvetica', 'bold');
      const titleLines = pdf.splitTextToSize(title, contentWidth);
      pdf.text(titleLines, margin, yPos);
      yPos += titleLines.length * 5 + 2;

      pdf.setFont('helvetica', 'normal');
      const descLines = pdf.splitTextToSize(description, contentWidth);
      pdf.text(descLines, margin, yPos);
      yPos += descLines.length * 5 + 5;

      if (items.length > 0) {
        items.forEach((item) => {
          if (yPos + 10 > pdf.internal.pageSize.getHeight() - margin) {
            pdf.addPage();
            yPos = margin;
          }
          const itemText = `• ${item}`;
          const itemLines = pdf.splitTextToSize(itemText, contentWidth - 5);
          pdf.text(itemLines, margin + 5, yPos);
          yPos += itemLines.length * 5 + 2;
        });
        yPos += 5;
      }
    });

    pdf.save('E8-Assessment-Results.pdf');
  } catch (error) {
    console.error('Error exporting to PDF:', error);
  }
};