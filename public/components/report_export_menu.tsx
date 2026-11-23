import React, { useCallback, useState } from 'react';
import { EuiButton, EuiContextMenuItem, EuiContextMenuPanel, EuiPopover } from '@elastic/eui';
import type { ReportExportFormat } from '../../common';
import { AlertsApiService, downloadBlob } from '../services/api';

/**
 * Export menu of the Reporting app header (step 10.3): the server renders the
 * current window as a self-contained HTML page, Markdown, CSV or JSON and the
 * browser saves it; "Print / Save as PDF" opens the HTML export in a new tab
 * with the print trigger, so the PDF comes from the browser's own Save as PDF
 * (no PDF library is bundled).
 */

interface Props {
  apiService: Pick<AlertsApiService, 'downloadReportExport' | 'reportExportUrl'>;
  /** Picker window as the page sends it to the metrics route (date math or ISO). */
  from: string;
  to: string;
  disabled?: boolean;
  onToast?: (title: string, color: 'success' | 'danger' | 'primary', text?: string) => void;
}

export const REPORT_EXPORT_ITEMS: Array<{ format: ReportExportFormat; label: string }> = [
  { format: 'html', label: 'Download HTML' },
  { format: 'markdown', label: 'Download Markdown' },
  { format: 'csv', label: 'Download CSV' },
  { format: 'json', label: 'Download JSON' },
];

export const REPORT_EXPORT_PDF_TOOLTIP = "Opens the HTML report in a new tab and calls Print; choose the browser's Save as PDF destination to get a PDF.";

export const ReportExportMenu: React.FC<Props> = ({ apiService, from, to, disabled, onToast }) => {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);

  const download = useCallback(
    async (format: ReportExportFormat) => {
      setOpen(false);
      setBusy(true);
      try {
        const result = await apiService.downloadReportExport(from, to, format);
        downloadBlob(result.filename, result.blob);
        onToast?.(`Report exported (${format.toUpperCase()})`, 'success', result.filename);
      } catch (e: any) {
        onToast?.('Failed to export the report', 'danger', e?.body?.message || e?.message);
      } finally {
        setBusy(false);
      }
    },
    [apiService, from, to, onToast]
  );

  const openPrint = useCallback(() => {
    setOpen(false);
    // Same-origin GET: the dashboard session cookie applies, no XSRF header needed.
    window.open(apiService.reportExportUrl(from, to, { print: true }), '_blank', 'noopener');
  }, [apiService, from, to]);

  return (
    <EuiPopover
      id="wamReportExportPopover"
      button={
        <EuiButton
          size="s"
          iconType="exportAction"
          iconSide="left"
          className="wamReportExport"
          data-test-subj="wamReportExport"
          isLoading={busy}
          isDisabled={disabled || busy}
          onClick={() => setOpen((v) => !v)}
        >
          Export
        </EuiButton>
      }
      isOpen={open}
      closePopover={() => setOpen(false)}
      panelPaddingSize="none"
      anchorPosition="downRight"
    >
      <EuiContextMenuPanel
        className="wamReportExportMenu"
        items={[
          ...REPORT_EXPORT_ITEMS.map((item) => (
            <EuiContextMenuItem key={item.format} icon="download" data-test-subj={`wamReportExport-${item.format}`} onClick={() => download(item.format)}>
              {item.label}
            </EuiContextMenuItem>
          )),
          <EuiContextMenuItem
            key="pdf"
            icon="popout"
            data-test-subj="wamReportExport-pdf"
            toolTipContent={REPORT_EXPORT_PDF_TOOLTIP}
            toolTipPosition="left"
            onClick={openPrint}
          >
            Print / Save as PDF
          </EuiContextMenuItem>,
        ]}
      />
    </EuiPopover>
  );
};
