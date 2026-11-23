/**
 * @jest-environment jsdom
 */
import React from 'react';
import { configure, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ReportExportMenu, REPORT_EXPORT_PDF_TOOLTIP } from './report_export_menu';

jest.mock('../services/api', () => ({ downloadBlob: jest.fn() }));

/* eslint-disable @typescript-eslint/no-var-requires */
const downloadBlob: jest.Mock = require('../services/api').downloadBlob;
/* eslint-enable @typescript-eslint/no-var-requires */

configure({ testIdAttribute: 'data-test-subj' });

function apiWith() {
  return {
    downloadReportExport: jest.fn(async (_from: string, _to: string, format: string) => ({
      blob: new Blob(['x'], { type: 'text/plain' }),
      filename: `wam-report-2026-11-21-now-7d_now.${format}`,
      truncated: false,
    })),
    reportExportUrl: jest.fn((from: string, to: string, options: any = {}) => `/base/api/wazuh_alert_manager/reports/export?format=html&inline=1&from=${from}&to=${to}${options.print ? '&print=1' : ''}`),
  };
}

describe('ReportExportMenu (step 10.3)', () => {
  beforeEach(() => downloadBlob.mockReset());

  test('opens a menu with one item per format and the Print / Save as PDF item', () => {
    render(<ReportExportMenu apiService={apiWith() as any} from="now-7d" to="now" />);
    fireEvent.click(screen.getByTestId('wamReportExport'));
    expect(screen.getByTestId('wamReportExport-html').textContent).toBe('Download HTML');
    expect(screen.getByTestId('wamReportExport-markdown').textContent).toBe('Download Markdown');
    expect(screen.getByTestId('wamReportExport-csv').textContent).toBe('Download CSV');
    expect(screen.getByTestId('wamReportExport-json').textContent).toBe('Download JSON');
    expect(screen.getByTestId('wamReportExport-pdf').textContent).toBe('Print / Save as PDF');
    expect(REPORT_EXPORT_PDF_TOOLTIP).toMatch(/Save as PDF/);
  });

  test('a format item downloads the export of the current window and toasts the file name', async () => {
    const apiService = apiWith();
    const onToast = jest.fn();
    render(<ReportExportMenu apiService={apiService as any} from="now-30d" to="now" onToast={onToast} />);
    fireEvent.click(screen.getByTestId('wamReportExport'));
    fireEvent.click(screen.getByTestId('wamReportExport-csv'));
    await waitFor(() => expect(downloadBlob).toHaveBeenCalledTimes(1));
    expect(apiService.downloadReportExport).toHaveBeenCalledWith('now-30d', 'now', 'csv');
    expect(downloadBlob).toHaveBeenCalledWith('wam-report-2026-11-21-now-7d_now.csv', expect.any(Blob));
    expect(onToast).toHaveBeenCalledWith('Report exported (CSV)', 'success', 'wam-report-2026-11-21-now-7d_now.csv');
  });

  test('a failed download toasts the server message', async () => {
    const apiService = apiWith();
    apiService.downloadReportExport.mockRejectedValueOnce({ body: { message: 'index_not_found_exception' } });
    const onToast = jest.fn();
    render(<ReportExportMenu apiService={apiService as any} from="now-7d" to="now" onToast={onToast} />);
    fireEvent.click(screen.getByTestId('wamReportExport'));
    fireEvent.click(screen.getByTestId('wamReportExport-json'));
    await waitFor(() => expect(onToast).toHaveBeenCalledWith('Failed to export the report', 'danger', 'index_not_found_exception'));
    expect(downloadBlob).not.toHaveBeenCalled();
  });

  test('Print / Save as PDF opens the inline HTML export with print=1 in a new tab', () => {
    const apiService = apiWith();
    const open = jest.spyOn(window, 'open').mockImplementation(() => null);
    render(<ReportExportMenu apiService={apiService as any} from="now-7d" to="now" />);
    fireEvent.click(screen.getByTestId('wamReportExport'));
    fireEvent.click(screen.getByTestId('wamReportExport-pdf'));
    expect(apiService.reportExportUrl).toHaveBeenCalledWith('now-7d', 'now', { print: true });
    expect(open).toHaveBeenCalledWith('/base/api/wazuh_alert_manager/reports/export?format=html&inline=1&from=now-7d&to=now&print=1', '_blank', 'noopener');
    expect(apiService.downloadReportExport).not.toHaveBeenCalled();
    open.mockRestore();
  });

  test('is disabled while the page has no data', () => {
    render(<ReportExportMenu apiService={apiWith() as any} from="now-7d" to="now" disabled />);
    expect((screen.getByTestId('wamReportExport') as HTMLButtonElement).disabled).toBe(true);
  });
});
