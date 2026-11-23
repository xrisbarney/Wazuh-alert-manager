/**
 * @jest-environment jsdom
 */
import React from 'react';
import { configure, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ATTACHMENT_MAX_FILE_BYTES, CaseAttachment } from '../../common';
import { AttachmentsTab, formatAttachmentSize, inspectAttachmentFile } from './attachments_tab';

configure({ testIdAttribute: 'data-test-subj' });

const FILE: CaseAttachment = { id: 'f1', case_id: 'case-1', kind: 'file', name: 'capture.pcap', url: null, content_type: 'application/vnd.tcpdump.pcap', size: 2048, sha256: 'ab', created_by: 'analyst', created_at: '2026-11-20T10:00:00.000Z' };
const LINK: CaseAttachment = { id: 'l1', case_id: 'case-1', kind: 'link', name: 'Ticket T-1', url: 'https://tickets.example.org/T-1', content_type: null, size: 0, sha256: null, created_by: 'analyst', created_at: '2026-11-20T11:00:00.000Z' };

function service(fetchImpl: () => Promise<any>) {
  return {
    fetchCaseAttachments: jest.fn(fetchImpl),
    addCaseAttachment: jest.fn(),
    deleteCaseAttachment: jest.fn(async () => ({ deleted: true })),
    caseAttachmentDownloadUrl: (caseId: string, id: string) => `/base/api/wazuh_alert_manager/cases/${caseId}/attachments/${id}/download`,
  } as any;
}

describe('AttachmentsTab', () => {
  test('renders a file row with a download action and a link row with an open action', async () => {
    const apiService = service(async () => ({ attachments: [FILE, LINK], total: 2, limit: 20 }));
    const onError = jest.fn();
    render(<AttachmentsTab caseId="case-1" apiService={apiService} onError={onError} />);
    await waitFor(() => expect(screen.getByTestId('wamCaseAttachments')).toBeTruthy());
    expect(apiService.fetchCaseAttachments).toHaveBeenCalledWith('case-1');
    expect(screen.getByTestId('wamAttachmentRow-f1')).toBeTruthy();
    expect(screen.getByTestId('wamAttachmentRow-l1')).toBeTruthy();

    const download = screen.getAllByTestId('wamAttachmentDownloadAction');
    expect(download).toHaveLength(1);
    expect(download[0].getAttribute('href')).toBe('/base/api/wazuh_alert_manager/cases/case-1/attachments/f1/download');
    expect(download[0].getAttribute('target')).toBe('_blank');
    expect(download[0].getAttribute('rel')).toContain('noopener');

    const open = screen.getAllByTestId('wamAttachmentOpenAction');
    expect(open).toHaveLength(1);
    expect(open[0].getAttribute('href')).toBe('https://tickets.example.org/T-1');
    expect(open[0].getAttribute('target')).toBe('_blank');

    expect(screen.getByTestId('wamAttachmentLink').getAttribute('href')).toBe('https://tickets.example.org/T-1');
    expect(screen.getByTestId('wamAttachmentDownload').getAttribute('href')).toBe('/base/api/wazuh_alert_manager/cases/case-1/attachments/f1/download');
    expect(screen.getAllByTestId('wamAttachmentRemove')).toHaveLength(2);
    expect(screen.queryByTestId('wamAttachmentsError')).toBeNull();
    expect(onError).not.toHaveBeenCalled();
    expect((screen.getByTestId('wamAttachmentAddLink') as HTMLButtonElement).disabled).toBe(false);
  });

  test('a failed load shows an in-tab error with retry and disables adding', async () => {
    let calls = 0;
    const apiService = service(async () => {
      calls += 1;
      if (calls === 1) throw Object.assign(new Error('Forbidden'), { response: { status: 403 } });
      return { attachments: [], total: 0, limit: 20 };
    });
    const onError = jest.fn();
    render(<AttachmentsTab caseId="case-1" apiService={apiService} onError={onError} />);
    await waitFor(() => expect(screen.getByTestId('wamAttachmentsError')).toBeTruthy());
    expect(screen.getByTestId('wamAttachmentsError').textContent).toContain("You do not have access to this case's attachments.");
    expect(screen.queryByText(/No attachments yet/)).toBeNull();
    expect((screen.getByTestId('wamAttachmentAddLink') as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByTestId('wamAttachmentUploadFile') as HTMLButtonElement).disabled).toBe(true);
    expect(onError).toHaveBeenCalledWith('Failed to load attachments');

    fireEvent.click(screen.getByTestId('wamAttachmentsRetry'));
    await waitFor(() => expect(screen.queryByTestId('wamAttachmentsError')).toBeNull());
    expect(screen.getByText(/No attachments yet/)).toBeTruthy();
    expect((screen.getByTestId('wamAttachmentAddLink') as HTMLButtonElement).disabled).toBe(false);
  });

  test('maps 404 and other failures to their messages', async () => {
    const apiService = service(async () => { throw Object.assign(new Error('boom'), { body: { statusCode: 404 } }); });
    render(<AttachmentsTab caseId="case-1" apiService={apiService} onError={jest.fn()} />);
    await waitFor(() => expect(screen.getByTestId('wamAttachmentsError').textContent).toContain('Case not found.'));
  });
});

describe('attachment file inspection (client-side mirror of the server checks)', () => {
  test('accepts an allowlisted declared type and infers one from the extension when the browser gives none', () => {
    expect(inspectAttachmentFile({ name: 'a.png', type: 'image/png', size: 10 })).toEqual({ ok: true, contentType: 'image/png', reason: null });
    expect(inspectAttachmentFile({ name: 'capture.pcap', type: '', size: 10 }).contentType).toBe('application/vnd.tcpdump.pcap');
    expect(inspectAttachmentFile({ name: 'notes.TXT', type: 'application/octet-stream', size: 10 }).contentType).toBe('text/plain');
  });

  test('refuses empty, oversized and non-allowlisted files', () => {
    expect(inspectAttachmentFile({ name: 'a.png', type: 'image/png', size: 0 }).ok).toBe(false);
    expect(inspectAttachmentFile({ name: 'a.png', type: 'image/png', size: ATTACHMENT_MAX_FILE_BYTES + 1 }).reason).toMatch(/limit/);
    expect(inspectAttachmentFile({ name: 'a.png', type: 'image/png', size: ATTACHMENT_MAX_FILE_BYTES }).ok).toBe(true);
    expect(inspectAttachmentFile({ name: 'tool.exe', type: 'application/x-msdownload', size: 10 }).reason).toMatch(/not accepted/);
    expect(inspectAttachmentFile({ name: 'page.html', type: 'text/html', size: 10 }).ok).toBe(false);
  });

  test('formats sizes', () => {
    expect(formatAttachmentSize(512)).toBe('512 B');
    expect(formatAttachmentSize(2048)).toBe('2.0 KiB');
    expect(formatAttachmentSize(ATTACHMENT_MAX_FILE_BYTES)).toBe('2.00 MiB');
    expect(formatAttachmentSize(null)).toBe('—');
  });
});
