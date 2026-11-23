import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  EuiBadge,
  EuiBasicTable,
  EuiButton,
  EuiButtonEmpty,
  EuiButtonIcon,
  EuiCallOut,
  EuiFieldText,
  EuiFilePicker,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFormRow,
  EuiLink,
  EuiLoadingSpinner,
  EuiPanel,
  EuiSpacer,
  EuiText,
  EuiToolTip,
} from '@elastic/eui';
import {
  ATTACHMENT_ALLOWED_CONTENT_TYPES,
  ATTACHMENT_MAX_FILE_BYTES,
  ATTACHMENT_MAX_NAME_LENGTH,
  ATTACHMENT_MAX_PER_CASE,
  ATTACHMENT_MAX_URL_LENGTH,
  CaseAttachment,
} from '../../common';
import { AlertsApiService } from '../services/api';
import { formatAbsolute } from '../design';

interface Props {
  caseId: string;
  apiService: AlertsApiService;
  onError: (message: string) => void;
  onToast?: (title: string, color: 'success' | 'danger' | 'primary', text?: string) => void;
  /** Reports the fetched attachment count so the case flyout nav can badge it (step 8.1); never triggers a fetch. */
  onCountChanged?: (count: number) => void;
}

const ALLOWED_TYPES = new Set<string>(ATTACHMENT_ALLOWED_CONTENT_TYPES);

/** Browsers report an empty or vendor type for some files; fall back to the extension. */
const EXTENSION_TYPES: Record<string, string> = {
  txt: 'text/plain',
  log: 'text/plain',
  csv: 'text/csv',
  json: 'application/json',
  pdf: 'application/pdf',
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  zip: 'application/zip',
  pcap: 'application/vnd.tcpdump.pcap',
  pcapng: 'application/vnd.tcpdump.pcap',
  cap: 'application/vnd.tcpdump.pcap',
};

export interface FileInspection {
  ok: boolean;
  contentType: string | null;
  reason: string | null;
}

/**
 * Client-side mirror of the server checks (size on the raw bytes, type on
 * the allowlist) so an analyst learns about a refused file before uploading
 * 2 MiB of base64. The server is still the authority.
 */
export function inspectAttachmentFile(file: { name: string; type: string; size: number }): FileInspection {
  if (!file || file.size <= 0) return { ok: false, contentType: null, reason: 'The file is empty.' };
  if (file.size > ATTACHMENT_MAX_FILE_BYTES) {
    return { ok: false, contentType: null, reason: `The file is ${formatAttachmentSize(file.size)}; the limit is ${formatAttachmentSize(ATTACHMENT_MAX_FILE_BYTES)}.` };
  }
  const declared = String(file.type || '').split(';')[0].trim().toLowerCase();
  const extension = (String(file.name || '').toLowerCase().match(/\.([a-z0-9]+)$/) || [])[1] || '';
  const contentType = ALLOWED_TYPES.has(declared) ? declared : EXTENSION_TYPES[extension] || null;
  if (!contentType) {
    return {
      ok: false,
      contentType: null,
      reason: `Files of type "${declared || extension || 'unknown'}" are not accepted. Allowed: ${ATTACHMENT_ALLOWED_CONTENT_TYPES.join(', ')}.`,
    };
  }
  return { ok: true, contentType, reason: null };
}

export function formatAttachmentSize(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined) return '—';
  const n = Number(bytes);
  if (!Number.isFinite(n) || n < 0) return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MiB`;
}

function readFileAsBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(reader.error || new Error('The file could not be read.'));
    reader.onload = () => {
      const result = String(reader.result || '');
      const comma = result.indexOf(',');
      resolve(comma >= 0 ? result.slice(comma + 1) : result);
    };
    reader.readAsDataURL(file);
  });
}

function errorMessage(e: any, fallback: string): string {
  return e?.body?.message || e?.message || fallback;
}

export const AttachmentsTab: React.FC<Props> = ({ caseId, apiService, onError, onToast, onCountChanged }) => {
  const [attachments, setAttachments] = useState<CaseAttachment[]>([]);
  const [limit, setLimit] = useState(ATTACHMENT_MAX_PER_CASE);
  const [loading, setLoading] = useState(true);
  const [mode, setMode] = useState<'link' | 'file' | null>(null);
  const [linkName, setLinkName] = useState('');
  const [linkUrl, setLinkUrl] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [fileName, setFileName] = useState('');
  const [fileCheck, setFileCheck] = useState<FileInspection | null>(null);
  const [busy, setBusy] = useState(false);
  const [deleting, setDeleting] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const filePickerRef = useRef<any>(null);

  const load = useCallback(async () => {
    try {
      setLoading(true);
      const res = await apiService.fetchCaseAttachments(caseId);
      const list = res?.attachments || [];
      setAttachments(list);
      setLimit(res?.limit || ATTACHMENT_MAX_PER_CASE);
      setLoadError(null);
      onCountChanged?.(list.length);
    } catch (e: any) {
      // Same mapping as the Indicators tab: an error/no-access state must
      // not look like an empty case.
      const status = e?.response?.status ?? e?.body?.statusCode;
      const message = status === 403
        ? "You do not have access to this case's attachments."
        : status === 404
        ? 'Case not found.'
        : e?.body?.message || e?.message || 'Failed to load attachments';
      setLoadError(message);
      setAttachments([]);
      onError('Failed to load attachments');
    } finally {
      setLoading(false);
    }
  }, [caseId]);

  useEffect(() => {
    load();
  }, [load]);

  const full = attachments.length >= limit;

  const resetForms = () => {
    setMode(null);
    setLinkName('');
    setLinkUrl('');
    setFile(null);
    setFileName('');
    setFileCheck(null);
    filePickerRef.current?.removeFiles?.();
  };

  const addLink = async () => {
    const name = linkName.trim();
    const url = linkUrl.trim();
    if (!name || !url) return;
    try {
      setBusy(true);
      await apiService.addCaseAttachment(caseId, { kind: 'link', name, url });
      resetForms();
      await load();
      onToast?.('Link attached', 'success');
    } catch (e: any) {
      onError(errorMessage(e, 'Failed to attach the link'));
    } finally {
      setBusy(false);
    }
  };

  const onFilesPicked = (files: FileList | null) => {
    const picked = files && files.length ? files[0] : null;
    setFile(picked);
    setFileCheck(picked ? inspectAttachmentFile(picked) : null);
    if (picked && !fileName.trim()) setFileName(picked.name.slice(0, ATTACHMENT_MAX_NAME_LENGTH));
  };

  const uploadFile = async () => {
    if (!file) return;
    const check = inspectAttachmentFile(file);
    setFileCheck(check);
    if (!check.ok || !check.contentType) return;
    const name = (fileName.trim() || file.name).slice(0, ATTACHMENT_MAX_NAME_LENGTH);
    try {
      setBusy(true);
      const dataBase64 = await readFileAsBase64(file);
      await apiService.addCaseAttachment(caseId, { kind: 'file', name, contentType: check.contentType, dataBase64 });
      resetForms();
      await load();
      onToast?.('File attached', 'success', `${name} (${formatAttachmentSize(file.size)})`);
    } catch (e: any) {
      onError(errorMessage(e, 'Failed to upload the file'));
    } finally {
      setBusy(false);
    }
  };

  const remove = async (attachment: CaseAttachment) => {
    try {
      setDeleting(attachment.id);
      await apiService.deleteCaseAttachment(caseId, attachment.id);
      await load();
      onToast?.('Attachment removed', 'success', attachment.name);
    } catch (e: any) {
      onError(errorMessage(e, 'Failed to remove the attachment'));
    } finally {
      setDeleting(null);
    }
  };

  if (loading && attachments.length === 0) return <EuiLoadingSpinner size="m" />;

  const columns: any[] = [
    {
      field: 'name',
      name: 'Name',
      render: (name: string, item: CaseAttachment) =>
        item.kind === 'link' && item.url ? (
          <EuiLink href={item.url} target="_blank" rel="noopener noreferrer" external data-test-subj="wamAttachmentLink">
            {name}
          </EuiLink>
        ) : (
          <EuiLink href={apiService.caseAttachmentDownloadUrl(caseId, item.id)} target="_blank" rel="noopener noreferrer" data-test-subj="wamAttachmentDownload">
            {name}
          </EuiLink>
        ),
    },
    {
      field: 'kind',
      name: 'Kind',
      width: '90px',
      render: (kind: string, item: CaseAttachment) => (
        <EuiToolTip content={item.kind === 'file' ? item.content_type || '' : item.url || ''}>
          <EuiBadge color={kind === 'link' ? 'hollow' : 'default'}>{kind}</EuiBadge>
        </EuiToolTip>
      ),
    },
    {
      field: 'size',
      name: 'Size',
      width: '90px',
      render: (size: number, item: CaseAttachment) => (item.kind === 'file' ? formatAttachmentSize(size) : '—'),
    },
    {
      field: 'created_by',
      name: 'Added',
      render: (by: string, item: CaseAttachment) => (
        <EuiText size="xs">
          {by || '—'}
          <br />
          <span className="wamAttachmentWhen">{formatAbsolute(item.created_at)}</span>
        </EuiText>
      ),
    },
    {
      name: 'Actions',
      width: '90px',
      // The bundled OUI `DefaultItemAction` forwards `href` verbatim to
      // `EuiButtonIcon` (no per-row function support), so the two link-style
      // actions are custom-rendered anchors instead.
      actions: [
        {
          available: (item: CaseAttachment) => item.kind === 'file',
          render: (item: CaseAttachment) => (
            <EuiToolTip content="Download">
              <EuiButtonIcon
                iconType="download"
                aria-label={`Download ${item.name}`}
                href={apiService.caseAttachmentDownloadUrl(caseId, item.id)}
                target="_blank"
                rel="noopener noreferrer"
                data-test-subj="wamAttachmentDownloadAction"
              />
            </EuiToolTip>
          ),
        },
        {
          available: (item: CaseAttachment) => item.kind === 'link' && Boolean(item.url),
          render: (item: CaseAttachment) => (
            <EuiToolTip content="Open link">
              <EuiButtonIcon
                iconType="popout"
                aria-label={`Open ${item.name}`}
                href={item.url || undefined}
                target="_blank"
                rel="noopener noreferrer"
                data-test-subj="wamAttachmentOpenAction"
              />
            </EuiToolTip>
          ),
        },
        {
          name: 'Remove',
          description: 'Remove attachment',
          type: 'icon',
          icon: 'trash',
          color: 'danger',
          enabled: (item: CaseAttachment) => deleting !== item.id,
          onClick: (item: CaseAttachment) => remove(item),
          'data-test-subj': 'wamAttachmentRemove',
        },
      ],
    },
  ];

  return (
    <div className="wamAttachments" data-test-subj="wamCaseAttachments">
      <EuiFlexGroup alignItems="center" justifyContent="spaceBetween" responsive={false}>
        <EuiFlexItem grow={false}>
          <EuiText size="s" color="subdued">
            {attachments.length} of {limit} attachments. Files up to {formatAttachmentSize(ATTACHMENT_MAX_FILE_BYTES)}; links open in a new tab.
          </EuiText>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiFlexGroup gutterSize="s" responsive={false}>
            <EuiFlexItem grow={false}>
              <EuiButtonEmpty size="s" iconType="link" onClick={() => setMode(mode === 'link' ? null : 'link')} isDisabled={full || busy || loadError !== null} data-test-subj="wamAttachmentAddLink">
                Add link
              </EuiButtonEmpty>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiButtonEmpty size="s" iconType="exportAction" onClick={() => setMode(mode === 'file' ? null : 'file')} isDisabled={full || busy || loadError !== null} data-test-subj="wamAttachmentUploadFile">
                Upload file
              </EuiButtonEmpty>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiButtonIcon iconType="refresh" aria-label="Reload attachments" onClick={load} isDisabled={loading || busy} />
            </EuiFlexItem>
          </EuiFlexGroup>
        </EuiFlexItem>
      </EuiFlexGroup>
      {full && (
        <>
          <EuiSpacer size="s" />
          <EuiCallOut size="s" color="warning" iconType="alert" title={`This case holds the maximum of ${limit} attachments. Remove one to add another.`} />
        </>
      )}
      {mode === 'link' && (
        <>
          <EuiSpacer size="s" />
          <EuiPanel paddingSize="m" className="wamAttachmentForm" data-test-subj="wamAttachmentLinkForm">
            <EuiFormRow label="Name" fullWidth>
              <EuiFieldText
                fullWidth
                compressed
                maxLength={ATTACHMENT_MAX_NAME_LENGTH}
                placeholder="Ticket, runbook, external report..."
                value={linkName}
                onChange={(e) => setLinkName(e.target.value)}
                data-test-subj="wamAttachmentLinkName"
              />
            </EuiFormRow>
            <EuiFormRow label="URL" helpText="http or https; internal addresses are allowed, the link is only opened by your browser." fullWidth>
              <EuiFieldText
                fullWidth
                compressed
                maxLength={ATTACHMENT_MAX_URL_LENGTH}
                placeholder="https://"
                value={linkUrl}
                onChange={(e) => setLinkUrl(e.target.value)}
                data-test-subj="wamAttachmentLinkUrl"
              />
            </EuiFormRow>
            <EuiSpacer size="s" />
            <EuiFlexGroup gutterSize="s" responsive={false}>
              <EuiFlexItem grow={false}>
                <EuiButton size="s" fill onClick={addLink} isLoading={busy} isDisabled={!linkName.trim() || !linkUrl.trim()} data-test-subj="wamAttachmentLinkSubmit">
                  Attach link
                </EuiButton>
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiButtonEmpty size="s" onClick={resetForms} isDisabled={busy}>
                  Cancel
                </EuiButtonEmpty>
              </EuiFlexItem>
            </EuiFlexGroup>
          </EuiPanel>
        </>
      )}
      {mode === 'file' && (
        <>
          <EuiSpacer size="s" />
          <EuiPanel paddingSize="m" className="wamAttachmentForm" data-test-subj="wamAttachmentFileForm">
            <EuiFormRow
              label="File"
              fullWidth
              isInvalid={Boolean(fileCheck && !fileCheck.ok)}
              error={fileCheck && !fileCheck.ok ? fileCheck.reason : undefined}
              helpText={`Up to ${formatAttachmentSize(ATTACHMENT_MAX_FILE_BYTES)}: text, CSV, JSON, PDF, PNG, JPEG, ZIP or PCAP.`}
            >
              <EuiFilePicker
                ref={filePickerRef}
                fullWidth
                compressed
                display="default"
                initialPromptText="Select or drag a file"
                onChange={onFilesPicked}
                isInvalid={Boolean(fileCheck && !fileCheck.ok)}
                data-test-subj="wamAttachmentFilePicker"
              />
            </EuiFormRow>
            <EuiFormRow label="Name" helpText="Defaults to the file name." fullWidth>
              <EuiFieldText
                fullWidth
                compressed
                maxLength={ATTACHMENT_MAX_NAME_LENGTH}
                value={fileName}
                onChange={(e) => setFileName(e.target.value)}
                data-test-subj="wamAttachmentFileName"
              />
            </EuiFormRow>
            <EuiSpacer size="s" />
            <EuiFlexGroup gutterSize="s" responsive={false}>
              <EuiFlexItem grow={false}>
                <EuiButton size="s" fill onClick={uploadFile} isLoading={busy} isDisabled={!file || Boolean(fileCheck && !fileCheck.ok)} data-test-subj="wamAttachmentFileSubmit">
                  Upload
                </EuiButton>
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiButtonEmpty size="s" onClick={resetForms} isDisabled={busy}>
                  Cancel
                </EuiButtonEmpty>
              </EuiFlexItem>
            </EuiFlexGroup>
          </EuiPanel>
        </>
      )}
      <EuiSpacer size="m" />
      {loadError !== null ? (
        <EuiCallOut size="s" color="danger" iconType="alert" title="Attachments are unavailable" data-test-subj="wamAttachmentsError">
          <p>{loadError}</p>
          <EuiButton size="s" color="danger" onClick={load} isLoading={loading} data-test-subj="wamAttachmentsRetry">
            Retry
          </EuiButton>
        </EuiCallOut>
      ) : (
        <EuiBasicTable
          className="wamAttachmentTable"
          items={attachments}
          columns={columns}
          loading={loading}
          noItemsMessage="No attachments yet. Add a link to a ticket or report, or upload a small file."
          rowProps={(item: CaseAttachment) => ({ 'data-test-subj': `wamAttachmentRow-${item.id}` })}
        />
      )}
    </div>
  );
};
