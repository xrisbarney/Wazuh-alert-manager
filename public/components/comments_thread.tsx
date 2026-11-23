import React, { useState, useEffect, useCallback } from 'react';
import { EuiTextArea, EuiButton, EuiButtonEmpty, EuiSpacer, EuiLoadingSpinner, EuiText, EuiFlexGroup, EuiFlexItem } from '@elastic/eui';
import { Comment } from '../../common';
import { AlertsApiService } from '../services/api';
import { formatAbsolute } from '../design';

interface Props {
  apiService: AlertsApiService;
  target: { alertId?: string; caseId?: string };
  onError: (message: string) => void;
  onToast?: (title: string, color: 'success' | 'danger' | 'primary', text?: string) => void;
  /** Reports the thread total so the case flyout nav can badge it (step 8.1); never triggers a fetch. */
  onCountChanged?: (total: number) => void;
}

/**
 * Comment thread of an alert or a case. Rows sit on the shared history grid
 * (time | author + text, step 8.2) so comments, audit history and related
 * alerts line up inside a flyout; the composer sits below the list.
 */
export const CommentsThread: React.FC<Props> = ({ apiService, target, onError, onToast, onCountChanged }) => {
  const [comments, setComments] = useState<Comment[]>([]);
  const [loading, setLoading] = useState(true);
  const [draft, setDraft] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [total, setTotal] = useState(0);
  const [loadingMore, setLoadingMore] = useState(false);

  const load = useCallback(async () => {
    try {
      setLoading(true);
      const res: any = await apiService.fetchComments(target);
      setComments(res?.comments || []);
      setNextCursor(res?.nextCursor || null);
      setTotal(res?.total || 0);
      onCountChanged?.(res?.total || 0);
    } catch (e) {
      onError('Failed to load comments');
    } finally {
      setLoading(false);
    }
  }, [target.alertId, target.caseId]);

  useEffect(() => {
    load();
  }, [load]);

  const submit = async () => {
    if (!draft.trim()) return;
    try {
      setSubmitting(true);
      await apiService.addComment(target, draft.trim());
      setDraft('');
      await load();
      onToast?.('Comment added', 'success');
    } catch (e) {
      onError('Failed to add comment');
    } finally {
      setSubmitting(false);
    }
  };

  const loadMore = async () => {
    if (!nextCursor) return;
    try {
      setLoadingMore(true);
      const res = await apiService.fetchComments(target, nextCursor);
      setComments((current) => [...current, ...(res.comments || [])]);
      setNextCursor(res.nextCursor);
      setTotal(res.total);
      onCountChanged?.(res.total || 0);
    } catch (e) {
      onError('Failed to load more comments');
    } finally {
      setLoadingMore(false);
    }
  };

  if (loading) return <EuiLoadingSpinner size="m" />;

  return (
    <div className="wamCommentsThread" data-test-subj="wamCommentsThread">
      {comments.length === 0 ? (
        <EuiText size="s" color="subdued" data-test-subj="wamCommentsEmpty">
          No comments yet.
        </EuiText>
      ) : (
        <ol className="wamHistoryList" data-test-subj="wamCommentsList">
          {comments.map((c) => (
            <li key={c.id} className="wamHistoryRow" data-test-subj="wamCommentRow">
              <span className="wamHistoryRow__time" title={c.created_at}>
                {formatAbsolute(c.created_at)}
              </span>
              <div className="wamHistoryRow__body">
                <EuiText size="s" className="wamHistoryRow__event">
                  <span className="wamHistoryRow__actor">{c.author}</span> <span className="wamHistoryRow__action">commented</span>
                </EuiText>
                <EuiText size="s" className="wamHistoryRow__details wamCommentText">
                  {c.text}
                </EuiText>
              </div>
            </li>
          ))}
        </ol>
      )}
      {nextCursor && (
        <>
          <EuiSpacer size="s" />
          <EuiButtonEmpty size="s" flush="left" onClick={loadMore} isLoading={loadingMore}>
            Load more comments ({comments.length} of {total})
          </EuiButtonEmpty>
        </>
      )}
      <EuiSpacer size="m" />
      <EuiTextArea
        fullWidth
        compressed
        placeholder="Add a comment..."
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        rows={3}
        aria-label="New comment"
      />
      <EuiSpacer size="s" />
      <EuiFlexGroup justifyContent="flexEnd" gutterSize="s" responsive={false}>
        <EuiFlexItem grow={false}>
          <EuiButton size="s" onClick={submit} isLoading={submitting} isDisabled={!draft.trim()}>
            Add comment
          </EuiButton>
        </EuiFlexItem>
      </EuiFlexGroup>
    </div>
  );
};
