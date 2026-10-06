import React, { useState, useEffect, useCallback } from 'react';
import { EuiCommentList, EuiComment, EuiTextArea, EuiButton, EuiSpacer, EuiLoadingSpinner, EuiText } from '@elastic/eui';
import { Comment } from '../../common';
import { AlertsApiService } from '../services/api';

interface Props {
  apiService: AlertsApiService;
  target: { alertId?: string; caseId?: string };
  onError: (message: string) => void;
  onToast?: (title: string, color: 'success' | 'danger' | 'primary', text?: string) => void;
}

export const CommentsThread: React.FC<Props> = ({ apiService, target, onError, onToast }) => {
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
    } catch (e) {
      onError('Failed to load more comments');
    } finally {
      setLoadingMore(false);
    }
  };

  if (loading) return <EuiLoadingSpinner size="m" />;

  return (
    <div>
      {comments.length === 0 ? (
        <EuiText size="s" color="subdued">
          No comments yet.
        </EuiText>
      ) : (
        <EuiCommentList>
          {comments.map((c) => (
            <EuiComment
              key={c.id}
              username={c.author}
              timestamp={new Date(c.created_at).toLocaleString()}
              event="commented"
            >
              <EuiText size="s">{c.text}</EuiText>
            </EuiComment>
          ))}
        </EuiCommentList>
      )}
      {nextCursor && (
        <>
          <EuiSpacer size="s" />
          <EuiButton size="s" onClick={loadMore} isLoading={loadingMore}>
            Load more comments ({comments.length} of {total})
          </EuiButton>
        </>
      )}
      <EuiSpacer size="m" />
      <EuiTextArea
        fullWidth
        placeholder="Add a comment..."
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        rows={3}
      />
      <EuiSpacer size="s" />
      <EuiButton size="s" onClick={submit} isLoading={submitting} isDisabled={!draft.trim()}>
        Add comment
      </EuiButton>
    </div>
  );
};
