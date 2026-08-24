import React, { useState, useEffect, useCallback } from 'react';
import { EuiCommentList, EuiComment, EuiTextArea, EuiButton, EuiSpacer, EuiLoadingSpinner, EuiText } from '@elastic/eui';
import { Comment } from '../../common';
import { AlertsApiService } from '../services/api';

interface Props {
  apiService: AlertsApiService;
  target: { alertId?: string; caseId?: string };
  onError: (message: string) => void;
}

export const CommentsThread: React.FC<Props> = ({ apiService, target, onError }) => {
  const [comments, setComments] = useState<Comment[]>([]);
  const [loading, setLoading] = useState(true);
  const [draft, setDraft] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const load = useCallback(async () => {
    try {
      setLoading(true);
      const res: any = await apiService.fetchComments(target);
      setComments(res?.comments || []);
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
    } catch (e) {
      onError('Failed to add comment');
    } finally {
      setSubmitting(false);
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
              {c.text}
            </EuiComment>
          ))}
        </EuiCommentList>
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
