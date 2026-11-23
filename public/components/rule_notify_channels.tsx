import React from 'react';
import { EuiComboBox, EuiFormRow, EuiLink, EuiText } from '@elastic/eui';
import { RULE_NOTIFY_MAX_CHANNELS } from '../../common';

/**
 * "Notify channels" control of the rule editor (step 1.4): a multi-select over
 * the channels bound in Settings > Notifications (`GET /notifications/settings`,
 * the redacted summary every signed-in user receives is enough). A selected id
 * that is no longer in the list stays visible as "(missing)" so the save can
 * name it; a disabled channel is selectable and labelled, execution skips it.
 */

export interface NotifyChannelOption {
  id: string;
  name: string;
  kind: string;
  enabled: boolean;
}

export type NotifyChannelsState = 'loading' | 'ready' | 'error';

interface Props {
  channels: NotifyChannelOption[];
  state: NotifyChannelsState;
  selected: string[];
  onChange: (channelIds: string[]) => void;
  disabled?: boolean;
}

/** Same app, Settings tab, Notifications sub-tab (`settings_view.tsx` reads `settingsTab` on mount). */
export const notificationsSettingsHref = (): string => `${window.location.pathname}?tab=settings&settingsTab=notifications`;

interface ChannelOption {
  label: string;
  value: string;
}

export const RuleNotifyChannels: React.FC<Props> = ({ channels, state, selected, onChange, disabled }) => {
  const options: ChannelOption[] = channels.map((channel) => ({
    label: `${channel.name}${channel.enabled ? '' : ' (disabled)'}`,
    value: channel.id,
  }));
  const selectedOptions: ChannelOption[] = selected.map(
    (id) => options.find((option) => option.value === id) || { label: `${id} (missing)`, value: id }
  );
  const tooMany = selected.length > RULE_NOTIFY_MAX_CHANNELS;
  const empty = state === 'ready' && !channels.length && !selected.length;
  const helpText =
    state === 'error'
      ? 'The channel list could not be loaded; the ids you keep are checked when you save.'
      : `Each alert this rule fires on is sent as a rule.action notification to these channels (at most ${RULE_NOTIFY_MAX_CHANNELS}). Combine with the other actions or use it alone.`;
  return (
    <EuiFormRow
      fullWidth
      label="Notify channels"
      helpText={empty ? undefined : helpText}
      isInvalid={tooMany}
      error={tooMany ? `Select at most ${RULE_NOTIFY_MAX_CHANNELS} channels.` : undefined}
    >
      {empty ? (
        <EuiText size="s" color="subdued" data-test-subj="wamRuleNotifyEmpty">
          <p>
            No notification channels configured.{' '}
            <EuiLink href={notificationsSettingsHref()} data-test-subj="wamRuleNotifySettingsLink">Open Settings &gt; Notifications</EuiLink> to bind one.
          </p>
        </EuiText>
      ) : (
        <EuiComboBox<string>
          fullWidth
          data-test-subj="wamRuleNotifyChannels"
          placeholder="No notification"
          options={options}
          selectedOptions={selectedOptions}
          onChange={(next) => onChange(next.map((option) => String(option.value)))}
          isLoading={state === 'loading'}
          isDisabled={disabled}
          isClearable
        />
      )}
    </EuiFormRow>
  );
};
