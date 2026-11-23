/**
 * @jest-environment jsdom
 */
import React from 'react';
import { configure, render, screen } from '@testing-library/react';
import { MetaGrid, MetaGroup, MetaRow } from './meta_grid';

configure({ testIdAttribute: 'data-test-subj' });

describe('MetaGrid (step 11.6)', () => {
  test('renders a <div> grid of role=group blocks, each one <dl> of dt/dd row wrappers, with the row / label / value classes the stylesheet draws hairlines on', () => {
    render(
      <MetaGrid data-test-subj="grid" className="wamMetaList">
        <MetaGroup title="Detection" data-test-subj="group-detection">
          <MetaRow label="Rule">File added</MetaRow>
          <MetaRow label="Level">5</MetaRow>
        </MetaGroup>
        <MetaGroup title="Record">
          <MetaRow label="Alert ID" className="wamAlertId" data-test-subj="row-id">1763632800.1234</MetaRow>
        </MetaGroup>
      </MetaGrid>
    );
    const grid = screen.getByTestId('grid');
    // Not a <dl> itself: `dl` only allows dt/dd or single-level div wrappers
    // of dt/dd, so the groups and their titles live outside the list.
    expect(grid.tagName).toBe('DIV');
    expect(grid.className).toBe('wamMetaGrid wamMetaList');
    expect(grid.className).not.toContain('wamMetaGrid--compact');
    const groups = Array.from(grid.querySelectorAll(':scope > .wamMetaGrid__group'));
    expect(groups).toHaveLength(2);
    expect(groups.map((group) => group.querySelector('.wamMetaGrid__groupTitle')!.textContent)).toEqual(['Detection', 'Record']);
    // Each group is a labelled region: role=group pointing at its title span.
    groups.forEach((group) => {
      expect(group.getAttribute('role')).toBe('group');
      const titleSpan = group.querySelector('.wamMetaGrid__groupTitle span')!;
      expect(titleSpan.id).toBeTruthy();
      expect(group.getAttribute('aria-labelledby')).toBe(titleSpan.id);
    });
    expect(groups[0].getAttribute('aria-labelledby')).not.toBe(groups[1].getAttribute('aria-labelledby'));
    // One <dl> per group right after the title; every row is a
    // `div.wamMetaGrid__row` directly under it holding one dt + one dd (the
    // wrapper form the HTML content model allows). The hairline rule is
    // `.wamMetaGrid__row + .wamMetaGrid__row`, so the first row of a group
    // has no previous sibling row and gets none.
    const detectionList = groups[0].querySelector(':scope > dl.wamMetaGrid__rows')!;
    expect(detectionList.previousElementSibling!.className).toContain('wamMetaGrid__groupTitle');
    const detectionRows = Array.from(detectionList.querySelectorAll(':scope > .wamMetaGrid__row'));
    expect(detectionRows).toHaveLength(2);
    expect(Array.from(detectionList.children)).toEqual(detectionRows);
    expect(detectionRows[0].previousElementSibling).toBeNull();
    expect(detectionRows[1].previousElementSibling).toBe(detectionRows[0]);
    detectionRows.forEach((row) => {
      expect(row.tagName).toBe('DIV');
      expect(Array.from(row.children).map((node) => node.tagName)).toEqual(['DT', 'DD']);
    });
    const labels = Array.from(grid.querySelectorAll('dt.wamMetaGrid__label')).map((node) => node.textContent);
    expect(labels).toEqual(['Rule', 'Level', 'Alert ID']);
    const values = Array.from(grid.querySelectorAll('dd.wamMetaGrid__value')).map((node) => node.textContent);
    expect(values).toEqual(['File added', '5', '1763632800.1234']);
    // Labels are xs subdued text, values small text (nothing larger).
    expect(grid.querySelector('dt .euiText')!.className).toContain('euiText--extraSmall');
    expect(grid.querySelector('dd .euiText')!.className).toContain('euiText--small');
  });

  test('subjects and classes pass through to the group and to the value cell, where the row content is read; an untitled group has no label', () => {
    render(
      <MetaGrid data-test-subj="grid">
        <MetaGroup data-test-subj="group">
          <MetaRow label="Closure reason" className="wamClosureReason" data-test-subj="reason">Known scanner</MetaRow>
        </MetaGroup>
      </MetaGrid>
    );
    const group = screen.getByTestId('group');
    expect(group.className).toBe('wamMetaGrid__group');
    expect(group.getAttribute('role')).toBe('group');
    expect(group.getAttribute('aria-labelledby')).toBeNull();
    expect(group.querySelector('.wamMetaGrid__groupTitle')).toBeNull();
    expect(group.firstElementChild!.tagName).toBe('DL');
    const value = screen.getByTestId('reason');
    expect(value.tagName).toBe('DD');
    expect(value.className).toBe('wamMetaGrid__value wamClosureReason');
    expect(value.textContent).toBe('Known scanner');
  });

  test('compact adds its modifier and labelWidth writes the --wamMetaLabelWidth variable inline', () => {
    const { container } = render(
      <MetaGrid compact labelWidth={120}>
        <MetaGroup><MetaRow label="Rule">x</MetaRow></MetaGroup>
      </MetaGrid>
    );
    const grid = container.querySelector('.wamMetaGrid')!;
    expect(grid.className).toBe('wamMetaGrid wamMetaGrid--compact');
    expect(grid.getAttribute('style')).toContain('--wamMetaLabelWidth: 120px');
    // Without the prop the width comes from the stylesheet (per flyout), not inline.
    const { container: plain } = render(<MetaGrid><MetaGroup><MetaRow label="Rule">x</MetaRow></MetaGroup></MetaGrid>);
    expect(plain.querySelector('.wamMetaGrid')!.getAttribute('style')).toBeNull();
  });
});
