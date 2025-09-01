import React, { useState, useEffect } from 'react';
import {
  EuiPage,
  EuiPageBody,
  EuiPageContent,
  EuiPageContentBody,
  EuiPageHeader,
  EuiTitle,
  EuiBasicTable,
  EuiHealth,
  EuiSelect,
  EuiButton,
  EuiSpacer,
  EuiLoadingSpinner,
  EuiEmptyPrompt,
  EuiGlobalToastList,
  EuiGlobalToastListToast,
  CriteriaWithPagination,
  EuiFlyout,
  EuiFlyoutBody,
  EuiFlyoutHeader,
  EuiTitle as EuiFlyoutTitle,
  EuiDescriptionList,
  EuiDescriptionListTitle,
  EuiDescriptionListDescription,
  EuiCodeBlock,
  EuiTabbedContent,
  EuiText,
  EuiPanel,
  EuiAccordion,
  EuiFlexGroup,
  EuiFlexItem,
  EuiSearchBar,
  EuiDatePickerRange,
  EuiDatePicker,
  EuiPopover,
  EuiStat,
  EuiHorizontalRule,
} from '@elastic/eui';
import { CoreStart } from '../../../../src/core/public';
import { DataPublicPluginStart } from '../../../../src/plugins/data/public';
import { Alert } from '../types';
import { AlertsApiService } from '../services/api';

interface AppProps {
  coreStart: CoreStart;
  dataStart: DataPublicPluginStart;
  basename: string;
}

interface TimeRange {
  from: string;
  to: string;
  mode?: 'absolute' | 'relative';
}

interface AlertCounts {
  open: number;
  inProgress: number;
  closed: number;
  total: number;
}

export const WazuhAlertManagerApp: React.FC<AppProps> = ({ coreStart, dataStart }) => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [totalAlerts, setTotalAlerts] = useState(0);
  const [alertCounts, setAlertCounts] = useState<AlertCounts>({
    open: 0,
    inProgress: 0,
    closed: 0,
    total: 0
  });
  const [loading, setLoading] = useState(true);
  const [loadingCounts, setLoadingCounts] = useState(true);
  const [updating, setUpdating] = useState<string | null>(null);
  const [toasts, setToasts] = useState<EuiGlobalToastListToast[]>([]);
  const [sortField, setSortField] = useState<keyof Alert>('_id');
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('desc');
  const [pageIndex, setPageIndex] = useState(0);
  const [pageSize, setPageSize] = useState(20);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [isFlyoutVisible, setIsFlyoutVisible] = useState(false);
  const [query, setQuery] = useState<string>('');
  const [timeRange, setTimeRange] = useState<TimeRange>({
    from: 'now-24h',
    to: 'now',
    mode: 'relative'
  });
  const [isTimeRangePopoverOpen, setIsTimeRangePopoverOpen] = useState(false);
  const [customTimeRange, setCustomTimeRange] = useState<{
    start: moment.Moment | null;
    end: moment.Moment | null;
  }>({
    start: null,
    end: null
  });

  const addToast = (toast: Omit<EuiGlobalToastListToast, 'id'>) => {
    const newToast: EuiGlobalToastListToast = {
      ...toast,
      id: Math.random().toString(),
    };
    setToasts([...toasts, newToast]);
  };

  const removeToast = (toast: EuiGlobalToastListToast) => {
    setToasts(toasts.filter(t => t.id !== toast.id));
  };

  const apiService = new AlertsApiService(coreStart.http);

  const buildQuery = () => {
    let luceneQuery = query;

    // Add timestamp filter based on time range
    if (timeRange.mode === 'absolute' && timeRange.from && timeRange.to) {
      // For absolute time ranges, use ISO string format
      const fromDate = new Date(timeRange.from).toISOString();
      const toDate = new Date(timeRange.to).toISOString();
      const timestampFilter = `@timestamp:["${fromDate}" TO "${toDate}"]`;
      luceneQuery = luceneQuery ? `(${luceneQuery}) AND ${timestampFilter}` : timestampFilter;
    } else if (timeRange.mode === 'relative' && timeRange.from && timeRange.to) {
      // For relative time ranges, use the raw values (like "now-24h")
      const timestampFilter = `@timestamp:[${timeRange.from} TO ${timeRange.to}]`;
      luceneQuery = luceneQuery ? `(${luceneQuery}) AND ${timestampFilter}` : timestampFilter;
    }

    return luceneQuery || undefined;
  };

  const fetchAlertCounts = async () => {
    try {
      setLoadingCounts(true);
      const luceneQuery = buildQuery();

      const response = await apiService.fetchAlertCounts(luceneQuery);
      if (response?.aggregations) {
        const counts = response.aggregations.status_counts.buckets.reduce((acc: any, bucket: any) => {
          acc[bucket.key] = bucket.doc_count;
          return acc;
        }, { open: 0, 'in progress': 0, closed: 0 });

        setAlertCounts({
          open: counts.open || 0,
          inProgress: counts['in progress'] || 0,
          closed: counts.closed || 0,
          total: response.hits.total?.value || 0
        });
      }
    } catch (error) {
      console.error('Error fetching alert counts:', error);
    } finally {
      setLoadingCounts(false);
    }
  };

  const fetchAlerts = async () => {
    try {
      setLoading(true);
      const luceneQuery = buildQuery();
      const from = pageIndex * pageSize;

      const response = await apiService.fetchAlerts(luceneQuery, from, pageSize);
      if (response?.hits) {
        setAlerts(response.hits.hits);
        setTotalAlerts(response.hits.total?.value || 0);
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to fetch alerts';
      addToast({
        title: 'Error fetching alerts',
        color: 'danger',
        text: errorMessage
      });
    } finally {
      setLoading(false);
    }
  };

  const updateAlertStatus = async (alertId: string, newStatus: string) => {
    try {
      setUpdating(alertId);
      await apiService.updateAlertStatus(alertId, newStatus);

      // Update local state
      setAlerts(alerts.map(alert =>
        alert._id === alertId
          ? { ...alert, _source: { ...alert._source, status: newStatus as 'open' | 'in progress' | 'closed' } }
          : alert
      ));

      // Update selected alert if it's the one being updated
      if (selectedAlert && selectedAlert._id === alertId) {
        setSelectedAlert({
          ...selectedAlert,
          _source: {
            ...selectedAlert._source,
            status: newStatus as 'open' | 'in progress' | 'closed'
          }
        });
      }

      // Refresh counts after status update
      fetchAlertCounts();

      addToast({
        title: 'Status updated successfully',
        color: 'success',
      });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to update alert status';
      addToast({
        title: 'Error updating status',
        color: 'danger',
        text: errorMessage
      });
    } finally {
      setUpdating(null);
    }
  };

  const onTableChange = (criteria: CriteriaWithPagination<Alert>) => {
    const { sort, page } = criteria;

    if (sort) {
      setSortField(sort.field);
      setSortDirection(sort.direction);
      setPageIndex(0); // Reset to first page when sorting changes
    }

    if (page) {
      setPageIndex(page.index);
      setPageSize(page.size);
    }
  };

  const showAlertDetails = (alert: Alert) => {
    setSelectedAlert(alert);
    setIsFlyoutVisible(true);
  };

  const closeFlyout = () => {
    setIsFlyoutVisible(false);
    setSelectedAlert(null);
  };

  const handleQueryChange = (searchText: string) => {
    setQuery(searchText);
  };

  const handleQuerySearch = () => {
    setPageIndex(0); // Reset to first page when search changes
    fetchData();
  };

  const handleTimeRangeChange = (newTimeRange: TimeRange) => {
    setTimeRange(newTimeRange);
    setIsTimeRangePopoverOpen(false);
    setPageIndex(0); // Reset to first page when time range changes
    fetchData();
  };

  const handleCustomTimeRangeApply = () => {
    if (customTimeRange.start && customTimeRange.end) {
      handleTimeRangeChange({
        from: customTimeRange.start.toISOString(),
        to: customTimeRange.end.toISOString(),
        mode: 'absolute'
      });
    }
  };

  const fetchData = () => {
    fetchAlertCounts();
    fetchAlerts();
  };

  const quickTimeRanges = [
    { start: 'now-15m', end: 'now', label: 'Last 15 minutes' },
    { start: 'now-30m', end: 'now', label: 'Last 30 minutes' },
    { start: 'now-1h', end: 'now', label: 'Last 1 hour' },
    { start: 'now-24h', end: 'now', label: 'Last 24 hours' },
    { start: 'now-7d', end: 'now', label: 'Last 7 days' },
    { start: 'now-30d', end: 'now', label: 'Last 30 days' },
  ];

  const formatTimeRangeDisplay = () => {
    if (timeRange.mode === 'absolute') {
      return `${new Date(timeRange.from).toLocaleString()} - ${new Date(timeRange.to).toLocaleString()}`;
    }

    const range = quickTimeRanges.find(r => r.start === timeRange.from && r.end === timeRange.to);
    return range ? range.label : `${timeRange.from} to ${timeRange.to}`;
  };

  useEffect(() => {
    fetchData();
  }, [pageIndex, pageSize]);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'open': return 'danger';
      case 'in progress': return 'warning';
      case 'closed': return 'success';
      default: return 'subdued';
    }
  };

  const statusOptions = [
    { value: 'open', text: 'Open' },
    { value: 'in progress', text: 'In Progress' },
    { value: 'closed', text: 'Closed' },
  ];

  // Add the alert summary boxes component
  const AlertSummaryBoxes = () => (
    <EuiFlexGroup gutterSize="m">
      <EuiFlexItem>
        <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
          <EuiStat
            title={loadingCounts ? <EuiLoadingSpinner size="m" /> : alertCounts.open}
            description="Open Alerts"
            titleColor="danger"
            isLoading={loadingCounts}
          />
        </EuiPanel>
      </EuiFlexItem>
      <EuiFlexItem>
        <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
          <EuiStat
            title={loadingCounts ? <EuiLoadingSpinner size="m" /> : alertCounts.inProgress}
            description="In Progress"
            titleColor="warning"
            isLoading={loadingCounts}
          />
        </EuiPanel>
      </EuiFlexItem>
      <EuiFlexItem>
        <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
          <EuiStat
            title={loadingCounts ? <EuiLoadingSpinner size="m" /> : alertCounts.closed}
            description="Closed"
            titleColor="success"
            isLoading={loadingCounts}
          />
        </EuiPanel>
      </EuiFlexItem>
      <EuiFlexItem>
        <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
          <EuiStat
            title={loadingCounts ? <EuiLoadingSpinner size="m" /> : alertCounts.total}
            description="Total Alerts"
            isLoading={loadingCounts}
          />
        </EuiPanel>
      </EuiFlexItem>
    </EuiFlexGroup>
  );

  const columns = [
    {
      field: '_source',
      name: 'Timestamp',
      sortable: true,
      render: (value: Alert['_source'], alert: Alert) => new Date(alert._source['@timestamp']).toLocaleString(),
    },
    {
      field: '_source',
      name: 'Agent',
      sortable: true,
      render: (value: Alert['_source'], alert: Alert) => alert._source.agent?.name || 'N/A',
    },
    {
      field: '_source',
      name: 'Agent IP',
      sortable: true,
      render: (value: Alert['_source'], alert: Alert) => alert._source.agent?.ip || 'N/A',
    },
    {
      field: '_source',
      name: 'Rule Description',
      sortable: true,
      render: (value: Alert['_source'], alert: Alert) => alert._source.rule?.description || 'N/A',
    },
    {
      field: '_source',
      name: 'Level',
      sortable: true,
      render: (value: Alert['_source'], alert: Alert) => {
        const level = alert._source.rule?.level || 0;
        return (
          <EuiHealth color={level >= 7 ? 'danger' : level >= 5 ? 'warning' : 'success'}>
            {level}
          </EuiHealth>
        );
      },
    },
    {
      field: '_source',
      name: 'Status',
      sortable: true,
      render: (value: Alert['_source'], alert: Alert) => (
        <EuiHealth color={getStatusColor(alert._source.status)}>
          {alert._source.status}
        </EuiHealth>
      ),
    },
    {
      name: 'Actions',
      actions: [
        {
          render: (alert: Alert) => (
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
              <EuiSelect
                options={statusOptions}
                value={alert._source.status}
                onChange={(e) => updateAlertStatus(alert._id, e.target.value)}
                disabled={updating === alert._id}
                compressed
              />
              {updating === alert._id && <EuiLoadingSpinner size="s" />}
            </div>
          ),
        },
      ],
    },
  ];

  const sorting = {
    sort: {
      field: sortField,
      direction: sortDirection,
    },
  };

  const pagination = {
    pageIndex,
    pageSize,
    totalItemCount: totalAlerts,
    pageSizeOptions: [10, 20, 50, 100],
  };

  // Helper function to render nested objects dynamically
  const renderNestedObject = (obj: any, depth = 0) => {
    if (obj === null || obj === undefined) return null;

    if (typeof obj === 'object') {
      return (
        <EuiPanel paddingSize="s" hasShadow={false} style={{ margin: '5px 0' }}>
          {Object.entries(obj).map(([key, value]) => (
            <div key={key} style={{ marginLeft: depth > 0 ? '15px' : '0' }}>
              <EuiText size="s">
                <strong>{key}:</strong>
              </EuiText>
              {typeof value === 'object' ? (
                renderNestedObject(value, depth + 1)
              ) : (
                <EuiText size="s" style={{ marginLeft: '10px' }}>
                  {String(value)}
                </EuiText>
              )}
            </div>
          ))}
        </EuiPanel>
      );
    }

    return <EuiText size="s">{String(obj)}</EuiText>;
  };

  const alertFlyout = selectedAlert && (
    <EuiFlyout
      onClose={closeFlyout}
      size="m"
      aria-labelledby="alert-details-flyout"
    >
      <EuiFlyoutHeader hasBorder>
        <EuiFlyoutTitle>
          <h2>Alert Details</h2>
        </EuiFlyoutTitle>
      </EuiFlyoutHeader>
      <EuiFlyoutBody>
        <EuiTabbedContent
          tabs={[
            {
              id: 'overview',
              name: 'Overview',
              content: (
                <div>
                  <EuiDescriptionList type="column" compressed>
                    <EuiDescriptionListTitle>Alert ID</EuiDescriptionListTitle>
                    <EuiDescriptionListDescription>{selectedAlert._id}</EuiDescriptionListDescription>

                    <EuiDescriptionListTitle>Timestamp</EuiDescriptionListTitle>
                    <EuiDescriptionListDescription>
                      {new Date(selectedAlert._source['@timestamp']).toLocaleString()}
                    </EuiDescriptionListDescription>

                    <EuiDescriptionListTitle>Status</EuiDescriptionListTitle>
                    <EuiDescriptionListDescription>
                      <EuiHealth color={getStatusColor(selectedAlert._source.status)}>
                        {selectedAlert._source.status}
                      </EuiHealth>
                    </EuiDescriptionListDescription>

                    <EuiDescriptionListTitle>Agent</EuiDescriptionListTitle>
                    <EuiDescriptionListDescription>
                      {selectedAlert._source.agent?.name} ({selectedAlert._source.agent?.ip})
                    </EuiDescriptionListDescription>

                    <EuiDescriptionListTitle>Rule</EuiDescriptionListTitle>
                    <EuiDescriptionListDescription>
                      {selectedAlert._source.rule?.description} (Level {selectedAlert._source.rule?.level})
                    </EuiDescriptionListDescription>

                    <EuiDescriptionListTitle>Manager</EuiDescriptionListTitle>
                    <EuiDescriptionListDescription>
                      {selectedAlert._source.manager?.name}
                    </EuiDescriptionListDescription>
                  </EuiDescriptionList>

                  <EuiSpacer size="l" />

                  <EuiSelect
                    options={statusOptions}
                    value={selectedAlert._source.status}
                    onChange={(e) => updateAlertStatus(selectedAlert._id, e.target.value)}
                    disabled={updating === selectedAlert._id}
                    fullWidth
                  />
                  {updating === selectedAlert._id && <EuiLoadingSpinner size="s" />}
                </div>
              ),
            },
            {
              id: 'details',
              name: 'Detailed Data',
              content: (
                <div>
                  {Object.entries(selectedAlert._source).map(([key, value]) => (
                    <EuiAccordion
                      key={key}
                      id={key}
                      buttonContent={key}
                      paddingSize="m"
                    >
                      {typeof value === 'object' ? (
                        renderNestedObject(value)
                      ) : (
                        <EuiCodeBlock language="json" fontSize="m" paddingSize="s">
                          {JSON.stringify(value, null, 2)}
                        </EuiCodeBlock>
                      )}
                    </EuiAccordion>
                  ))}
                </div>
              ),
            },
            {
              id: 'raw',
              name: 'Raw JSON',
              content: (
                <EuiCodeBlock language="json" isCopyable>
                  {JSON.stringify(selectedAlert, null, 2)}
                </EuiCodeBlock>
              ),
            },
          ]}
        />
      </EuiFlyoutBody>
    </EuiFlyout>
  );

  if (loading && alerts.length === 0) {
    return (
      <EuiPage>
        <EuiPageBody>
          <EuiPageContent verticalPosition="center" horizontalPosition="center">
            <EuiLoadingSpinner size="xl" />
          </EuiPageContent>
        </EuiPageBody>
      </EuiPage>
    );
  }

  return (
    <>
      <EuiPage>
        <EuiPageBody>
          <EuiPageHeader>
            <EuiTitle size="l">
              <h1>Wazuh Alert Manager</h1>
            </EuiTitle>
          </EuiPageHeader>

          <EuiPageContent>
            <EuiPageContentBody>
              {/* Alert Summary Boxes */}
              <AlertSummaryBoxes />
              <EuiSpacer size="l" />
              <EuiHorizontalRule />
              <EuiSpacer size="l" />

              {/* Filter Bar */}
              <EuiFlexGroup gutterSize="s" alignItems="center">
                <EuiFlexItem>
                  <EuiSearchBar
                    query={query}
                    onChange={({ queryText }) => handleQueryChange(queryText || '')}
                    box={{
                      placeholder: 'Search alerts (Lucene syntax)',
                      incremental: false,
                    }}
                  />
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiButton
                    onClick={handleQuerySearch}
                    iconType="search"
                  >
                    Search
                  </EuiButton>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiPopover
                    button={
                      <EuiButton
                        iconType="arrowDown"
                        iconSide="right"
                        onClick={() => setIsTimeRangePopoverOpen(!isTimeRangePopoverOpen)}
                      >
                        {formatTimeRangeDisplay()}
                      </EuiButton>
                    }
                    isOpen={isTimeRangePopoverOpen}
                    closePopover={() => setIsTimeRangePopoverOpen(false)}
                    panelPaddingSize="m"
                  >
                    <div style={{ width: 300 }}>
                      <EuiText size="s">
                        <h4>Quick Time Ranges</h4>
                      </EuiText>
                      <EuiSpacer size="s" />
                      {quickTimeRanges.map((range) => (
                        <EuiButton
                          key={range.label}
                          size="s"
                          fullWidth
                          onClick={() => handleTimeRangeChange({
                            from: range.start,
                            to: range.end,
                            mode: 'relative'
                          })}
                          style={{ marginBottom: '4px', justifyContent: 'flex-start' }}
                        >
                          {range.label}
                        </EuiButton>
                      ))}

                      <EuiSpacer size="m" />
                      <EuiText size="s">
                        <h4>Custom Time Range</h4>
                      </EuiText>
                      <EuiSpacer size="s" />

                      <EuiDatePickerRange
                        startDateControl={
                          <EuiDatePicker
                            selected={customTimeRange.start}
                            onChange={(date) => setCustomTimeRange({ ...customTimeRange, start: date })}
                            placeholder="Start date"
                            showTimeSelect
                          />
                        }
                        endDateControl={
                          <EuiDatePicker
                            selected={customTimeRange.end}
                            onChange={(date) => setCustomTimeRange({ ...customTimeRange, end: date })}
                            placeholder="End date"
                            showTimeSelect
                          />
                        }
                      />

                      <EuiSpacer size="s" />
                      <EuiButton
                        size="s"
                        fullWidth
                        onClick={handleCustomTimeRangeApply}
                        disabled={!customTimeRange.start || !customTimeRange.end}
                      >
                        Apply Custom Range
                      </EuiButton>
                    </div>
                  </EuiPopover>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiButton
                    onClick={fetchData}
                    iconType="refresh"
                    isLoading={loading || loadingCounts}
                  >
                    Refresh
                  </EuiButton>
                </EuiFlexItem>
              </EuiFlexGroup>

              <EuiSpacer />

              {alerts.length === 0 ? (
                <EuiEmptyPrompt
                  title={<h2>No alerts found</h2>}
                  body={
                    <p>
                      No alerts were found matching your search criteria.
                      {query && ` Query: ${query}`}
                    </p>
                  }
                />
              ) : (
                <>
                  <EuiText size="s" color="subdued">
                    Showing {pageIndex * pageSize + 1}-{Math.min((pageIndex + 1) * pageSize, totalAlerts)} of {totalAlerts} alerts {query && `matching "${query}"`}
                  </EuiText>
                  <EuiSpacer size="s" />
                  <EuiBasicTable<Alert>
                    items={alerts}
                    columns={columns}
                    sorting={sorting}
                    pagination={pagination}
                    onChange={onTableChange}
                    rowProps={(alert) => ({
                      onClick: () => showAlertDetails(alert),
                      style: { cursor: 'pointer' }
                    })}
                  />
                </>
              )}
            </EuiPageContentBody>
          </EuiPageContent>
        </EuiPageBody>
      </EuiPage>

      {isFlyoutVisible && alertFlyout}

      <EuiGlobalToastList
        toasts={toasts}
        dismissToast={removeToast}
        toastLifeTimeMs={6000}
      />
    </>
  );
};