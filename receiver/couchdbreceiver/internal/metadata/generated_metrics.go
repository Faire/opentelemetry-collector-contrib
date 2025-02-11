// Code generated by mdatagen. DO NOT EDIT.

package metadata

import (
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/filter"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver"
)

// AttributeHTTPMethod specifies the value http.method attribute.
type AttributeHTTPMethod int

const (
	_ AttributeHTTPMethod = iota
	AttributeHTTPMethodCOPY
	AttributeHTTPMethodDELETE
	AttributeHTTPMethodGET
	AttributeHTTPMethodHEAD
	AttributeHTTPMethodOPTIONS
	AttributeHTTPMethodPOST
	AttributeHTTPMethodPUT
)

// String returns the string representation of the AttributeHTTPMethod.
func (av AttributeHTTPMethod) String() string {
	switch av {
	case AttributeHTTPMethodCOPY:
		return "COPY"
	case AttributeHTTPMethodDELETE:
		return "DELETE"
	case AttributeHTTPMethodGET:
		return "GET"
	case AttributeHTTPMethodHEAD:
		return "HEAD"
	case AttributeHTTPMethodOPTIONS:
		return "OPTIONS"
	case AttributeHTTPMethodPOST:
		return "POST"
	case AttributeHTTPMethodPUT:
		return "PUT"
	}
	return ""
}

// MapAttributeHTTPMethod is a helper map of string to AttributeHTTPMethod attribute value.
var MapAttributeHTTPMethod = map[string]AttributeHTTPMethod{
	"COPY":    AttributeHTTPMethodCOPY,
	"DELETE":  AttributeHTTPMethodDELETE,
	"GET":     AttributeHTTPMethodGET,
	"HEAD":    AttributeHTTPMethodHEAD,
	"OPTIONS": AttributeHTTPMethodOPTIONS,
	"POST":    AttributeHTTPMethodPOST,
	"PUT":     AttributeHTTPMethodPUT,
}

// AttributeOperation specifies the value operation attribute.
type AttributeOperation int

const (
	_ AttributeOperation = iota
	AttributeOperationWrites
	AttributeOperationReads
)

// String returns the string representation of the AttributeOperation.
func (av AttributeOperation) String() string {
	switch av {
	case AttributeOperationWrites:
		return "writes"
	case AttributeOperationReads:
		return "reads"
	}
	return ""
}

// MapAttributeOperation is a helper map of string to AttributeOperation attribute value.
var MapAttributeOperation = map[string]AttributeOperation{
	"writes": AttributeOperationWrites,
	"reads":  AttributeOperationReads,
}

// AttributeView specifies the value view attribute.
type AttributeView int

const (
	_ AttributeView = iota
	AttributeViewTemporaryViewReads
	AttributeViewViewReads
)

// String returns the string representation of the AttributeView.
func (av AttributeView) String() string {
	switch av {
	case AttributeViewTemporaryViewReads:
		return "temporary_view_reads"
	case AttributeViewViewReads:
		return "view_reads"
	}
	return ""
}

// MapAttributeView is a helper map of string to AttributeView attribute value.
var MapAttributeView = map[string]AttributeView{
	"temporary_view_reads": AttributeViewTemporaryViewReads,
	"view_reads":           AttributeViewViewReads,
}

type metricCouchdbAverageRequestTime struct {
	data     pmetric.Metric // data buffer for generated metric.
	config   MetricConfig   // metric config provided by user.
	capacity int            // max observed number of data points added to the metric.
}

// init fills couchdb.average_request_time metric with initial data.
func (m *metricCouchdbAverageRequestTime) init() {
	m.data.SetName("couchdb.average_request_time")
	m.data.SetDescription("The average duration of a served request.")
	m.data.SetUnit("ms")
	m.data.SetEmptyGauge()
}

func (m *metricCouchdbAverageRequestTime) recordDataPoint(start pcommon.Timestamp, ts pcommon.Timestamp, val float64) {
	if !m.config.Enabled {
		return
	}
	dp := m.data.Gauge().DataPoints().AppendEmpty()
	dp.SetStartTimestamp(start)
	dp.SetTimestamp(ts)
	dp.SetDoubleValue(val)
}

// updateCapacity saves max length of data point slices that will be used for the slice capacity.
func (m *metricCouchdbAverageRequestTime) updateCapacity() {
	if m.data.Gauge().DataPoints().Len() > m.capacity {
		m.capacity = m.data.Gauge().DataPoints().Len()
	}
}

// emit appends recorded metric data to a metrics slice and prepares it for recording another set of data points.
func (m *metricCouchdbAverageRequestTime) emit(metrics pmetric.MetricSlice) {
	if m.config.Enabled && m.data.Gauge().DataPoints().Len() > 0 {
		m.updateCapacity()
		m.data.MoveTo(metrics.AppendEmpty())
		m.init()
	}
}

func newMetricCouchdbAverageRequestTime(cfg MetricConfig) metricCouchdbAverageRequestTime {
	m := metricCouchdbAverageRequestTime{config: cfg}
	if cfg.Enabled {
		m.data = pmetric.NewMetric()
		m.init()
	}
	return m
}

type metricCouchdbDatabaseOpen struct {
	data     pmetric.Metric // data buffer for generated metric.
	config   MetricConfig   // metric config provided by user.
	capacity int            // max observed number of data points added to the metric.
}

// init fills couchdb.database.open metric with initial data.
func (m *metricCouchdbDatabaseOpen) init() {
	m.data.SetName("couchdb.database.open")
	m.data.SetDescription("The number of open databases.")
	m.data.SetUnit("{databases}")
	m.data.SetEmptySum()
	m.data.Sum().SetIsMonotonic(false)
	m.data.Sum().SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
}

func (m *metricCouchdbDatabaseOpen) recordDataPoint(start pcommon.Timestamp, ts pcommon.Timestamp, val int64) {
	if !m.config.Enabled {
		return
	}
	dp := m.data.Sum().DataPoints().AppendEmpty()
	dp.SetStartTimestamp(start)
	dp.SetTimestamp(ts)
	dp.SetIntValue(val)
}

// updateCapacity saves max length of data point slices that will be used for the slice capacity.
func (m *metricCouchdbDatabaseOpen) updateCapacity() {
	if m.data.Sum().DataPoints().Len() > m.capacity {
		m.capacity = m.data.Sum().DataPoints().Len()
	}
}

// emit appends recorded metric data to a metrics slice and prepares it for recording another set of data points.
func (m *metricCouchdbDatabaseOpen) emit(metrics pmetric.MetricSlice) {
	if m.config.Enabled && m.data.Sum().DataPoints().Len() > 0 {
		m.updateCapacity()
		m.data.MoveTo(metrics.AppendEmpty())
		m.init()
	}
}

func newMetricCouchdbDatabaseOpen(cfg MetricConfig) metricCouchdbDatabaseOpen {
	m := metricCouchdbDatabaseOpen{config: cfg}
	if cfg.Enabled {
		m.data = pmetric.NewMetric()
		m.init()
	}
	return m
}

type metricCouchdbDatabaseOperations struct {
	data     pmetric.Metric // data buffer for generated metric.
	config   MetricConfig   // metric config provided by user.
	capacity int            // max observed number of data points added to the metric.
}

// init fills couchdb.database.operations metric with initial data.
func (m *metricCouchdbDatabaseOperations) init() {
	m.data.SetName("couchdb.database.operations")
	m.data.SetDescription("The number of database operations.")
	m.data.SetUnit("{operations}")
	m.data.SetEmptySum()
	m.data.Sum().SetIsMonotonic(true)
	m.data.Sum().SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
	m.data.Sum().DataPoints().EnsureCapacity(m.capacity)
}

func (m *metricCouchdbDatabaseOperations) recordDataPoint(start pcommon.Timestamp, ts pcommon.Timestamp, val int64, operationAttributeValue string) {
	if !m.config.Enabled {
		return
	}
	dp := m.data.Sum().DataPoints().AppendEmpty()
	dp.SetStartTimestamp(start)
	dp.SetTimestamp(ts)
	dp.SetIntValue(val)
	dp.Attributes().PutStr("operation", operationAttributeValue)
}

// updateCapacity saves max length of data point slices that will be used for the slice capacity.
func (m *metricCouchdbDatabaseOperations) updateCapacity() {
	if m.data.Sum().DataPoints().Len() > m.capacity {
		m.capacity = m.data.Sum().DataPoints().Len()
	}
}

// emit appends recorded metric data to a metrics slice and prepares it for recording another set of data points.
func (m *metricCouchdbDatabaseOperations) emit(metrics pmetric.MetricSlice) {
	if m.config.Enabled && m.data.Sum().DataPoints().Len() > 0 {
		m.updateCapacity()
		m.data.MoveTo(metrics.AppendEmpty())
		m.init()
	}
}

func newMetricCouchdbDatabaseOperations(cfg MetricConfig) metricCouchdbDatabaseOperations {
	m := metricCouchdbDatabaseOperations{config: cfg}
	if cfg.Enabled {
		m.data = pmetric.NewMetric()
		m.init()
	}
	return m
}

type metricCouchdbFileDescriptorOpen struct {
	data     pmetric.Metric // data buffer for generated metric.
	config   MetricConfig   // metric config provided by user.
	capacity int            // max observed number of data points added to the metric.
}

// init fills couchdb.file_descriptor.open metric with initial data.
func (m *metricCouchdbFileDescriptorOpen) init() {
	m.data.SetName("couchdb.file_descriptor.open")
	m.data.SetDescription("The number of open file descriptors.")
	m.data.SetUnit("{files}")
	m.data.SetEmptySum()
	m.data.Sum().SetIsMonotonic(false)
	m.data.Sum().SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
}

func (m *metricCouchdbFileDescriptorOpen) recordDataPoint(start pcommon.Timestamp, ts pcommon.Timestamp, val int64) {
	if !m.config.Enabled {
		return
	}
	dp := m.data.Sum().DataPoints().AppendEmpty()
	dp.SetStartTimestamp(start)
	dp.SetTimestamp(ts)
	dp.SetIntValue(val)
}

// updateCapacity saves max length of data point slices that will be used for the slice capacity.
func (m *metricCouchdbFileDescriptorOpen) updateCapacity() {
	if m.data.Sum().DataPoints().Len() > m.capacity {
		m.capacity = m.data.Sum().DataPoints().Len()
	}
}

// emit appends recorded metric data to a metrics slice and prepares it for recording another set of data points.
func (m *metricCouchdbFileDescriptorOpen) emit(metrics pmetric.MetricSlice) {
	if m.config.Enabled && m.data.Sum().DataPoints().Len() > 0 {
		m.updateCapacity()
		m.data.MoveTo(metrics.AppendEmpty())
		m.init()
	}
}

func newMetricCouchdbFileDescriptorOpen(cfg MetricConfig) metricCouchdbFileDescriptorOpen {
	m := metricCouchdbFileDescriptorOpen{config: cfg}
	if cfg.Enabled {
		m.data = pmetric.NewMetric()
		m.init()
	}
	return m
}

type metricCouchdbHttpdBulkRequests struct {
	data     pmetric.Metric // data buffer for generated metric.
	config   MetricConfig   // metric config provided by user.
	capacity int            // max observed number of data points added to the metric.
}

// init fills couchdb.httpd.bulk_requests metric with initial data.
func (m *metricCouchdbHttpdBulkRequests) init() {
	m.data.SetName("couchdb.httpd.bulk_requests")
	m.data.SetDescription("The number of bulk requests.")
	m.data.SetUnit("{requests}")
	m.data.SetEmptySum()
	m.data.Sum().SetIsMonotonic(true)
	m.data.Sum().SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
}

func (m *metricCouchdbHttpdBulkRequests) recordDataPoint(start pcommon.Timestamp, ts pcommon.Timestamp, val int64) {
	if !m.config.Enabled {
		return
	}
	dp := m.data.Sum().DataPoints().AppendEmpty()
	dp.SetStartTimestamp(start)
	dp.SetTimestamp(ts)
	dp.SetIntValue(val)
}

// updateCapacity saves max length of data point slices that will be used for the slice capacity.
func (m *metricCouchdbHttpdBulkRequests) updateCapacity() {
	if m.data.Sum().DataPoints().Len() > m.capacity {
		m.capacity = m.data.Sum().DataPoints().Len()
	}
}

// emit appends recorded metric data to a metrics slice and prepares it for recording another set of data points.
func (m *metricCouchdbHttpdBulkRequests) emit(metrics pmetric.MetricSlice) {
	if m.config.Enabled && m.data.Sum().DataPoints().Len() > 0 {
		m.updateCapacity()
		m.data.MoveTo(metrics.AppendEmpty())
		m.init()
	}
}

func newMetricCouchdbHttpdBulkRequests(cfg MetricConfig) metricCouchdbHttpdBulkRequests {
	m := metricCouchdbHttpdBulkRequests{config: cfg}
	if cfg.Enabled {
		m.data = pmetric.NewMetric()
		m.init()
	}
	return m
}

type metricCouchdbHttpdRequests struct {
	data     pmetric.Metric // data buffer for generated metric.
	config   MetricConfig   // metric config provided by user.
	capacity int            // max observed number of data points added to the metric.
}

// init fills couchdb.httpd.requests metric with initial data.
func (m *metricCouchdbHttpdRequests) init() {
	m.data.SetName("couchdb.httpd.requests")
	m.data.SetDescription("The number of HTTP requests by method.")
	m.data.SetUnit("{requests}")
	m.data.SetEmptySum()
	m.data.Sum().SetIsMonotonic(true)
	m.data.Sum().SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
	m.data.Sum().DataPoints().EnsureCapacity(m.capacity)
}

func (m *metricCouchdbHttpdRequests) recordDataPoint(start pcommon.Timestamp, ts pcommon.Timestamp, val int64, httpMethodAttributeValue string) {
	if !m.config.Enabled {
		return
	}
	dp := m.data.Sum().DataPoints().AppendEmpty()
	dp.SetStartTimestamp(start)
	dp.SetTimestamp(ts)
	dp.SetIntValue(val)
	dp.Attributes().PutStr("http.method", httpMethodAttributeValue)
}

// updateCapacity saves max length of data point slices that will be used for the slice capacity.
func (m *metricCouchdbHttpdRequests) updateCapacity() {
	if m.data.Sum().DataPoints().Len() > m.capacity {
		m.capacity = m.data.Sum().DataPoints().Len()
	}
}

// emit appends recorded metric data to a metrics slice and prepares it for recording another set of data points.
func (m *metricCouchdbHttpdRequests) emit(metrics pmetric.MetricSlice) {
	if m.config.Enabled && m.data.Sum().DataPoints().Len() > 0 {
		m.updateCapacity()
		m.data.MoveTo(metrics.AppendEmpty())
		m.init()
	}
}

func newMetricCouchdbHttpdRequests(cfg MetricConfig) metricCouchdbHttpdRequests {
	m := metricCouchdbHttpdRequests{config: cfg}
	if cfg.Enabled {
		m.data = pmetric.NewMetric()
		m.init()
	}
	return m
}

type metricCouchdbHttpdResponses struct {
	data     pmetric.Metric // data buffer for generated metric.
	config   MetricConfig   // metric config provided by user.
	capacity int            // max observed number of data points added to the metric.
}

// init fills couchdb.httpd.responses metric with initial data.
func (m *metricCouchdbHttpdResponses) init() {
	m.data.SetName("couchdb.httpd.responses")
	m.data.SetDescription("The number of each HTTP status code.")
	m.data.SetUnit("{responses}")
	m.data.SetEmptySum()
	m.data.Sum().SetIsMonotonic(true)
	m.data.Sum().SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
	m.data.Sum().DataPoints().EnsureCapacity(m.capacity)
}

func (m *metricCouchdbHttpdResponses) recordDataPoint(start pcommon.Timestamp, ts pcommon.Timestamp, val int64, httpStatusCodeAttributeValue string) {
	if !m.config.Enabled {
		return
	}
	dp := m.data.Sum().DataPoints().AppendEmpty()
	dp.SetStartTimestamp(start)
	dp.SetTimestamp(ts)
	dp.SetIntValue(val)
	dp.Attributes().PutStr("http.status_code", httpStatusCodeAttributeValue)
}

// updateCapacity saves max length of data point slices that will be used for the slice capacity.
func (m *metricCouchdbHttpdResponses) updateCapacity() {
	if m.data.Sum().DataPoints().Len() > m.capacity {
		m.capacity = m.data.Sum().DataPoints().Len()
	}
}

// emit appends recorded metric data to a metrics slice and prepares it for recording another set of data points.
func (m *metricCouchdbHttpdResponses) emit(metrics pmetric.MetricSlice) {
	if m.config.Enabled && m.data.Sum().DataPoints().Len() > 0 {
		m.updateCapacity()
		m.data.MoveTo(metrics.AppendEmpty())
		m.init()
	}
}

func newMetricCouchdbHttpdResponses(cfg MetricConfig) metricCouchdbHttpdResponses {
	m := metricCouchdbHttpdResponses{config: cfg}
	if cfg.Enabled {
		m.data = pmetric.NewMetric()
		m.init()
	}
	return m
}

type metricCouchdbHttpdViews struct {
	data     pmetric.Metric // data buffer for generated metric.
	config   MetricConfig   // metric config provided by user.
	capacity int            // max observed number of data points added to the metric.
}

// init fills couchdb.httpd.views metric with initial data.
func (m *metricCouchdbHttpdViews) init() {
	m.data.SetName("couchdb.httpd.views")
	m.data.SetDescription("The number of views read.")
	m.data.SetUnit("{views}")
	m.data.SetEmptySum()
	m.data.Sum().SetIsMonotonic(true)
	m.data.Sum().SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
	m.data.Sum().DataPoints().EnsureCapacity(m.capacity)
}

func (m *metricCouchdbHttpdViews) recordDataPoint(start pcommon.Timestamp, ts pcommon.Timestamp, val int64, viewAttributeValue string) {
	if !m.config.Enabled {
		return
	}
	dp := m.data.Sum().DataPoints().AppendEmpty()
	dp.SetStartTimestamp(start)
	dp.SetTimestamp(ts)
	dp.SetIntValue(val)
	dp.Attributes().PutStr("view", viewAttributeValue)
}

// updateCapacity saves max length of data point slices that will be used for the slice capacity.
func (m *metricCouchdbHttpdViews) updateCapacity() {
	if m.data.Sum().DataPoints().Len() > m.capacity {
		m.capacity = m.data.Sum().DataPoints().Len()
	}
}

// emit appends recorded metric data to a metrics slice and prepares it for recording another set of data points.
func (m *metricCouchdbHttpdViews) emit(metrics pmetric.MetricSlice) {
	if m.config.Enabled && m.data.Sum().DataPoints().Len() > 0 {
		m.updateCapacity()
		m.data.MoveTo(metrics.AppendEmpty())
		m.init()
	}
}

func newMetricCouchdbHttpdViews(cfg MetricConfig) metricCouchdbHttpdViews {
	m := metricCouchdbHttpdViews{config: cfg}
	if cfg.Enabled {
		m.data = pmetric.NewMetric()
		m.init()
	}
	return m
}

// MetricsBuilder provides an interface for scrapers to report metrics while taking care of all the transformations
// required to produce metric representation defined in metadata and user config.
type MetricsBuilder struct {
	config                          MetricsBuilderConfig // config of the metrics builder.
	startTime                       pcommon.Timestamp    // start time that will be applied to all recorded data points.
	metricsCapacity                 int                  // maximum observed number of metrics per resource.
	metricsBuffer                   pmetric.Metrics      // accumulates metrics data before emitting.
	buildInfo                       component.BuildInfo  // contains version information.
	resourceAttributeIncludeFilter  map[string]filter.Filter
	resourceAttributeExcludeFilter  map[string]filter.Filter
	metricCouchdbAverageRequestTime metricCouchdbAverageRequestTime
	metricCouchdbDatabaseOpen       metricCouchdbDatabaseOpen
	metricCouchdbDatabaseOperations metricCouchdbDatabaseOperations
	metricCouchdbFileDescriptorOpen metricCouchdbFileDescriptorOpen
	metricCouchdbHttpdBulkRequests  metricCouchdbHttpdBulkRequests
	metricCouchdbHttpdRequests      metricCouchdbHttpdRequests
	metricCouchdbHttpdResponses     metricCouchdbHttpdResponses
	metricCouchdbHttpdViews         metricCouchdbHttpdViews
}

// MetricBuilderOption applies changes to default metrics builder.
type MetricBuilderOption interface {
	apply(*MetricsBuilder)
}

type metricBuilderOptionFunc func(mb *MetricsBuilder)

func (mbof metricBuilderOptionFunc) apply(mb *MetricsBuilder) {
	mbof(mb)
}

// WithStartTime sets startTime on the metrics builder.
func WithStartTime(startTime pcommon.Timestamp) MetricBuilderOption {
	return metricBuilderOptionFunc(func(mb *MetricsBuilder) {
		mb.startTime = startTime
	})
}
func NewMetricsBuilder(mbc MetricsBuilderConfig, settings receiver.Settings, options ...MetricBuilderOption) *MetricsBuilder {
	mb := &MetricsBuilder{
		config:                          mbc,
		startTime:                       pcommon.NewTimestampFromTime(time.Now()),
		metricsBuffer:                   pmetric.NewMetrics(),
		buildInfo:                       settings.BuildInfo,
		metricCouchdbAverageRequestTime: newMetricCouchdbAverageRequestTime(mbc.Metrics.CouchdbAverageRequestTime),
		metricCouchdbDatabaseOpen:       newMetricCouchdbDatabaseOpen(mbc.Metrics.CouchdbDatabaseOpen),
		metricCouchdbDatabaseOperations: newMetricCouchdbDatabaseOperations(mbc.Metrics.CouchdbDatabaseOperations),
		metricCouchdbFileDescriptorOpen: newMetricCouchdbFileDescriptorOpen(mbc.Metrics.CouchdbFileDescriptorOpen),
		metricCouchdbHttpdBulkRequests:  newMetricCouchdbHttpdBulkRequests(mbc.Metrics.CouchdbHttpdBulkRequests),
		metricCouchdbHttpdRequests:      newMetricCouchdbHttpdRequests(mbc.Metrics.CouchdbHttpdRequests),
		metricCouchdbHttpdResponses:     newMetricCouchdbHttpdResponses(mbc.Metrics.CouchdbHttpdResponses),
		metricCouchdbHttpdViews:         newMetricCouchdbHttpdViews(mbc.Metrics.CouchdbHttpdViews),
		resourceAttributeIncludeFilter:  make(map[string]filter.Filter),
		resourceAttributeExcludeFilter:  make(map[string]filter.Filter),
	}
	if mbc.ResourceAttributes.CouchdbNodeName.MetricsInclude != nil {
		mb.resourceAttributeIncludeFilter["couchdb.node.name"] = filter.CreateFilter(mbc.ResourceAttributes.CouchdbNodeName.MetricsInclude)
	}
	if mbc.ResourceAttributes.CouchdbNodeName.MetricsExclude != nil {
		mb.resourceAttributeExcludeFilter["couchdb.node.name"] = filter.CreateFilter(mbc.ResourceAttributes.CouchdbNodeName.MetricsExclude)
	}

	for _, op := range options {
		op.apply(mb)
	}
	return mb
}

// NewResourceBuilder returns a new resource builder that should be used to build a resource associated with for the emitted metrics.
func (mb *MetricsBuilder) NewResourceBuilder() *ResourceBuilder {
	return NewResourceBuilder(mb.config.ResourceAttributes)
}

// updateCapacity updates max length of metrics and resource attributes that will be used for the slice capacity.
func (mb *MetricsBuilder) updateCapacity(rm pmetric.ResourceMetrics) {
	if mb.metricsCapacity < rm.ScopeMetrics().At(0).Metrics().Len() {
		mb.metricsCapacity = rm.ScopeMetrics().At(0).Metrics().Len()
	}
}

// ResourceMetricsOption applies changes to provided resource metrics.
type ResourceMetricsOption interface {
	apply(pmetric.ResourceMetrics)
}

type resourceMetricsOptionFunc func(pmetric.ResourceMetrics)

func (rmof resourceMetricsOptionFunc) apply(rm pmetric.ResourceMetrics) {
	rmof(rm)
}

// WithResource sets the provided resource on the emitted ResourceMetrics.
// It's recommended to use ResourceBuilder to create the resource.
func WithResource(res pcommon.Resource) ResourceMetricsOption {
	return resourceMetricsOptionFunc(func(rm pmetric.ResourceMetrics) {
		res.CopyTo(rm.Resource())
	})
}

// WithStartTimeOverride overrides start time for all the resource metrics data points.
// This option should be only used if different start time has to be set on metrics coming from different resources.
func WithStartTimeOverride(start pcommon.Timestamp) ResourceMetricsOption {
	return resourceMetricsOptionFunc(func(rm pmetric.ResourceMetrics) {
		var dps pmetric.NumberDataPointSlice
		metrics := rm.ScopeMetrics().At(0).Metrics()
		for i := 0; i < metrics.Len(); i++ {
			switch metrics.At(i).Type() {
			case pmetric.MetricTypeGauge:
				dps = metrics.At(i).Gauge().DataPoints()
			case pmetric.MetricTypeSum:
				dps = metrics.At(i).Sum().DataPoints()
			}
			for j := 0; j < dps.Len(); j++ {
				dps.At(j).SetStartTimestamp(start)
			}
		}
	})
}

// EmitForResource saves all the generated metrics under a new resource and updates the internal state to be ready for
// recording another set of data points as part of another resource. This function can be helpful when one scraper
// needs to emit metrics from several resources. Otherwise calling this function is not required,
// just `Emit` function can be called instead.
// Resource attributes should be provided as ResourceMetricsOption arguments.
func (mb *MetricsBuilder) EmitForResource(options ...ResourceMetricsOption) {
	rm := pmetric.NewResourceMetrics()
	ils := rm.ScopeMetrics().AppendEmpty()
	ils.Scope().SetName("github.com/open-telemetry/opentelemetry-collector-contrib/receiver/couchdbreceiver")
	ils.Scope().SetVersion(mb.buildInfo.Version)
	ils.Metrics().EnsureCapacity(mb.metricsCapacity)
	mb.metricCouchdbAverageRequestTime.emit(ils.Metrics())
	mb.metricCouchdbDatabaseOpen.emit(ils.Metrics())
	mb.metricCouchdbDatabaseOperations.emit(ils.Metrics())
	mb.metricCouchdbFileDescriptorOpen.emit(ils.Metrics())
	mb.metricCouchdbHttpdBulkRequests.emit(ils.Metrics())
	mb.metricCouchdbHttpdRequests.emit(ils.Metrics())
	mb.metricCouchdbHttpdResponses.emit(ils.Metrics())
	mb.metricCouchdbHttpdViews.emit(ils.Metrics())

	for _, op := range options {
		op.apply(rm)
	}
	for attr, filter := range mb.resourceAttributeIncludeFilter {
		if val, ok := rm.Resource().Attributes().Get(attr); ok && !filter.Matches(val.AsString()) {
			return
		}
	}
	for attr, filter := range mb.resourceAttributeExcludeFilter {
		if val, ok := rm.Resource().Attributes().Get(attr); ok && filter.Matches(val.AsString()) {
			return
		}
	}

	if ils.Metrics().Len() > 0 {
		mb.updateCapacity(rm)
		rm.MoveTo(mb.metricsBuffer.ResourceMetrics().AppendEmpty())
	}
}

// Emit returns all the metrics accumulated by the metrics builder and updates the internal state to be ready for
// recording another set of metrics. This function will be responsible for applying all the transformations required to
// produce metric representation defined in metadata and user config, e.g. delta or cumulative.
func (mb *MetricsBuilder) Emit(options ...ResourceMetricsOption) pmetric.Metrics {
	mb.EmitForResource(options...)
	metrics := mb.metricsBuffer
	mb.metricsBuffer = pmetric.NewMetrics()
	return metrics
}

// RecordCouchdbAverageRequestTimeDataPoint adds a data point to couchdb.average_request_time metric.
func (mb *MetricsBuilder) RecordCouchdbAverageRequestTimeDataPoint(ts pcommon.Timestamp, val float64) {
	mb.metricCouchdbAverageRequestTime.recordDataPoint(mb.startTime, ts, val)
}

// RecordCouchdbDatabaseOpenDataPoint adds a data point to couchdb.database.open metric.
func (mb *MetricsBuilder) RecordCouchdbDatabaseOpenDataPoint(ts pcommon.Timestamp, val int64) {
	mb.metricCouchdbDatabaseOpen.recordDataPoint(mb.startTime, ts, val)
}

// RecordCouchdbDatabaseOperationsDataPoint adds a data point to couchdb.database.operations metric.
func (mb *MetricsBuilder) RecordCouchdbDatabaseOperationsDataPoint(ts pcommon.Timestamp, val int64, operationAttributeValue AttributeOperation) {
	mb.metricCouchdbDatabaseOperations.recordDataPoint(mb.startTime, ts, val, operationAttributeValue.String())
}

// RecordCouchdbFileDescriptorOpenDataPoint adds a data point to couchdb.file_descriptor.open metric.
func (mb *MetricsBuilder) RecordCouchdbFileDescriptorOpenDataPoint(ts pcommon.Timestamp, val int64) {
	mb.metricCouchdbFileDescriptorOpen.recordDataPoint(mb.startTime, ts, val)
}

// RecordCouchdbHttpdBulkRequestsDataPoint adds a data point to couchdb.httpd.bulk_requests metric.
func (mb *MetricsBuilder) RecordCouchdbHttpdBulkRequestsDataPoint(ts pcommon.Timestamp, val int64) {
	mb.metricCouchdbHttpdBulkRequests.recordDataPoint(mb.startTime, ts, val)
}

// RecordCouchdbHttpdRequestsDataPoint adds a data point to couchdb.httpd.requests metric.
func (mb *MetricsBuilder) RecordCouchdbHttpdRequestsDataPoint(ts pcommon.Timestamp, val int64, httpMethodAttributeValue AttributeHTTPMethod) {
	mb.metricCouchdbHttpdRequests.recordDataPoint(mb.startTime, ts, val, httpMethodAttributeValue.String())
}

// RecordCouchdbHttpdResponsesDataPoint adds a data point to couchdb.httpd.responses metric.
func (mb *MetricsBuilder) RecordCouchdbHttpdResponsesDataPoint(ts pcommon.Timestamp, val int64, httpStatusCodeAttributeValue string) {
	mb.metricCouchdbHttpdResponses.recordDataPoint(mb.startTime, ts, val, httpStatusCodeAttributeValue)
}

// RecordCouchdbHttpdViewsDataPoint adds a data point to couchdb.httpd.views metric.
func (mb *MetricsBuilder) RecordCouchdbHttpdViewsDataPoint(ts pcommon.Timestamp, val int64, viewAttributeValue AttributeView) {
	mb.metricCouchdbHttpdViews.recordDataPoint(mb.startTime, ts, val, viewAttributeValue.String())
}

// Reset resets metrics builder to its initial state. It should be used when external metrics source is restarted,
// and metrics builder should update its startTime and reset it's internal state accordingly.
func (mb *MetricsBuilder) Reset(options ...MetricBuilderOption) {
	mb.startTime = pcommon.NewTimestampFromTime(time.Now())
	for _, op := range options {
		op.apply(mb)
	}
}
