// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package translator // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/datadogreceiver/internal/translator"

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/DataDog/datadog-agent/pkg/obfuscate"
	pb "github.com/DataDog/datadog-agent/pkg/proto/pbgo/trace"
	"github.com/DataDog/datadog-agent/pkg/trace/traceutil"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	semconv "go.opentelemetry.io/collector/semconv/v1.16.0"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/proto"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/datadogreceiver/config"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/datadogreceiver/internal/translator/header"
)

const (
	datadogSpanKindKey = "span.kind"
	// The datadog trace id
	//
	// Type: string
	// Requirement Level: Optional
	// Examples: '6249785623524942554'
	attributeDatadogTraceID = "datadog.trace.id"
	// The datadog span id
	//
	// Type: string
	// Requirement Level: Optional
	// Examples: '228114450199004348'
	attributeDatadogSpanID = "datadog.span.id"

	tagRedisRawCommand  = "redis.raw_command"
	tagMemcachedCommand = "memcached.command"
	tagMongoDBQuery     = "mongodb.query"
	tagElasticBody      = "elasticsearch.body"
	tagOpenSearchBody   = "opensearch.body"
	tagSQLQuery         = "sql.query"
	tagHTTPURL          = "http.url"
)

type TracesTranslator struct {
	obfuscator *obfuscate.Obfuscator

	conf *config.TracesConfig
}

func NewTracesTranslator(config config.TracesConfig) *TracesTranslator {
	return &TracesTranslator{
		obfuscator: obfuscate.NewObfuscator(config.Obfuscation.Export()),
		conf:       &config,
	}
}

func upsertHeadersAttributes(req *http.Request, attrs pcommon.Map) {
	if ddTracerVersion := req.Header.Get(header.TracerVersion); ddTracerVersion != "" {
		attrs.PutStr(semconv.AttributeTelemetrySDKVersion, "Datadog-"+ddTracerVersion)
	}
	if ddTracerLang := req.Header.Get(header.Lang); ddTracerLang != "" {
		otelLang := ddTracerLang
		if ddTracerLang == ".NET" {
			otelLang = "dotnet"
		}
		attrs.PutStr(semconv.AttributeTelemetrySDKLanguage, otelLang)
	}
}

func (tt *TracesTranslator) ToTraces(payload *pb.TracerPayload, req *http.Request) ptrace.Traces {
	var traces pb.Traces
	for _, p := range payload.GetChunks() {
		traces = append(traces, p.GetSpans())
	}
	sharedAttributes := pcommon.NewMap()
	for k, v := range map[string]string{
		semconv.AttributeContainerID:           payload.ContainerID,
		semconv.AttributeTelemetrySDKLanguage:  payload.LanguageName,
		semconv.AttributeProcessRuntimeVersion: payload.LanguageVersion,
		semconv.AttributeDeploymentEnvironment: payload.Env,
		semconv.AttributeHostName:              payload.Hostname,
		semconv.AttributeServiceVersion:        payload.AppVersion,
		semconv.AttributeTelemetrySDKName:      "Datadog",
		semconv.AttributeTelemetrySDKVersion:   payload.TracerVersion,
	} {
		if v != "" {
			sharedAttributes.PutStr(k, v)
		}
	}

	for k, v := range payload.Tags {
		if k = translateDatadogKeyToOTel(k); v != "" {
			sharedAttributes.PutStr(k, v)
		}
	}

	upsertHeadersAttributes(req, sharedAttributes)

	// Creating a map of service spans to slices
	// since the expectation is that `service.name`
	// is added as a resource attribute in most systems
	// now instead of being a span level attribute.
	groupByService := make(map[string]ptrace.SpanSlice)

	for _, trace := range traces {
		for _, span := range trace {
			tt.obfuscateSpan(span)

			slice, exist := groupByService[span.Service]
			if !exist {
				slice = ptrace.NewSpanSlice()
				groupByService[span.Service] = slice
			}
			newSpan := slice.AppendEmpty()

			_ = tagsToSpanLinks(span.GetMeta(), newSpan.Links())

			newSpan.SetTraceID(uInt64ToTraceID(0, span.TraceID))
			newSpan.SetSpanID(uInt64ToSpanID(span.SpanID))
			newSpan.SetStartTimestamp(pcommon.Timestamp(span.Start))
			newSpan.SetEndTimestamp(pcommon.Timestamp(span.Start + span.Duration))
			newSpan.SetParentSpanID(uInt64ToSpanID(span.ParentID))
			newSpan.SetName(span.Name)
			newSpan.Status().SetCode(ptrace.StatusCodeOk)
			newSpan.Attributes().PutStr("dd.span.Resource", span.Resource)
			if samplingPriority, ok := span.Metrics["_sampling_priority_v1"]; ok {
				newSpan.Attributes().PutStr("sampling.priority", fmt.Sprintf("%f", samplingPriority))
			}
			if span.Error > 0 {
				newSpan.Status().SetCode(ptrace.StatusCodeError)
			}
			newSpan.Attributes().PutStr(attributeDatadogSpanID, strconv.FormatUint(span.SpanID, 10))
			newSpan.Attributes().PutStr(attributeDatadogTraceID, strconv.FormatUint(span.TraceID, 10))
			for k, v := range span.GetMeta() {
				if k = translateDatadogKeyToOTel(k); len(k) > 0 {
					newSpan.Attributes().PutStr(k, v)
				}
			}
			for k, v := range span.GetMetrics() {
				if k = translateDatadogKeyToOTel(k); len(k) > 0 {
					newSpan.Attributes().PutDouble(k, v)
				}
			}

			switch span.Meta[datadogSpanKindKey] {
			case "server":
				newSpan.SetKind(ptrace.SpanKindServer)
			case "client":
				newSpan.SetKind(ptrace.SpanKindClient)
			case "producer":
				newSpan.SetKind(ptrace.SpanKindProducer)
			case "consumer":
				newSpan.SetKind(ptrace.SpanKindConsumer)
			case "internal":
				newSpan.SetKind(ptrace.SpanKindInternal)
			default:
				switch span.Type {
				case "web":
					newSpan.SetKind(ptrace.SpanKindServer)
				case "http":
					newSpan.SetKind(ptrace.SpanKindClient)
				default:
					newSpan.SetKind(ptrace.SpanKindUnspecified)
				}
			}
		}
	}

	results := ptrace.NewTraces()
	for service, spans := range groupByService {
		rs := results.ResourceSpans().AppendEmpty()
		rs.SetSchemaUrl(semconv.SchemaURL)
		sharedAttributes.CopyTo(rs.Resource().Attributes())
		rs.Resource().Attributes().PutStr(semconv.AttributeServiceName, service)

		in := rs.ScopeSpans().AppendEmpty()
		in.Scope().SetName("Datadog")
		in.Scope().SetVersion(payload.TracerVersion)
		spans.CopyTo(in.Spans())
	}

	return results
}

// DDSpanLink represents the structure of each JSON object
type DDSpanLink struct {
	TraceID    string         `json:"trace_id"`
	SpanID     string         `json:"span_id"`
	Tracestate string         `json:"tracestate"`
	Attributes map[string]any `json:"attributes"`
}

func tagsToSpanLinks(tags map[string]string, dest ptrace.SpanLinkSlice) error {
	key := "_dd.span_links"
	val, ok := tags[key]
	if !ok {
		return nil
	}
	delete(tags, key)

	var spans []DDSpanLink
	err := json.Unmarshal([]byte(val), &spans)
	if err != nil {
		return err
	}

	for i := 0; i < len(spans); i++ {
		span := spans[i]
		link := dest.AppendEmpty()

		// Convert trace id.
		rawTrace, errTrace := trace.TraceIDFromHex(span.TraceID)
		if errTrace != nil {
			return errTrace
		}
		link.SetTraceID(pcommon.TraceID(rawTrace))

		// Convert span id.
		rawSpan, errSpan := trace.SpanIDFromHex(span.SpanID)
		if errSpan != nil {
			return errSpan
		}
		link.SetSpanID(pcommon.SpanID(rawSpan))

		link.TraceState().FromRaw(span.Tracestate)

		err = link.Attributes().FromRaw(span.Attributes)
		if err != nil {
			return err
		}
	}

	return nil
}

var bufferPool = sync.Pool{
	New: func() any {
		return new(bytes.Buffer)
	},
}

func GetBuffer() *bytes.Buffer {
	buffer := bufferPool.Get().(*bytes.Buffer)
	buffer.Reset()
	return buffer
}

func PutBuffer(buffer *bytes.Buffer) {
	bufferPool.Put(buffer)
}

func HandleTracesPayload(req *http.Request) (tp []*pb.TracerPayload, err error) {
	var tracerPayloads []*pb.TracerPayload

	defer func() {
		_, errs := io.Copy(io.Discard, req.Body)
		err = errors.Join(err, errs, req.Body.Close())
	}()

	switch {
	case strings.HasPrefix(req.URL.Path, "/v0.7"):
		buf := GetBuffer()
		defer PutBuffer(buf)
		if _, err = io.Copy(buf, req.Body); err != nil {
			return nil, err
		}
		var tracerPayload pb.TracerPayload
		if _, err = tracerPayload.UnmarshalMsg(buf.Bytes()); err != nil {
			return nil, err
		}

		tracerPayloads = append(tracerPayloads, &tracerPayload)
	case strings.HasPrefix(req.URL.Path, "/v0.5"):
		buf := GetBuffer()
		defer PutBuffer(buf)
		if _, err = io.Copy(buf, req.Body); err != nil {
			return nil, err
		}
		var traces pb.Traces

		if err = traces.UnmarshalMsgDictionary(buf.Bytes()); err != nil {
			return nil, err
		}

		traceChunks := traceChunksFromTraces(traces)
		appVersion := appVersionFromTraceChunks(traceChunks)

		tracerPayload := &pb.TracerPayload{
			LanguageName:    req.Header.Get(header.Lang),
			LanguageVersion: req.Header.Get(header.LangVersion),
			TracerVersion:   req.Header.Get(header.TracerVersion),
			ContainerID:     req.Header.Get(header.ContainerID),
			Chunks:          traceChunks,
			AppVersion:      appVersion,
		}
		tracerPayloads = append(tracerPayloads, tracerPayload)

	case strings.HasPrefix(req.URL.Path, "/v0.1"):
		var spans []pb.Span
		if err = json.NewDecoder(req.Body).Decode(&spans); err != nil {
			return nil, err
		}
		tracerPayload := &pb.TracerPayload{
			LanguageName:    req.Header.Get(header.Lang),
			LanguageVersion: req.Header.Get(header.LangVersion),
			TracerVersion:   req.Header.Get(header.TracerVersion),
			Chunks:          traceChunksFromSpans(spans),
		}
		tracerPayloads = append(tracerPayloads, tracerPayload)
	case strings.HasPrefix(req.URL.Path, "/api/v0.2"):
		buf := GetBuffer()
		defer PutBuffer(buf)
		if _, err = io.Copy(buf, req.Body); err != nil {
			return nil, err
		}

		var agentPayload pb.AgentPayload
		if err = proto.Unmarshal(buf.Bytes(), &agentPayload); err != nil {
			return nil, err
		}

		return agentPayload.TracerPayloads, err

	default:
		var traces pb.Traces
		if err = decodeRequest(req, &traces); err != nil {
			return nil, err
		}
		traceChunks := traceChunksFromTraces(traces)
		appVersion := appVersionFromTraceChunks(traceChunks)
		tracerPayload := &pb.TracerPayload{
			LanguageName:    req.Header.Get(header.Lang),
			LanguageVersion: req.Header.Get(header.LangVersion),
			TracerVersion:   req.Header.Get(header.TracerVersion),
			Chunks:          traceChunks,
			AppVersion:      appVersion,
		}
		tracerPayloads = append(tracerPayloads, tracerPayload)
	}

	return tracerPayloads, nil
}

func decodeRequest(req *http.Request, dest *pb.Traces) (err error) {
	switch mediaType := getMediaType(req); mediaType {
	case "application/msgpack":
		buf := GetBuffer()
		defer PutBuffer(buf)
		_, err = io.Copy(buf, req.Body)
		if err != nil {
			return err
		}
		_, err = dest.UnmarshalMsg(buf.Bytes())
		return err
	case "application/json":
		fallthrough
	case "text/json":
		fallthrough
	case "":
		err = json.NewDecoder(req.Body).Decode(&dest)
		return err
	default:
		// do our best
		if err1 := json.NewDecoder(req.Body).Decode(&dest); err1 != nil {
			buf := GetBuffer()
			defer PutBuffer(buf)
			_, err2 := io.Copy(buf, req.Body)
			if err2 != nil {
				return err2
			}
			_, err2 = dest.UnmarshalMsg(buf.Bytes())
			return err2
		}
		return nil
	}
}

func traceChunksFromSpans(spans []pb.Span) []*pb.TraceChunk {
	traceChunks := []*pb.TraceChunk{}
	byID := make(map[uint64][]*pb.Span)
	for i := range spans {
		byID[spans[i].TraceID] = append(byID[spans[i].TraceID], &spans[i])
	}
	for _, t := range byID {
		traceChunks = append(traceChunks, &pb.TraceChunk{
			Priority: int32(0),
			Spans:    t,
		})
	}
	return traceChunks
}

func traceChunksFromTraces(traces pb.Traces) []*pb.TraceChunk {
	traceChunks := make([]*pb.TraceChunk, 0, len(traces))
	for _, trace := range traces {
		traceChunks = append(traceChunks, &pb.TraceChunk{
			Priority: int32(0),
			Spans:    trace,
		})
	}

	return traceChunks
}

func appVersionFromTraceChunks(traces []*pb.TraceChunk) string {
	appVersion := ""
	for _, trace := range traces {
		for _, span := range trace.Spans {
			if span != nil && span.Meta["version"] != "" {
				appVersion = span.Meta["version"]
				return appVersion
			}
		}
	}
	return appVersion
}

func getMediaType(req *http.Request) string {
	mt, _, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if err != nil {
		return "application/json"
	}
	return mt
}

func uInt64ToTraceID(high, low uint64) pcommon.TraceID {
	traceID := [16]byte{}
	binary.BigEndian.PutUint64(traceID[:8], high)
	binary.BigEndian.PutUint64(traceID[8:], low)
	return traceID
}

func uInt64ToSpanID(id uint64) pcommon.SpanID {
	spanID := [8]byte{}
	binary.BigEndian.PutUint64(spanID[:], id)
	return spanID
}

func (tt *TracesTranslator) obfuscateSpan(span *pb.Span) {
	if !tt.conf.Obfuscation.Enabled {
		return
	}

	o := tt.obfuscator
	if tt.conf.Obfuscation.CreditCards.Enabled {
		for k, v := range span.Meta {
			newV := o.ObfuscateCreditCardNumber(k, v)
			if v != newV {
				span.Meta[k] = newV
			}
		}
	}

	switch span.Type {
	case "sql", "cassandra":
		if span.Resource == "" {
			return
		}
		oq, err := o.ObfuscateSQLString(span.Resource)
		if err != nil {
			// we have an error, discard the SQL to avoid polluting user resources.
			span.Resource = textNonParsable
			traceutil.SetMeta(span, tagSQLQuery, textNonParsable)
			return
		}

		span.Resource = oq.Query
		if len(oq.Metadata.TablesCSV) > 0 {
			traceutil.SetMeta(span, "sql.tables", oq.Metadata.TablesCSV)
		}
		traceutil.SetMeta(span, tagSQLQuery, oq.Query)
	case "redis":
		span.Resource = o.QuantizeRedisString(span.Resource)
		if tt.conf.Obfuscation.Redis.Enabled {
			if span.Meta == nil || span.Meta[tagRedisRawCommand] == "" {
				return
			}
			if tt.conf.Obfuscation.Redis.RemoveAllArgs {
				span.Meta[tagRedisRawCommand] = o.RemoveAllRedisArgs(span.Meta[tagRedisRawCommand])
				return
			}
			span.Meta[tagRedisRawCommand] = o.ObfuscateRedisString(span.Meta[tagRedisRawCommand])
		}
	case "memcached":
		if !tt.conf.Obfuscation.Memcached.Enabled {
			return
		}
		if span.Meta == nil || span.Meta[tagMemcachedCommand] == "" {
			return
		}
		span.Meta[tagMemcachedCommand] = o.ObfuscateMemcachedString(span.Meta[tagMemcachedCommand])
	case "web", "http":
		if span.Meta == nil || span.Meta[tagHTTPURL] == "" {
			return
		}
		span.Meta[tagHTTPURL] = o.ObfuscateURLString(span.Meta[tagHTTPURL])
	case "mongodb":
		if !tt.conf.Obfuscation.Mongo.Enabled {
			return
		}
		if span.Meta == nil || span.Meta[tagMongoDBQuery] == "" {
			return
		}
		span.Meta[tagMongoDBQuery] = o.ObfuscateMongoDBString(span.Meta[tagMongoDBQuery])
	case "elasticsearch", "opensearch":
		if span.Meta == nil {
			return
		}
		if tt.conf.Obfuscation.ES.Enabled {
			if span.Meta[tagElasticBody] != "" {
				span.Meta[tagElasticBody] = o.ObfuscateElasticSearchString(span.Meta[tagElasticBody])
			}
		}
		if tt.conf.Obfuscation.OpenSearch.Enabled {
			if span.Meta[tagOpenSearchBody] != "" {
				span.Meta[tagOpenSearchBody] = o.ObfuscateOpenSearchString(span.Meta[tagOpenSearchBody])
			}
		}
	}
}
