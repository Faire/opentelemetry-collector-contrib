// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package spanprocessor // import "github.com/open-telemetry/opentelemetry-collector-contrib/processor/spanprocessor"

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/DataDog/go-sqllexer"
	"github.com/outcaste-io/ristretto"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	semconv "go.opentelemetry.io/collector/semconv/v1.27.0"

	"github.com/open-telemetry/opentelemetry-collector-contrib/internal/filter/expr"
	"github.com/open-telemetry/opentelemetry-collector-contrib/internal/filter/filterspan"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl/contexts/ottlspan"
)

type spanProcessor struct {
	config           Config
	toAttributeRules []toAttributeRule
	skipExpr         expr.BoolExpr[ottlspan.TransformContext]
	sqlCache         *ristretto.Cache
}

// toAttributeRule is the compiled equivalent of config.ToAttributes field.
type toAttributeRule struct {
	// Compiled regexp.
	re *regexp.Regexp

	// Attribute names extracted from the regexp's subexpressions.
	attrNames []string
}

// newSpanProcessor returns the span processor.
func newSpanProcessor(config Config) (*spanProcessor, error) {
	skipExpr, err := filterspan.NewSkipExpr(&config.MatchConfig)
	if err != nil {
		return nil, err
	}

	sp := &spanProcessor{
		config:   config,
		skipExpr: skipExpr,
	}

	// Compile ToAttributes regexp and extract attributes names.
	if config.Rename.ToAttributes != nil {
		for _, pattern := range config.Rename.ToAttributes.Rules {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("invalid regexp pattern %s", pattern)
			}

			rule := toAttributeRule{
				re: re,
				// Subexpression names will become attribute names during extraction.
				attrNames: re.SubexpNames(),
			}

			sp.toAttributeRules = append(sp.toAttributeRules, rule)
		}
	}

	sqlCache, err := newSQLCache()
	if err != nil {
		return nil, err
	}

	sp.sqlCache = sqlCache
	return sp, nil
}

// newSQLCache returns a new ristretto.Cache for storing normalized SQL queries.
func newSQLCache() (*ristretto.Cache, error) {
	cfg := &ristretto.Config{
		// We know that the maximum allowed resource length is 5K. This means that
		// in 5MB we can store a minimum of 1000 queries.
		MaxCost: 5000000,

		// An approximated worst-case scenario when the cache is filled with small
		// queries averaged as being of length 11 ("LOCK TABLES"), we would be able
		// to fit 476K of them into 5MB of cost.
		//
		// We average it to 500K and multiply 10x as the documentation recommends.
		NumCounters: 500000 * 10,

		BufferItems: 64,    // default recommended value
		Metrics:     false, // disable hit/miss counters
	}
	cache, err := ristretto.NewCache(cfg)
	if err != nil {
		return nil, err
	}
	return cache, nil
}

func (sp *spanProcessor) Shutdown(context.Context) error {
	sp.sqlCache.Close()
	return nil
}

func (sp *spanProcessor) processTraces(ctx context.Context, td ptrace.Traces) (ptrace.Traces, error) {
	rss := td.ResourceSpans()
	for i := 0; i < rss.Len(); i++ {
		rs := rss.At(i)
		ilss := rs.ScopeSpans()
		resource := rs.Resource()
		for j := 0; j < ilss.Len(); j++ {
			ils := ilss.At(j)
			spans := ils.Spans()
			scope := ils.Scope()
			for k := 0; k < spans.Len(); k++ {
				span := spans.At(k)
				if sp.skipExpr != nil {
					skip, err := sp.skipExpr.Eval(ctx, ottlspan.NewTransformContext(span, scope, resource, ils, rs))
					if err != nil {
						return td, err
					}
					if skip {
						continue
					}
				}
				sp.processAttributes(span)
				sp.processFromAttributes(span)
				sp.processToAttributes(span)
				sp.processUpdateStatus(span)
			}
		}
	}
	return td, nil
}

func (sp *spanProcessor) processFromAttributes(span ptrace.Span) {
	if len(sp.config.Rename.FromAttributes) == 0 {
		// There is FromAttributes rule.
		return
	}

	attrs := span.Attributes()
	if attrs.Len() == 0 {
		// There are no attributes to create span name from.
		return
	}

	// Note: There was a separate proposal for creating the string.
	// With benchmarking, strings.Builder is faster than the proposal.
	// For full context, refer to this PR comment:
	// https://go.opentelemetry.io/collector/pull/301#discussion_r318357678
	var sb strings.Builder
	for i, key := range sp.config.Rename.FromAttributes {
		attr, found := attrs.Get(key)

		// If one of the keys isn't found, the span name is not updated.
		if !found {
			return
		}

		// Note: WriteString() always return a nil error so there is no error checking
		// for this method call.
		// https://golang.org/src/strings/builder.go?s=3425:3477#L110

		// Include the separator before appending an attribute value if:
		// this isn't the first value(ie i == 0) loop through the FromAttributes
		// and
		// the separator isn't an empty string.
		if i > 0 && sp.config.Rename.Separator != "" {
			sb.WriteString(sp.config.Rename.Separator)
		}

		switch attr.Type() {
		case pcommon.ValueTypeStr:
			sb.WriteString(attr.Str())
		case pcommon.ValueTypeBool:
			sb.WriteString(strconv.FormatBool(attr.Bool()))
		case pcommon.ValueTypeDouble:
			sb.WriteString(strconv.FormatFloat(attr.Double(), 'f', -1, 64))
		case pcommon.ValueTypeInt:
			sb.WriteString(strconv.FormatInt(attr.Int(), 10))
		case pcommon.ValueTypeEmpty:
			fallthrough
		case pcommon.ValueTypeSlice:
			fallthrough
		case pcommon.ValueTypeBytes:
			fallthrough
		case pcommon.ValueTypeMap:
			fallthrough
		default:
			sb.WriteString("<unknown-attribute-type>")
		}
	}
	span.SetName(sb.String())
}

func (sp *spanProcessor) processToAttributes(span ptrace.Span) {
	if span.Name() == "" {
		// There is no span name to work on.
		return
	}

	if sp.config.Rename.ToAttributes == nil {
		// No rules to apply.
		return
	}

	// Process rules one by one. Store results of processing in the span
	// so that each subsequent rule works on the span name that is the output
	// after processing the previous rule.
	for _, rule := range sp.toAttributeRules {
		re := rule.re
		oldName := span.Name()

		// Match the regular expression and extract matched subexpressions.
		submatches := re.FindStringSubmatch(oldName)
		if submatches == nil {
			continue
		}
		// There is a match. We will also need positions of subexpression matches.
		submatchIdxPairs := re.FindStringSubmatchIndex(oldName)

		// A place to accumulate new span name.
		var sb strings.Builder

		// Index in the oldName until which we traversed.
		var oldNameIndex = 0

		attrs := span.Attributes()

		// TODO: Pre-allocate len(submatches) space in the attributes.

		// Start from index 1, which is the first submatch (index 0 is the entire match).
		// We will go over submatches and will simultaneously build a new span name,
		// replacing matched subexpressions by attribute names.
		for i := 1; i < len(submatches); i++ {
			attrs.PutStr(rule.attrNames[i], submatches[i])

			// Add part of span name from end of previous match to start of this match
			// and then add attribute name wrapped in curly brackets.
			matchStartIndex := submatchIdxPairs[i*2] // start of i'th submatch.
			sb.WriteString(oldName[oldNameIndex:matchStartIndex] + "{" + rule.attrNames[i] + "}")

			// Advance the index to the end of current match.
			oldNameIndex = submatchIdxPairs[i*2+1] // end of i'th submatch.
		}
		if oldNameIndex < len(oldName) {
			// Append the remainder, from the end of last match until end of span name.
			sb.WriteString(oldName[oldNameIndex:])
		}

		// Set new span name.
		span.SetName(sb.String())

		if sp.config.Rename.ToAttributes.BreakAfterMatch {
			// Stop processing, break after first match is requested.
			break
		}
	}
}

func (sp *spanProcessor) processUpdateStatus(span ptrace.Span) {
	cfg := sp.config.SetStatus
	if cfg != nil {
		switch cfg.Code {
		case statusCodeOk:
			span.Status().SetCode(ptrace.StatusCodeOk)
			span.Status().SetMessage("")
		case statusCodeError:
			span.Status().SetCode(ptrace.StatusCodeError)
			span.Status().SetMessage(cfg.Description)
		case statusCodeUnset:
			span.Status().SetCode(ptrace.StatusCodeUnset)
			span.Status().SetMessage("")
		}
	}
}

func (sp *spanProcessor) processAttributes(span ptrace.Span) {
	if sp.config.Attributes == nil {
		return
	}

	sp.processDBAttributes(span)
}

func (sp *spanProcessor) processDBAttributes(span ptrace.Span) {
	if sp.config.Attributes.DB == nil {
		return
	}

	sp.processSQLAttributes(span)
}

func (sp *spanProcessor) processSQLAttributes(span ptrace.Span) {
	sqlConfig := sp.config.Attributes.DB.SQL
	if sqlConfig == nil || !sqlConfig.Enabled {
		return
	}

	dbSystem, ok := span.Attributes().Get(semconv.AttributeDBSystem)
	if !ok || !isSQL(dbSystem.Str()) {
		return
	}

	dbQueryText, ok := span.Attributes().Get(semconv.AttributeDBQueryText)
	if !ok || dbQueryText.Str() == "" {
		return
	}

	obfuscator := sqllexer.NewObfuscator(
		sqllexer.WithReplaceDigits(true),
		sqllexer.WithReplaceBoolean(true),
		sqllexer.WithReplaceNull(true),
	)

	normalizer := sqllexer.NewNormalizer(
		sqllexer.WithCollectCommands(sqlConfig.OperationName),
		sqllexer.WithCollectTables(sqlConfig.CollectionName),
		sqllexer.WithCollectProcedures(sqlConfig.OperationName),
		sqllexer.WithRemoveSpaceBetweenParentheses(true),
	)

	var normalizedQuery *NormalizedQuery
	cachedQuery, ok := sp.sqlCache.Get(dbQueryText.Str())

	if ok {
		normalizedQuery = cachedQuery.(*NormalizedQuery)
	} else {
		query, metadata, err := sqllexer.ObfuscateAndNormalize(
			dbQueryText.Str(),
			obfuscator,
			normalizer,
			sqllexer.WithDBMS(sqllexer.DBMSType(dbSystem.Str())),
		)

		if err != nil {
			return
		}

		normalizedQuery = &NormalizedQuery{
			Query:    query,
			Metadata: metadata,
		}

		sp.sqlCache.Set(dbQueryText.Str(), normalizedQuery, normalizedQuery.Cost())
	}

	span.Attributes().PutStr(semconv.AttributeDBQueryText, normalizedQuery.Query)

	// SemConv specifies that these attributes should only be capture for queries that contain a single operation entry of them.
	// (https://github.com/open-telemetry/semantic-conventions/blob/main/docs/database/database-spans.md#common-attributes)
	if normalizedQuery.Metadata.Tables != nil && len(normalizedQuery.Metadata.Tables) == 1 {
		span.Attributes().PutStr(semconv.AttributeDBCollectionName, normalizedQuery.Metadata.Tables[0])
	}
	if normalizedQuery.Metadata.Procedures != nil && len(normalizedQuery.Metadata.Procedures) == 1 {
		span.Attributes().PutStr(semconv.AttributeDBOperationName, normalizedQuery.Metadata.Procedures[0])
	}
	if normalizedQuery.Metadata.Commands != nil && len(normalizedQuery.Metadata.Commands) == 1 {
		span.Attributes().PutStr(semconv.AttributeDBOperationName, normalizedQuery.Metadata.Commands[0])
	}
}

// NormalizedQuery specifies information about an obfuscated SQL query.
type NormalizedQuery struct {
	Query    string                      `json:"query"`    // the obfuscated SQL query
	Metadata *sqllexer.StatementMetadata `json:"metadata"` // metadata extracted from the SQL query
}

// Cost returns the number of bytes needed to store all the fields
// of this NormalizedQuery.
func (oq *NormalizedQuery) Cost() int64 {
	return int64(len(oq.Query)) + int64(oq.Metadata.Size)
}

// https://github.com/open-telemetry/semantic-conventions/blob/main/docs/database/sql.md
func isSQL(dbSystem string) bool {
	switch dbSystem {
	case semconv.AttributeDBSystemCockroachdb:
		fallthrough
	case semconv.AttributeDBSystemDB2:
		fallthrough
	case semconv.AttributeDBSystemDerby:
		fallthrough
	case semconv.AttributeDBSystemEDB:
		fallthrough
	case semconv.AttributeDBSystemFirebird:
		fallthrough
	case semconv.AttributeDBSystemH2:
		fallthrough
	case semconv.AttributeDBSystemHSQLDB:
		fallthrough
	case semconv.AttributeDBSystemIngres:
		fallthrough
	case semconv.AttributeDBSystemInterbase:
		fallthrough
	case semconv.AttributeDBSystemMariaDB:
		fallthrough
	case semconv.AttributeDBSystemMaxDB:
		fallthrough
	case semconv.AttributeDBSystemMSSQL:
		fallthrough
	case semconv.AttributeDBSystemMssqlcompact:
		fallthrough
	case semconv.AttributeDBSystemMySQL:
		fallthrough
	case semconv.AttributeDBSystemOracle:
		fallthrough
	case semconv.AttributeDBSystemPervasive:
		fallthrough
	case semconv.AttributeDBSystemPostgreSQL:
		fallthrough
	case semconv.AttributeDBSystemSqlite:
		fallthrough
	case semconv.AttributeDBSystemTrino:
		fallthrough
	case semconv.AttributeDBSystemOtherSQL:
		return true
	default:
	}
	return false
}
