# DataAnalystAgent - Data Analysis & Insights

**Version:** 1.0.0  
**Status:** Production Ready ✅

---

## Overview

The **DataAnalystAgent** provides statistical analysis, correlation detection, trend analysis, anomaly detection, automated insights, and report generation for your data.

### Key Capabilities

- 📊 **Statistical Analysis** - Mean, median, std dev, percentiles
- 🔗 **Correlation Detection** - Pearson correlation analysis
- 📈 **Trend Analysis** - Linear regression trend detection
- 🔍 **Anomaly Detection** - Z-score based outlier detection
- 💡 **Automated Insights** - Auto-generated insights and recommendations
- 📋 **Report Generation** - Comprehensive analysis reports

---

## Quick Start

```python
from agentic_ai.agents.data_analyst import DataAnalystAgent

# Initialize
analyst = DataAnalystAgent()

# Register dataset
dataset = analyst.register_dataset(
    name="Sales Data",
    source="database",
    columns=['date', 'revenue', 'customers'],
)

# Load data
analyst.load_data(dataset.dataset_id, sales_data)

# Analyze
stats = analyst.calculate_statistics(dataset.dataset_id, 'revenue')
```

---

## Dataset Management

### Register Dataset

```python
dataset = analyst.register_dataset(
    name="E-commerce Sales",
    source="database",  # database, api, file, stream
    columns=['date', 'revenue', 'customers', 'orders', 'avg_order_value'],
    row_count=10000,
)

print(f"Dataset ID: {dataset.dataset_id}")
print(f"Columns: {dataset.column_count}")
print(f"Rows: {dataset.row_count}")
```

### Load Data

```python
# Data as list of dicts
data = [
    {'date': '2026-01-01', 'revenue': 15000, 'customers': 250},
    {'date': '2026-01-02', 'revenue': 18000, 'customers': 300},
    # ...
]

analyst.load_data(dataset.dataset_id, data)
```

---

## Statistical Analysis

### Calculate Statistics

```python
stats = analyst.calculate_statistics(dataset.dataset_id, 'revenue')

print(f"Count: {stats['count']}")
print(f"Mean: ${stats['mean']:,.2f}")
print(f"Median: ${stats['median']:,.2f}")
print(f"Std Dev: ${stats['std_dev']:,.2f}")
print(f"Min: ${stats['min']:,.2f}")
print(f"Max: ${stats['max']:,.2f}")
print(f"P25: ${stats['p25']:,.2f}")
print(f"P75: ${stats['p75']:,.2f}")
print(f"P95: ${stats['p95']:,.2f}")
```

### Statistics for Multiple Columns

```python
for column in ['revenue', 'customers', 'orders']:
    stats = analyst.calculate_statistics(dataset.dataset_id, column)
    if 'error' not in stats:
        print(f"{column}: mean={stats['mean']:.2f}, std={stats['std_dev']:.2f}")
```

---

## Correlation Analysis

### Detect Correlations

```python
corr = analyst.detect_correlations(
    dataset.dataset_id,
    'ad_spend',
    'revenue',
)

print(f"Correlation: {corr['correlation']:.3f}")
print(f"Strength: {corr['strength']}")  # strong, moderate, weak
print(f"Direction: {corr['direction']}")  # positive, negative
print(f"Data Points: {corr['data_points']}")
```

### Correlation Matrix

```python
columns = ['revenue', 'customers', 'ad_spend', 'conversion_rate']

for i, col1 in enumerate(columns):
    for col2 in columns[i+1:]:
        corr = analyst.detect_correlations(dataset.dataset_id, col1, col2)
        if 'error' not in corr:
            print(f"{col1} ↔ {col2}: {corr['correlation']:.3f} ({corr['strength']})")
```

---

## Trend Analysis

### Detect Trends

```python
trend = analyst.detect_trends(
    dataset.dataset_id,
    'revenue',
    'date',  # Time column
)

print(f"Trend: {trend['trend'].upper()}")  # increasing, decreasing, stable
print(f"Slope: {trend['slope']:.2f}")
print(f"Growth Rate: {trend['growth_rate_percent']:.1f}%")
print(f"Start: ${trend['start_value']:,.0f}")
print(f"End: ${trend['end_value']:,.0f}")
```

---

## Anomaly Detection

### Detect Anomalies

```python
anomalies = analyst.detect_anomalies(
    dataset.dataset_id,
    'transaction_count',
    threshold=2.0,  # Z-score threshold
)

print(f"Found {len(anomalies)} anomalies:")
for anomaly in anomalies:
    direction = "↑" if anomaly['deviation'] == 'above' else "↓"
    print(f"  {direction} Value {anomaly['value']:.0f} (z-score: {anomaly['z_score']:.2f})")
```

### Adjust Sensitivity

```python
# More sensitive (find more anomalies)
anomalies_sensitive = analyst.detect_anomalies(dataset.dataset_id, 'value', threshold=1.5)

# Less sensitive (find only extreme anomalies)
anomalies_strict = analyst.detect_anomalies(dataset.dataset_id, 'value', threshold=3.0)
```

---

## Automated Insights

### Generate Insights

```python
analysis = analyst.generate_insights(dataset.dataset_id)

print(f"Analysis: {analysis.name}")
print(f"\nInsights ({len(analysis.insights)}):")
for insight in analysis.insights:
    print(f"  • {insight}")

print(f"\nRecommendations ({len(analysis.recommendations)}):")
for rec in analysis.recommendations:
    print(f"  • {rec}")
```

### Example Insights

```
Insights:
  • High variability in revenue (std_dev > 50% of mean)
  • Outliers detected in customers (P95 > 2x mean)
  • Strong positive correlation between ad_spend and revenue
  • Moderate positive correlation between customers and orders

Recommendations:
  • Consider normalizing high-variance features
  • Investigate correlated features for potential multicollinearity
  • Review outliers for data quality issues
```

---

## Report Generation

### Generate Report

```python
report = analyst.generate_report(
    name="Q1 2026 Sales Report",
    title="First Quarter 2026 Sales Analysis",
    dataset_ids=[q1_dataset_id, q2_dataset_id],
    period_start=datetime(2026, 1, 1),
    period_end=datetime(2026, 3, 31),
)
```

### Get Report

```python
report = analyst.get_report(report_id)

for section in report.sections:
    print(f"Dataset: {section['dataset_name']}")
    print(f"  Source: {section['source']}")
    print(f"  Rows: {section['row_count']}")
    if 'statistics' in section:
        print(f"  Columns analyzed: {len(section['statistics'])}")
```

---

## Analysis Types

| Type | Description | Method |
|------|-------------|--------|
| **Descriptive Statistics** | Mean, median, std dev, percentiles | Standard formulas |
| **Correlation Analysis** | Relationship between variables | Pearson correlation |
| **Trend Analysis** | Time-series trend detection | Linear regression |
| **Anomaly Detection** | Outlier identification | Z-score method |
| **Automated Insights** | Pattern detection & recommendations | Rule-based analysis |

---

## Correlation Strength

| Correlation | Strength |
|-------------|----------|
| 0.7 - 1.0 | Strong |
| 0.4 - 0.7 | Moderate |
| 0.0 - 0.4 | Weak |

---

## Anomaly Thresholds

| Threshold | Sensitivity | Use Case |
|-----------|-------------|----------|
| 1.5 | High | Exploratory analysis |
| 2.0 | Medium (default) | Standard anomaly detection |
| 3.0 | Low | Only extreme outliers |

---

## Examples

See `examples/data_analysis.py` for comprehensive examples:

```bash
cd ~/agentic-ai/agentic_ai
PYTHONPATH=. ./venv/bin/python examples/data_analysis.py
```

**Examples Include:**
1. Statistical analysis
2. Correlation analysis
3. Trend detection
4. Anomaly detection
5. Automated insights
6. Report generation

---

## Testing

```bash
# Run unit tests
pytest tests/test_data_analyst.py -v
```

**Test Coverage:**
- Initialization (2 tests)
- Dataset management (2 tests)
- Statistical analysis (2 tests)
- Correlation analysis (1 test)
- Trend analysis (1 test)
- Anomaly detection (1 test)
- Insights generation (1 test)
- Report generation (2 tests)
- Capabilities export (1 test)

---

## Lead Agent Integration

```python
from agentic_ai.agents.data_analyst import get_capabilities

caps = get_capabilities()

# Returns:
# {
#   'agent_type': 'data_analyst',
#   'version': '1.0.0',
#   'capabilities': ['register_dataset', 'calculate_statistics', ...],
#   'analysis_types': ['descriptive_statistics', 'correlation_analysis', ...],
# }
```

---

## Best Practices

### 1. Validate Data Before Analysis

```python
# Check data is loaded
if dataset.dataset_id not in analyst.data_cache:
    raise ValueError("Dataset not loaded")

# Check minimum data points
if len(analyst.data_cache[dataset.dataset_id]) < 10:
    print("Warning: Insufficient data for reliable statistics")
```

### 2. Handle Non-Numeric Columns

```python
stats = analyst.calculate_statistics(dataset.dataset_id, column)

if 'error' in stats:
    print(f"Column {column} has no numeric values")
else:
    print(f"Mean: {stats['mean']}")
```

### 3. Use Appropriate Thresholds

```python
# For exploratory analysis
anomalies = analyst.detect_anomalies(dataset_id, column, threshold=1.5)

# For production monitoring
anomalies = analyst.detect_anomalies(dataset_id, column, threshold=2.5)
```

### 4. Generate Regular Reports

```python
# Schedule weekly reports
report = analyst.generate_report(
    name="Weekly Metrics",
    title=f"Week {week_number} Analysis",
    dataset_ids=[key_metrics_dataset],
)
```

---

## Support

- **Documentation:** `docs/DATA.md`
- **Examples:** `examples/data_analysis.py`
- **Tests:** `tests/test_data_analyst.py`
- **Issues:** https://github.com/openclaw/openclaw/issues

---

**DataAnalystAgent v1.0.0 - Production Ready** 📊
