# Yohns\AntiSpam\ContentAnalyzer

ContentAnalyzer class for advanced content analysis and pattern detection

Provides detailed content analysis including language detection,
sentiment analysis, and advanced spam pattern recognition.

Usage example:
```php
$analyzer = new ContentAnalyzer();
$result = $analyzer->analyzeContent($text);
if ($result['suspicious_score'] > 0.7) {
    echo "Warning: Content is likely spam.";
}
$analyzer->storeAnalysis($text, $result);
```





## Methods

| Name | Description |
|------|-------------|
|[__construct](#contentanalyzer__construct)||
|[analyzeContent](#contentanalyzeranalyzecontent)|Perform comprehensive content analysis.|
|[analyzeFormatting](#contentanalyzeranalyzeformatting)|Analyze formatting patterns.|
|[analyzeLinks](#contentanalyzeranalyzelinks)|Analyze links in content.|
|[analyzeSentiment](#contentanalyzeranalyzesentiment)|Analyze sentiment of the content.|
|[calculateReadability](#contentanalyzercalculatereadability)|Calculate readability score (simplified Flesch Reading Ease).|
|[detectLanguage](#contentanalyzerdetectlanguage)|Detect the primary language of the content.|
|[detectPatterns](#contentanalyzerdetectpatterns)|Detect suspicious patterns in content.|
|[getAnalysisStats](#contentanalyzergetanalysisstats)|Get content analysis statistics|
|[storeAnalysis](#contentanalyzerstoreanalysis)|Store analysis results.|




### ContentAnalyzer::__construct

**Description**

```php
 __construct (void)
```





**Parameters**

`This function has no parameters.`

**Return Values**

`void`


<hr />


### ContentAnalyzer::analyzeContent

**Description**

```php
public analyzeContent (string $content)
```

Perform comprehensive content analysis.



**Parameters**

* `(string) $content`
: The content to analyze.

**Return Values**

`array`

> Analysis results including language, sentiment, patterns, etc.

Example:
```php
$result = $analyzer->analyzeContent($text);
```


<hr />


### ContentAnalyzer::analyzeFormatting

**Description**

```php
public analyzeFormatting (string $content)
```

Analyze formatting patterns.



**Parameters**

* `(string) $content`
: The content to analyze.

**Return Values**

`array`

> Formatting analysis.

Example:
```php
$formatting = $analyzer->analyzeFormatting($text);
```


<hr />


### ContentAnalyzer::analyzeLinks

**Description**

```php
public analyzeLinks (string $content)
```

Analyze links in content.



**Parameters**

* `(string) $content`
: The content to analyze.

**Return Values**

`array`

> Link analysis result.

Example:
```php
$links = $analyzer->analyzeLinks($text);
```


<hr />


### ContentAnalyzer::analyzeSentiment

**Description**

```php
public analyzeSentiment (string $content)
```

Analyze sentiment of the content.



**Parameters**

* `(string) $content`
: The content to analyze.

**Return Values**

`array`

> Sentiment analysis result.

Example:
```php
$sentiment = $analyzer->analyzeSentiment($text);
```


<hr />


### ContentAnalyzer::calculateReadability

**Description**

```php
public calculateReadability (string $content)
```

Calculate readability score (simplified Flesch Reading Ease).



**Parameters**

* `(string) $content`
: The content to analyze.

**Return Values**

`array`

> Readability score and level.

Example:
```php
$readability = $analyzer->calculateReadability($text);
```


<hr />


### ContentAnalyzer::detectLanguage

**Description**

```php
public detectLanguage (string $content)
```

Detect the primary language of the content.



**Parameters**

* `(string) $content`
: The content to analyze.

**Return Values**

`array`

> Array with 'primary', 'confidence', and 'all_scores'.

Example:
```php
$lang = $analyzer->detectLanguage($text);
```


<hr />


### ContentAnalyzer::detectPatterns

**Description**

```php
public detectPatterns (string $content)
```

Detect suspicious patterns in content.



**Parameters**

* `(string) $content`
: The content to analyze.

**Return Values**

`array`

> Detected patterns with details.

Example:
```php
$patterns = $analyzer->detectPatterns($text);
```


<hr />


### ContentAnalyzer::getAnalysisStats

**Description**

```php
public getAnalysisStats (void)
```

Get content analysis statistics



**Parameters**

`This function has no parameters.`

**Return Values**

`void`


<hr />


### ContentAnalyzer::storeAnalysis

**Description**

```php
public storeAnalysis (string $content, array $analysis)
```

Store analysis results.



**Parameters**

* `(string) $content`
: The original content.
* `(array) $analysis`
: The analysis result array.

**Return Values**

`string`

> Inserted record ID or hash.

Example:
```php
$analyzer->storeAnalysis($text, $result);
```


<hr />
